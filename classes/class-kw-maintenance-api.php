<?php
/**
 * KW Security – Maintenance API
 *
 * Registers GET /wp-json/kw-security/v1/site-status
 *
 * Used by the Kilowott maintenance-agent to fetch WordPress version,
 * PHP version, and plugin update status without requiring a per-user
 * Application Password.
 *
 * Auth: Authorization: Bearer <key>  (key stored in kw_maintenance_key option)
 * Security layers:
 *   1. Key compared via hash_equals() — timing-safe, no enumeration.
 *   2. HTTPS enforced on sites whose home URL is https://.
 *   3. Rate limited to 20 requests/hour per IP using WP transients.
 *   4. Read-only — GET only, no writes.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Maintenance_API' ) ) {

    class KW_Maintenance_API {

        const OPTION_KEY    = 'kw_maintenance_key';
        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/site-status';
        const RATE_LIMIT    = 20;
        const RATE_WINDOW   = 3600;

        // PHP EOL/support status — update annually.
        private static $php_supported = array( '8.4', '8.3', '8.2' );
        private static $php_outdated  = array( '8.1' );
        // anything else is eol

        // ----------------------------------------------------------------
        // Bootstrap
        // ----------------------------------------------------------------

        public static function init() {
            register_rest_route( self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => array( __CLASS__, 'handle' ),
                'permission_callback' => array( __CLASS__, 'authenticate' ),
            ) );
        }

        // ----------------------------------------------------------------
        // Auth + security checks (permission_callback)
        // ----------------------------------------------------------------

        public static function authenticate( WP_REST_Request $request ) {
            // 1. HTTPS — only enforce if the site itself is on https.
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error(
                    'https_required',
                    'This endpoint requires HTTPS.',
                    array( 'status' => 403 )
                );
            }

            // 2. Rate limiting — 20 requests per hour per hashed IP.
            $ip      = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
            $ip_hash = sha1( $ip . wp_salt() );
            $rl_key  = 'kw_maint_rl_' . substr( $ip_hash, 0, 16 );
            $count   = (int) get_transient( $rl_key );

            if ( $count >= self::RATE_LIMIT ) {
                return new WP_Error(
                    'rate_limited',
                    'Too many requests.',
                    array( 'status' => 429 )
                );
            }
            set_transient( $rl_key, $count + 1, self::RATE_WINDOW );

            // 3. Key check — intentionally vague errors to prevent enumeration.
            $stored_key = get_option( self::OPTION_KEY, '' );
            if ( ! $stored_key ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            $auth_header = $request->get_header( 'authorization' );
            if ( ! $auth_header || strpos( $auth_header, 'Bearer ' ) !== 0 ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            $provided_key = substr( $auth_header, 7 );
            if ( ! hash_equals( $stored_key, $provided_key ) ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            return true;
        }

        // ----------------------------------------------------------------
        // Response handler
        // ----------------------------------------------------------------

        public static function handle( WP_REST_Request $request ) {
            return new WP_REST_Response( self::build_response(), 200 );
        }

        private static function build_response() {
            // Load admin includes not available outside wp-admin context.
            if ( ! function_exists( 'get_core_updates' ) ) {
                require_once ABSPATH . 'wp-admin/includes/update.php';
            }
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            // ── WordPress core ───────────────────────────────────────────
            $wp_version       = get_bloginfo( 'version' );
            $wp_latest        = $wp_version;
            $wp_update_needed = false;

            $core_updates = get_core_updates();
            if ( is_array( $core_updates ) ) {
                foreach ( $core_updates as $update ) {
                    if (
                        isset( $update->response, $update->version ) &&
                        $update->response === 'upgrade'
                    ) {
                        $wp_latest        = $update->version;
                        $wp_update_needed = true;
                        break;
                    }
                }
            }

            // ── PHP ──────────────────────────────────────────────────────
            $php_version = PHP_VERSION;
            $php_status  = self::classify_php( $php_version );

            // ── Plugins ──────────────────────────────────────────────────
            $all_plugins      = get_plugins();
            $update_transient = get_site_transient( 'update_plugins' );
            $plugins          = array();

            foreach ( $all_plugins as $plugin_file => $plugin_data ) {
                $slug = dirname( $plugin_file );
                if ( '.' === $slug ) {
                    $slug = basename( $plugin_file, '.php' );
                }
                $installed_ver    = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '';
                $latest_ver       = $installed_ver;
                $update_available = false;
                $is_security      = false;

                if ( isset( $update_transient->response[ $plugin_file ]->new_version ) ) {
                    $update_obj       = $update_transient->response[ $plugin_file ];
                    $latest_ver       = $update_obj->new_version;
                    $update_available = ( $latest_ver !== $installed_ver );

                    if ( $update_available && ! empty( $update_obj->upgrade_notice ) ) {
                        $is_security = (bool) preg_match(
                            '/security|vulnerability|critical/i',
                            wp_strip_all_tags( $update_obj->upgrade_notice )
                        );
                    }
                }

                $plugins[] = array(
                    'name'               => isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug,
                    'slug'               => $slug,
                    'version'            => $installed_ver,
                    'latest'             => $latest_ver,
                    'update_available'   => $update_available,
                    'is_security_update' => $is_security,
                );
            }

            // ── KW Security module status ────────────────────────────────
            $fi_last_scan = (int) get_option( 'kw_security_file_last_scan', 0 );
            $features     = wp_parse_args(
                get_option( KW_Security_Settings::OPTION_NAME, array() ),
                KW_Security_Settings::get_defaults()
            );

            $kw_security = array(
                'file_integrity_last_scan' => $fi_last_scan ? gmdate( 'c', $fi_last_scan ) : null,
                'features_enabled'         => array_keys( array_filter( $features ) ),
            );

            return array(
                'wp_version'       => $wp_version,
                'wp_latest'        => $wp_latest,
                'wp_update_needed' => $wp_update_needed,
                'php_version'      => $php_version,
                'php_status'       => $php_status,
                'plugins'          => $plugins,
                'kw_security'      => $kw_security,
            );
        }

        // ----------------------------------------------------------------
        // Helpers
        // ----------------------------------------------------------------

        private static function classify_php( $version ) {
            $minor = implode( '.', array_slice( explode( '.', $version ), 0, 2 ) );
            if ( in_array( $minor, self::$php_supported, true ) ) return 'supported';
            if ( in_array( $minor, self::$php_outdated, true ) )  return 'outdated';
            return 'eol';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'maintenance_api' ) ) {
        add_action( 'rest_api_init', array( 'KW_Maintenance_API', 'init' ) );
    }
}
