<?php
/**
 * KW Security – Dashboard-triggered plugin install
 *
 * Registers POST /wp-json/kw-security/v1/install-plugin
 *
 * Lets the Security Dashboard install a real plugin from wordpress.org
 * onto this site remotely, then activates it — the sanctioned path once
 * Plugin Lockout (classes/plugin-lockout.php) has disabled every other way
 * to add one. Same signed-request model as the plugin's other
 * dashboard-triggered endpoints.
 *
 * The signed message carries only a slug, never a download URL — this
 * endpoint resolves the actual download link itself via wordpress.org's
 * own plugins_api(), the same call wp-admin's own install flow makes
 * (see wp_ajax_install_plugin() in wp-admin/includes/ajax-actions.php),
 * so a compromised or malicious dashboard could name any slug but could
 * never force an arbitrary payload URL onto this site.
 *
 * Calls Plugin_Upgrader::install() and activate_plugin() directly rather
 * than going through wp-admin's Add Plugins screen, so it is never
 * affected by Plugin Lockout's map_meta_cap() filter — that filter only
 * strips capabilities, and neither of those functions checks one.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Plugin_Install' ) ) {

    class KW_Security_Plugin_Install {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE          = '/install-plugin';
        const TS_WINDOW      = 300; // seconds — reject stale/replayed requests

        // Same keypair as the plugin's other dashboard-triggered endpoints.
        const DASHBOARD_UPDATE_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjtG3XkYTGtr3YoN5/BgJ
OHXBKcHKaY90xyw/6zxRFTHxVwGGCGqm1MGhcx/9EHHPNKJzBTzFSrzUY46Pc9lE
KWD4CdJnmgDKNzNw5xJR2cjlsVDK+fABDh2GC23XztAc0o/2m0tr57Gm2Ivcnael
vu81LbCfysLRAm6O75s8UawN/UEqpp0eaeMedBzWAB1RBEaDoe4aBPJc2ZQo+uLr
UirIbOYn69OyNWoxqG7AwwoKwXvun6WSONnnRC3btH88D1hKq3oAMALp0zHw8Fkc
Grty7dMqCwbdNKtwr9GL2i7Ve8YrhNCt7uT4NEhbi2JXnXDIqxBQwVumXsJ1taPx
YQIDAQAB
-----END PUBLIC KEY-----';

        public static function init() {
            register_rest_route( self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( __CLASS__, 'handle' ),
                'permission_callback' => array( __CLASS__, 'authenticate' ),
            ) );
        }

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact slug, within a short freshness window.
         */
        public static function authenticate( WP_REST_Request $request ) {
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error( 'https_required', 'This endpoint requires HTTPS.', array( 'status' => 403 ) );
            }

            $installation_id = sanitize_text_field( (string) $request->get_param( 'installation_id' ) );
            $slug             = sanitize_key( (string) $request->get_param( 'slug' ) );
            $timestamp        = (int) $request->get_param( 'timestamp' );
            $signature        = (string) $request->get_param( 'signature' );

            if ( ! $installation_id || '' === $slug || ! $timestamp || ! $signature ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( ! class_exists( 'KW_Security_Telemetry' ) || $installation_id !== KW_Security_Telemetry::get_site_id() ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( abs( time() - $timestamp ) > self::TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $message   = $installation_id . '|install-plugin|' . $slug . '|' . $timestamp;
            $sig_bytes = base64_decode( $signature, true );
            if ( false === $sig_bytes ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $pub = openssl_get_publickey( self::DASHBOARD_UPDATE_PUBLIC_KEY );
            if ( false === $pub || 1 !== openssl_verify( $message, $sig_bytes, $pub, OPENSSL_ALGO_SHA256 ) ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            return true;
        }

        public static function handle( WP_REST_Request $request ) {
            $slug = sanitize_key( (string) $request->get_param( 'slug' ) );

            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
            require_once ABSPATH . 'wp-admin/includes/plugin-install.php';

            $api = plugins_api( 'plugin_information', array(
                'slug'   => $slug,
                'fields' => array( 'sections' => false ),
            ) );

            if ( is_wp_error( $api ) || empty( $api->download_link ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'Plugin not found.' ), 404 );
            }

            // Attribute the resulting Activity Log "Installed"/"Activated"
            // entries to the dashboard role behind this request instead of
            // "Guest" — see KW_Security_Dashboard_Actor in
            // mu-plugins/kw-security-activator.php (always loaded, so it's
            // guaranteed to already exist here).
            if ( class_exists( 'KW_Security_Dashboard_Actor' ) ) {
                KW_Security_Dashboard_Actor::set( $request->get_param( 'actor_role' ) );
            }

            // Same sequence and error handling as core's own
            // wp_ajax_install_plugin() (wp-admin/includes/ajax-actions.php)
            // — WP_Ajax_Upgrader_Skin is the headless skin built for
            // exactly this kind of structured, non-HTML install context.
            $skin     = new WP_Ajax_Upgrader_Skin();
            $upgrader = new Plugin_Upgrader( $skin );
            $result   = $upgrader->install( $api->download_link );

            if ( is_wp_error( $result ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => $result->get_error_message() ), 500 );
            }
            if ( is_wp_error( $skin->result ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => $skin->result->get_error_message() ), 500 );
            }
            if ( $skin->get_errors()->has_errors() ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => $skin->get_error_messages() ), 500 );
            }
            if ( is_null( $result ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'Unable to connect to the filesystem to install the plugin.' ), 500 );
            }

            // Resolve the file WordPress actually installed — same
            // approach install_plugin_install_status() uses: scan just the
            // slug's own directory rather than assuming "{slug}/{slug}.php",
            // since a plugin's main file doesn't always match its slug.
            $installed = get_plugins( '/' . $slug );
            if ( empty( $installed ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'Installed, but the plugin file could not be located.' ), 500 );
            }
            $file = $slug . '/' . array_key_first( $installed );

            $activate_result = activate_plugin( $file );
            if ( is_wp_error( $activate_result ) ) {
                return new WP_REST_Response( array(
                    'ok'      => true,
                    'file'    => $file,
                    'name'    => $api->name,
                    'active'  => false,
                    'message' => 'Installed, but could not be activated: ' . $activate_result->get_error_message(),
                ), 200 );
            }

            return new WP_REST_Response( array(
                'ok'     => true,
                'file'   => $file,
                'name'   => $api->name,
                'active' => is_plugin_active( $file ),
            ), 200 );
        }
    }

    // Registered unconditionally — installing itself has no feature toggle;
    // Plugin Lockout only gates the OTHER ways to manage plugins, by design.
    add_action( 'rest_api_init', array( 'KW_Security_Plugin_Install', 'init' ) );
}
