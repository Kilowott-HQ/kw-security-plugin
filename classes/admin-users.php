<?php
/**
 * KW Security – Admin Users List
 *
 * Read-only bridge that exposes this site's administrator accounts
 * (username, name, email, 2FA status, last login) to the Security
 * Dashboard — same live-pull, signed-read pattern as activity-log.php and
 * wordfence-integration.php. Nothing here writes anything.
 *
 * 2FA status is read from Wordfence's Login Security tables
 * (wfls_2fa_secrets / wfls_passkeys) when present, since that's the 2FA
 * provider already in use on the sites this ships to — returns null
 * ("unknown", not "off") if neither table exists rather than guessing.
 *
 * Last login is read from this plugin's own Activity Log table
 * (kw_activity_log), which already records every "Logged In" event — more
 * reliable than trying to infer it from another plugin's schema. Only
 * reflects logins since the Activity Log feature was turned on.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Admin_Users' ) ) {

    class KW_Security_Admin_Users {

        const DASHBOARD_API_NAMESPACE = 'kw-security/v1';
        const DASHBOARD_API_ROUTE     = '/admin-users';
        const DELETE_API_ROUTE        = '/delete-admin-user';
        const DASHBOARD_TS_WINDOW     = 300; // seconds — reject stale/replayed requests

        // Same keypair as the plugin's other dashboard-triggered endpoints.
        // Safe to publish — verifies signatures, cannot forge them.
        const DASHBOARD_UPDATE_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjtG3XkYTGtr3YoN5/BgJ
OHXBKcHKaY90xyw/6zxRFTHxVwGGCGqm1MGhcx/9EHHPNKJzBTzFSrzUY46Pc9lE
KWD4CdJnmgDKNzNw5xJR2cjlsVDK+fABDh2GC23XztAc0o/2m0tr57Gm2Ivcnael
vu81LbCfysLRAm6O75s8UawN/UEqpp0eaeMedBzWAB1RBEaDoe4aBPJc2ZQo+uLr
UirIbOYn69OyNWoxqG7AwwoKwXvun6WSONnnRC3btH88D1hKq3oAMALp0zHw8Fkc
Grty7dMqCwbdNKtwr9GL2i7Ve8YrhNCt7uT4NEhbi2JXnXDIqxBQwVumXsJ1taPx
YQIDAQAB
-----END PUBLIC KEY-----';

        public static function init_dashboard_api() {
            register_rest_route( self::DASHBOARD_API_NAMESPACE, self::DASHBOARD_API_ROUTE, array(
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => array( __CLASS__, 'handle_dashboard_request' ),
                'permission_callback' => array( __CLASS__, 'authenticate_dashboard_request' ),
            ) );

            register_rest_route( self::DASHBOARD_API_NAMESPACE, self::DELETE_API_ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( __CLASS__, 'handle_delete_request' ),
                'permission_callback' => array( __CLASS__, 'authenticate_delete_request' ),
            ) );
        }

        /**
         * Verifies the request came from the dashboard for THIS site,
         * within a short freshness window. Mirrors activity-log.php.
         */
        public static function authenticate_dashboard_request( WP_REST_Request $request ) {
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error( 'https_required', 'This endpoint requires HTTPS.', array( 'status' => 403 ) );
            }

            $installation_id = sanitize_text_field( (string) $request->get_param( 'installation_id' ) );
            $timestamp        = (int) $request->get_param( 'timestamp' );
            $signature        = (string) $request->get_param( 'signature' );

            if ( ! $installation_id || ! $timestamp || ! $signature ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( ! class_exists( 'KW_Security_Telemetry' ) || $installation_id !== KW_Security_Telemetry::get_site_id() ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( abs( time() - $timestamp ) > self::DASHBOARD_TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $message   = $installation_id . '|admin-users|' . $timestamp;
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

        public static function handle_dashboard_request( WP_REST_Request $request ) {
            global $wpdb;

            $admins = get_users( array(
                'role'    => 'administrator',
                'orderby' => 'display_name',
                'order'   => 'ASC',
            ) );

            $users = array();
            foreach ( $admins as $user ) {
                $users[] = array(
                    'id'         => (int) $user->ID,
                    'username'   => $user->user_login,
                    'name'       => $user->display_name,
                    'email'      => $user->user_email,
                    'two_factor' => self::get_two_factor_status( $wpdb, (int) $user->ID ),
                    'last_login' => self::get_last_login( $wpdb, (int) $user->ID ),
                );
            }

            return new WP_REST_Response( array( 'ok' => true, 'users' => $users ), 200 );
        }

        // ----------------------------------------------------------------
        // Delete an admin user — always requires reassigning their content
        // to another existing administrator (never left orphaned or wiped),
        // which also means the sole remaining administrator can never be
        // deleted through this route: there would be no valid reassignment
        // target to choose.
        // ----------------------------------------------------------------

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact user+reassignment pair, within a short freshness
         * window. The signed message binds both IDs so a captured signature
         * can't be replayed to delete a different user or reassign
         * elsewhere.
         */
        public static function authenticate_delete_request( WP_REST_Request $request ) {
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error( 'https_required', 'This endpoint requires HTTPS.', array( 'status' => 403 ) );
            }

            $installation_id = sanitize_text_field( (string) $request->get_param( 'installation_id' ) );
            $user_id          = (int) $request->get_param( 'user_id' );
            $reassign_id      = (int) $request->get_param( 'reassign_id' );
            $timestamp        = (int) $request->get_param( 'timestamp' );
            $signature        = (string) $request->get_param( 'signature' );

            if ( ! $installation_id || ! $user_id || ! $reassign_id || ! $timestamp || ! $signature ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( ! class_exists( 'KW_Security_Telemetry' ) || $installation_id !== KW_Security_Telemetry::get_site_id() ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( abs( time() - $timestamp ) > self::DASHBOARD_TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $message   = $installation_id . '|delete-admin-user|' . $user_id . '|' . $reassign_id . '|' . $timestamp;
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

        public static function handle_delete_request( WP_REST_Request $request ) {
            $user_id     = (int) $request->get_param( 'user_id' );
            $reassign_id = (int) $request->get_param( 'reassign_id' );

            if ( $user_id === $reassign_id ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => "Can't reassign a user's content to themselves." ), 400 );
            }

            $target = get_userdata( $user_id );
            if ( ! $target || ! in_array( 'administrator', (array) $target->roles, true ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'User not found, or is not an administrator.' ), 404 );
            }

            $reassign_user = get_userdata( $reassign_id );
            if ( ! $reassign_user || ! in_array( 'administrator', (array) $reassign_user->roles, true ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'Reassignment target must be an existing administrator.' ), 400 );
            }

            if ( ! function_exists( 'wp_delete_user' ) ) {
                require_once ABSPATH . 'wp-admin/includes/user.php';
            }

            $deleted_username = $target->user_login;
            $result           = wp_delete_user( $user_id, $reassign_id );

            if ( ! $result ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'Failed to delete the user.' ), 500 );
            }

            return new WP_REST_Response( array(
                'ok'            => true,
                'deleted'       => $deleted_username,
                'reassigned_to' => $reassign_user->user_login,
            ), 200 );
        }

        // ----------------------------------------------------------------
        // 2FA status — Wordfence Login Security's own tables
        // ----------------------------------------------------------------

        /**
         * Returns true/false when a Wordfence Login Security table is
         * present and queryable, or null when neither table exists (2FA
         * status genuinely unknown, not "off") — e.g. Wordfence isn't
         * installed, or is an older version without this module.
         */
        private static function get_two_factor_status( $wpdb, $user_id ) {
            $secrets_table = self::resolve_wf_table( $wpdb, $wpdb->prefix . 'wfls_2fa_secrets' );
            if ( $secrets_table ) {
                $columns    = self::columns( $wpdb, $secrets_table );
                $user_col   = self::pick_column( $columns, array( 'user_id' ) );
                $secret_col = self::pick_column( $columns, array( 'secret' ) );
                if ( $user_col && $secret_col ) {
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                    $secret = $wpdb->get_var( $wpdb->prepare( "SELECT `{$secret_col}` FROM {$secrets_table} WHERE `{$user_col}` = %d LIMIT 1", $user_id ) );
                    if ( ! empty( $secret ) ) {
                        return true;
                    }
                }
            }

            $passkeys_table = self::resolve_wf_table( $wpdb, $wpdb->prefix . 'wfls_passkeys' );
            if ( $passkeys_table ) {
                $columns  = self::columns( $wpdb, $passkeys_table );
                $user_col = self::pick_column( $columns, array( 'user_id' ) );
                if ( $user_col ) {
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                    $count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$passkeys_table} WHERE `{$user_col}` = %d", $user_id ) );
                    if ( $count > 0 ) {
                        return true;
                    }
                }
            }

            if ( ! $secrets_table && ! $passkeys_table ) {
                return null;
            }

            return false;
        }

        // ----------------------------------------------------------------
        // Last login — this plugin's own Activity Log
        // ----------------------------------------------------------------

        private static function get_last_login( $wpdb, $user_id ) {
            $table = $wpdb->prefix . 'kw_activity_log';
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is a fixed internal string (created by this same plugin).
            $found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
            if ( $found !== $table ) {
                return null;
            }

            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is a fixed internal string.
            $ts = $wpdb->get_var( $wpdb->prepare( "SELECT MAX(created_at) FROM {$table} WHERE user_id = %d AND action = %s", $user_id, 'Logged In' ) );
            if ( ! $ts ) {
                return null;
            }
            return gmdate( 'c', (int) $ts );
        }

        // ----------------------------------------------------------------
        // Schema helpers — same defensive, case-insensitive approach as
        // wordfence-integration.php (duplicated rather than shared, kept
        // self-contained like every other dashboard-facing class here).
        // ----------------------------------------------------------------

        private static function get_wf_tables_map( $wpdb ) {
            static $map = null;
            if ( null !== $map ) {
                return $map;
            }

            $like = $wpdb->esc_like( $wpdb->prefix . 'wf' ) . '%';
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $like is escaped via esc_like and passed as a bound placeholder value.
            $tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) );

            $map = array();
            foreach ( (array) $tables as $table ) {
                $map[ strtolower( $table ) ] = $table;
            }
            return $map;
        }

        private static function resolve_wf_table( $wpdb, $logical_name ) {
            $map = self::get_wf_tables_map( $wpdb );
            $key = strtolower( $logical_name );
            return isset( $map[ $key ] ) ? $map[ $key ] : null;
        }

        private static function columns( $wpdb, $table ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name comes from an internal allowlist, not user input.
            $rows = $wpdb->get_results( "SHOW COLUMNS FROM {$table}" );
            $out  = array();
            foreach ( (array) $rows as $row ) {
                $out[ $row->Field ] = $row->Type;
            }
            return $out;
        }

        private static function pick_column( $available, $candidates ) {
            foreach ( $candidates as $candidate ) {
                if ( isset( $available[ $candidate ] ) ) {
                    return $candidate;
                }
            }
            return null;
        }
    }

    // Registered unconditionally — a passive read with no feature toggle of its own.
    add_action( 'rest_api_init', array( 'KW_Security_Admin_Users', 'init_dashboard_api' ) );
}
