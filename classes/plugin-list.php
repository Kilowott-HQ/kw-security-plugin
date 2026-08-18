<?php
/**
 * KW Security – Installed Plugins List
 *
 * Read-only bridge that exposes this site's installed plugins (name,
 * version, active state, update availability) to the Security Dashboard —
 * same live-pull, signed-read pattern as activity-log.php and
 * wordfence-integration.php. Nothing here writes anything.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Plugin_List' ) ) {

    class KW_Security_Plugin_List {

        const DASHBOARD_API_NAMESPACE = 'kw-security/v1';
        const DASHBOARD_API_ROUTE     = '/plugins';
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

            $message   = $installation_id . '|plugins|' . $timestamp;
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
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            $all_plugins = get_plugins();
            $active      = (array) get_option( 'active_plugins', array() );

            if ( is_multisite() ) {
                $network_active = array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) );
                $active         = array_unique( array_merge( $active, $network_active ) );
            }

            // Reads whatever WP's own update transient already knows —
            // doesn't force a fresh check against wordpress.org.
            $update_transient = get_site_transient( 'update_plugins' );
            $updates          = ( $update_transient && ! empty( $update_transient->response ) )
                ? $update_transient->response
                : array();

            $plugins = array();
            foreach ( $all_plugins as $file => $data ) {
                $update_info = isset( $updates[ $file ] ) ? $updates[ $file ] : null;
                $plugins[]   = array(
                    'file'             => $file,
                    'name'             => isset( $data['Name'] ) ? $data['Name'] : $file,
                    'version'          => isset( $data['Version'] ) ? $data['Version'] : null,
                    'active'           => in_array( $file, $active, true ),
                    'update_available' => (bool) $update_info,
                    'new_version'      => ( $update_info && isset( $update_info->new_version ) ) ? $update_info->new_version : null,
                );
            }

            usort( $plugins, function ( $a, $b ) {
                return strcasecmp( $a['name'], $b['name'] );
            } );

            return new WP_REST_Response( array( 'ok' => true, 'plugins' => $plugins ), 200 );
        }
    }

    // Registered unconditionally — a passive read with no feature toggle of its own.
    add_action( 'rest_api_init', array( 'KW_Security_Plugin_List', 'init_dashboard_api' ) );
}
