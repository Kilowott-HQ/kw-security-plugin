<?php
/**
 * KW Security — Dashboard-triggered visibility toggle
 *
 * Registers POST /wp-json/kw-security/v1/dashboard-visibility
 *
 * Backs the Security Dashboard's "Remove" action: lets the dashboard tell
 * this site to stop reporting (and reappear once told to resume), the same
 * signed-request model as toggle-feature.php. Distinct from that endpoint
 * because this isn't one of KW_Security_Settings' feature toggles — it's
 * telemetry opt-in/out, checked by KW_Security_Telemetry::send_ping()
 * before every heartbeat.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Dashboard_Visibility')) {

    class KW_Security_Dashboard_Visibility {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/dashboard-visibility';
        const TS_WINDOW     = 300; // seconds — reject stale/replayed requests

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
            register_rest_route(self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array(__CLASS__, 'handle'),
                'permission_callback' => array(__CLASS__, 'authenticate'),
            ));
        }

        private static function to_bool($value) {
            return in_array($value, array(true, 1, '1', 'true'), true);
        }

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact visibility state, within a short freshness window.
         */
        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $visible_param    = $request->get_param('visible');
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || null === $visible_param || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $visible   = self::to_bool($visible_param);
            $message   = $installation_id . '|dashboard-visibility|' . ($visible ? '1' : '0') . '|' . $timestamp;
            $sig_bytes = base64_decode($signature, true);
            if (false === $sig_bytes) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $pub = openssl_get_publickey(self::DASHBOARD_UPDATE_PUBLIC_KEY);
            if (false === $pub || 1 !== openssl_verify($message, $sig_bytes, $pub, OPENSSL_ALGO_SHA256)) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            return true;
        }

        public static function handle(WP_REST_Request $request) {
            $visible = self::to_bool($request->get_param('visible'));

            $option = class_exists('KW_Security_Settings')
                ? KW_Security_Settings::DASHBOARD_VISIBILITY_OPTION
                : 'kw_security_show_in_dashboard';
            update_option($option, $visible);

            return new WP_REST_Response(array('ok' => true, 'visible' => $visible), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Dashboard_Visibility', 'init'));
}
