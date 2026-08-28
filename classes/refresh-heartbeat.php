<?php
/**
 * KW Security — Dashboard-triggered heartbeat refresh
 *
 * Registers POST /wp-json/kw-security/v1/refresh-heartbeat
 *
 * Lets the Security Dashboard ask this site to send a heartbeat right now
 * instead of waiting for the next hourly WP-Cron tick. Triggered by a REST
 * request rather than cron, so it works even when a site's own WP-Cron has
 * stalled (no traffic, a broken cron setup) — exactly the situation that
 * leaves a site looking stale/Inactive on the dashboard despite the plugin
 * being fine. Same signed-request model as the plugin's other
 * dashboard-triggered endpoints.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Refresh_Heartbeat')) {

    class KW_Security_Refresh_Heartbeat {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/refresh-heartbeat';
        const TS_WINDOW     = 300; // seconds — reject stale/replayed requests

        // Same keypair as the plugin's other dashboard-triggered endpoints —
        // same trust boundary, but a different signed message shape, so a
        // signature for one action never verifies for another.
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

        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $message   = $installation_id . '|refresh-heartbeat|' . $timestamp;
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

        /**
         * Kicks off an immediate heartbeat. send_ping() posts to the
         * dashboard non-blocking, so this returns before that heartbeat has
         * necessarily landed — the dashboard's own listing updates a moment
         * later through the normal /v1/heartbeat route, same as any other
         * heartbeat.
         */
        public static function handle(WP_REST_Request $request) {
            if (!class_exists('KW_Security_Telemetry')) {
                return new WP_REST_Response(array('ok' => false, 'message' => 'Not available on this plugin version.'), 500);
            }

            KW_Security_Telemetry::send_ping('heartbeat');

            return new WP_REST_Response(array('ok' => true), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Refresh_Heartbeat', 'init'));
}
