<?php
/**
 * KW Security — Dashboard-triggered plugin activate/deactivate
 *
 * Registers POST /wp-json/kw-security/v1/toggle-plugin
 *
 * Lets the Security Dashboard activate or deactivate any plugin listed by
 * plugin-list.php, remotely — including this plugin itself. Same
 * signed-request model as toggle-feature.php: the dashboard signs the
 * request with a private key only it holds, and this verifies it against a
 * bundled public key. The signed message includes the target plugin file
 * and desired state, so a captured signature can't be replayed to toggle a
 * different plugin or the opposite way.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Plugin_Toggle')) {

    class KW_Security_Plugin_Toggle {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/toggle-plugin';
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

        private static function to_bool($value) {
            return in_array($value, array(true, 1, '1', 'true'), true);
        }

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact plugin+state, within a short freshness window.
         */
        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $plugin_file      = sanitize_text_field((string) $request->get_param('plugin_file'));
            $enabled_param    = $request->get_param('enabled');
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$plugin_file || null === $enabled_param || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $enabled   = self::to_bool($enabled_param);
            $message   = $installation_id . '|toggle-plugin|' . $plugin_file . '|' . ($enabled ? '1' : '0') . '|' . $timestamp;
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
         * Activates or deactivates the requested plugin — validated against
         * the real installed-plugins list first, since activate_plugin() /
         * deactivate_plugins() both include() the target file: an
         * unvalidated path here would be a local-file-inclusion risk, not
         * just a correctness one.
         */
        public static function handle(WP_REST_Request $request) {
            $plugin_file = sanitize_text_field((string) $request->get_param('plugin_file'));
            $enabled     = self::to_bool($request->get_param('enabled'));

            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            if (!array_key_exists($plugin_file, get_plugins())) {
                return new WP_REST_Response(array('ok' => false, 'message' => 'Unknown plugin.'), 404);
            }

            if ($enabled) {
                $result = activate_plugin($plugin_file);
                if (is_wp_error($result)) {
                    return new WP_REST_Response(array('ok' => false, 'message' => $result->get_error_message()), 500);
                }
            } else {
                deactivate_plugins($plugin_file);
            }

            return new WP_REST_Response(array(
                'ok'     => true,
                'file'   => $plugin_file,
                'active' => is_plugin_active($plugin_file),
            ), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Plugin_Toggle', 'init'));
}
