<?php
/**
 * KW Security — Remote Activation (must-use plugin)
 *
 * DEPLOYMENT: this file goes in wp-content/mu-plugins/, NOT
 * wp-content/plugins/kw-security/classes/ — WordPress always loads every
 * file directly under mu-plugins/ regardless of whether any regular plugin
 * (including kw-security itself) is active. That's the entire reason this
 * file exists as a separate mu-plugin instead of a class inside the main
 * plugin: once kw-security is deactivated, WordPress stops loading
 * classes/*.php entirely, so its own REST routes (update-trigger.php,
 * toggle-feature.php, activity-log.php's dashboard endpoint) stop existing —
 * there would be nothing left on the site to receive a remote "activate"
 * command. This file is what's still there to receive it.
 *
 * Registers:
 *   POST /wp-json/kw-security/v1/activate-plugin     (activates KW Security itself)
 *   POST /wp-json/kw-security/v1/activate-wordfence  (activates Wordfence, if present)
 *
 * The Wordfence route exists for the same reason as the plugin one: if
 * Wordfence is installed but deactivated, the dashboard still needs a way to
 * turn it back on, and that command has to land somewhere that's loaded
 * regardless of either plugin's state.
 *
 * Self-contained by necessity: does not reference any class from the main
 * plugin (KW_Security_Telemetry, KW_Security_Settings, etc.), since those
 * are not loaded while kw-security is inactive. Reads the installation ID
 * straight from its option (options persist across deactivation) and
 * verifies against the same signing keypair the main plugin's other
 * dashboard-triggered endpoints use.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Remote_Activator')) {

    class KW_Security_Remote_Activator {

        const API_NAMESPACE       = 'kw-security/v1';
        const ROUTE                = '/activate-plugin';
        const WORDFENCE_ROUTE       = '/activate-wordfence';
        const TS_WINDOW            = 300; // seconds — reject stale/replayed requests
        const PLUGIN_FILE          = 'kw-security/kw-security.php';
        const WORDFENCE_PLUGIN_FILE = 'wordfence/wordfence.php';
        const OPTION_SITE_ID       = 'kw_security_site_id';

        // Same keypair as the main plugin's other dashboard-triggered
        // endpoints. Safe to publish — verifies signatures, cannot forge them.
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

            register_rest_route(self::API_NAMESPACE, self::WORDFENCE_ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array(__CLASS__, 'handle_wordfence'),
                'permission_callback' => array(__CLASS__, 'authenticate_wordfence'),
            ));
        }

        public static function authenticate(WP_REST_Request $request) {
            return self::authenticate_action($request, 'activate-plugin');
        }

        public static function authenticate_wordfence(WP_REST_Request $request) {
            return self::authenticate_action($request, 'activate-wordfence');
        }

        /**
         * Verifies the request came from the dashboard for THIS site, within
         * a short freshness window, for the given signed action. Reads the
         * site's own installation ID directly from its option rather than
         * via KW_Security_Telemetry, since that class isn't loaded while the
         * plugin is inactive. $action is baked into the signed message so a
         * captured signature for one activation route can't be replayed
         * against the other.
         */
        private static function authenticate_action(WP_REST_Request $request, $action) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            $site_id = get_option(self::OPTION_SITE_ID);
            if (!$site_id || $installation_id !== $site_id) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $message   = $installation_id . '|' . $action . '|' . $timestamp;
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
            return self::activate_plugin_file(self::PLUGIN_FILE, 'KW Security plugin files were not found on this site.');
        }

        public static function handle_wordfence(WP_REST_Request $request) {
            return self::activate_plugin_file(self::WORDFENCE_PLUGIN_FILE, 'Wordfence plugin files were not found on this site.');
        }

        /**
         * Activates a plugin via WordPress's own activate_plugin() — the
         * same core function a manual "Activate" click in wp-admin uses,
         * which runs the plugin's normal register_activation_hook callback.
         */
        private static function activate_plugin_file($plugin_file, $not_found_message) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';

            if (!file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
                return new WP_REST_Response(array(
                    'ok'      => false,
                    'message' => $not_found_message,
                ), 404);
            }

            if (is_plugin_active($plugin_file)) {
                return new WP_REST_Response(array(
                    'ok'        => true,
                    'activated' => false,
                    'message'   => 'Already active.',
                ), 200);
            }

            $result = activate_plugin($plugin_file);

            if (is_wp_error($result)) {
                return new WP_REST_Response(array('ok' => false, 'message' => $result->get_error_message()), 500);
            }

            return new WP_REST_Response(array(
                'ok'        => true,
                'activated' => true,
                'message'   => 'Activated.',
            ), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Remote_Activator', 'init'));
}
