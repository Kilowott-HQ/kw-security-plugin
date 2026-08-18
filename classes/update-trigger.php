<?php
/**
 * KW Security — Dashboard-triggered plugin update
 *
 * Registers POST /wp-json/kw-security/v1/update-plugin
 *
 * Lets the Security Dashboard trigger a live update of this plugin. There is
 * no shared secret between the dashboard and this site to use as a bearer
 * credential here — the dashboard stores only a hash of this site's own
 * heartbeat key, never the raw value, so it has nothing it could present.
 * Instead the dashboard signs {installation_id}|{timestamp} with a private
 * key only it holds, and this verifies the signature against the public key
 * below. A leaked WordPress database exposes only the public key, which can
 * verify signatures but cannot forge them.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Update_Trigger')) {

    class KW_Security_Update_Trigger {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/update-plugin';
        const TS_WINDOW     = 300; // seconds — reject stale/replayed requests

        // Public half of the dashboard's update-signing keypair (distinct
        // from KW_DELIVERY_PUBLIC_KEY, which belongs to the unrelated
        // Kilowott maintenance scanner). Safe to publish.
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

        /**
         * Verifies the request came from the dashboard: HTTPS, a fresh
         * timestamp, and a signature that only the dashboard's private key
         * could have produced for this specific installation_id.
         */
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

            // The signed installation_id must match this site's own ID —
            // otherwise a signature issued for a different site would also
            // verify here.
            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $message   = $installation_id . '|' . $timestamp;
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
         * Forces a fresh update check against the plugin's own GitHub-backed
         * update checker (see classes/updater.php), then hands off to
         * WordPress's own Plugin_Upgrader — the same code path a manual
         * "Update Now" click in wp-admin uses — rather than touching plugin
         * files directly.
         */
        public static function handle(WP_REST_Request $request) {
            $plugin_file = defined('KW_SECURITY_PLUGIN_FILE') ? KW_SECURITY_PLUGIN_FILE : null;
            if (!$plugin_file) {
                return new WP_REST_Response(array('ok' => false, 'message' => 'Plugin file constant not defined.'), 500);
            }

            $from_version = defined('KW_SECURITY_VERSION') ? KW_SECURITY_VERSION : null;
            $plugin_file_relative = plugin_basename($plugin_file);

            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

            if (!class_exists('YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
                require_once KW_SECURITY_PLUGIN_DIR . 'vendor/plugin-update-checker/load-v5p6.php';
            }

            // Same repo/slug as classes/updater.php — this just forces an
            // immediate check instead of waiting for PUC's own schedule.
            $checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
                'https://github.com/Kilowott-HQ/kw-security-plugin/',
                $plugin_file,
                'kw-security'
            );
            $checker->checkForUpdates();

            $update_transient = get_site_transient('update_plugins');
            $has_update = is_object($update_transient) && isset($update_transient->response[$plugin_file_relative]);

            if (!$has_update) {
                return new WP_REST_Response(array(
                    'ok'           => true,
                    'updated'      => false,
                    'from_version' => $from_version,
                    'to_version'   => $from_version,
                    'message'      => 'Already on the latest version.',
                ), 200);
            }

            $was_active = is_plugin_active($plugin_file_relative);

            // Automatic_Upgrader_Skin is WP core's own headless skin (used by
            // its background auto-updates) — it suppresses the HTML output a
            // normal wp-admin upgrade would print, which has no home here.
            $skin     = new Automatic_Upgrader_Skin();
            $upgrader = new Plugin_Upgrader($skin);
            $result   = $upgrader->upgrade($plugin_file_relative);

            if (is_wp_error($result)) {
                return new WP_REST_Response(array('ok' => false, 'message' => $result->get_error_message()), 500);
            }
            if (true !== $result) {
                $error   = $skin->get_errors();
                $message = (is_wp_error($error) && $error->get_error_message()) ? $error->get_error_message() : 'Update failed.';
                return new WP_REST_Response(array('ok' => false, 'message' => $message), 500);
            }

            // Plugin_Upgrader deactivates the plugin for the duration of the
            // file swap; restore its prior state.
            if ($was_active && !is_plugin_active($plugin_file_relative)) {
                activate_plugin($plugin_file_relative);
            }

            // Read the version straight from the freshly-written file header
            // rather than the KW_SECURITY_VERSION constant, which still
            // holds the pre-upgrade value for the remainder of this request.
            $plugin_data = get_plugin_data($plugin_file, false, false);
            $to_version  = isset($plugin_data['Version']) ? $plugin_data['Version'] : null;

            return new WP_REST_Response(array(
                'ok'           => true,
                'updated'      => true,
                'from_version' => $from_version,
                'to_version'   => $to_version,
                'message'      => $to_version ? "Updated to {$to_version}." : 'Updated.',
            ), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Update_Trigger', 'init'));
}
