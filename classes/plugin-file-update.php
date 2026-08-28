<?php
/**
 * KW Security — Dashboard-triggered update for any installed plugin
 *
 * Registers POST /wp-json/kw-security/v1/update-plugin-file
 *
 * Lets the Security Dashboard update any installed plugin remotely from the
 * Installed Plugins list — not just KW Security itself (see
 * update-trigger.php for that dedicated, PUC-specific route). Forces
 * WordPress's own generic update check (wp_update_plugins()) rather than a
 * specific checker, since an arbitrary plugin's update source could be
 * wp.org, a bundled custom checker, or anything else registered the normal
 * WordPress way — then hands off to Plugin_Upgrader, the same code path a
 * manual "Update Now" click in wp-admin uses.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Plugin_File_Update')) {

    class KW_Security_Plugin_File_Update {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/update-plugin-file';
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

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact plugin, within a short freshness window.
         */
        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $plugin_file      = sanitize_text_field((string) $request->get_param('plugin_file'));
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$plugin_file || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $message   = $installation_id . '|update-plugin-file|' . $plugin_file . '|' . $timestamp;
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
         * Forces a fresh check against WordPress's own update system, then
         * hands off to Plugin_Upgrader — validated against the real
         * installed-plugins list first, since Plugin_Upgrader ultimately
         * include()s the target file: an unvalidated path here would be a
         * local-file-inclusion risk, not just a correctness one.
         */
        public static function handle(WP_REST_Request $request) {
            $plugin_file = sanitize_text_field((string) $request->get_param('plugin_file'));

            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
            require_once ABSPATH . 'wp-admin/includes/update.php';

            $installed = get_plugins();
            if (!array_key_exists($plugin_file, $installed)) {
                return new WP_REST_Response(array('ok' => false, 'message' => 'Unknown plugin.'), 404);
            }

            $from_version = isset($installed[$plugin_file]['Version']) ? $installed[$plugin_file]['Version'] : null;

            // WordPress's own generic update check — refreshes the
            // update_plugins transient for every installed plugin via
            // whatever update source each one is registered with (wp.org,
            // a bundled custom checker, etc.), not just KW Security's own
            // GitHub-backed one (see update-trigger.php for that).
            wp_update_plugins();

            $update_transient = get_site_transient('update_plugins');
            $has_update = is_object($update_transient) && isset($update_transient->response[$plugin_file]);

            if (!$has_update) {
                return new WP_REST_Response(array(
                    'ok'           => true,
                    'updated'      => false,
                    'from_version' => $from_version,
                    'to_version'   => $from_version,
                    'message'      => 'Already on the latest version.',
                ), 200);
            }

            $was_active = is_plugin_active($plugin_file);

            $skin     = new Automatic_Upgrader_Skin();
            $upgrader = new Plugin_Upgrader($skin);
            $result   = $upgrader->upgrade($plugin_file);

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
            if ($was_active && !is_plugin_active($plugin_file)) {
                activate_plugin($plugin_file);
            }

            // If the plugin being updated is KW Security itself, guarantee
            // the heartbeat cron survives — same reasoning as
            // update-trigger.php: activate_plugin() above is a silent
            // no-op if WordPress already believed the plugin was active,
            // which would otherwise leave this site stuck Inactive.
            $is_self = defined('KW_SECURITY_PLUGIN_FILE') && $plugin_file === plugin_basename(KW_SECURITY_PLUGIN_FILE);
            if ($is_self && $was_active && is_plugin_active($plugin_file) && class_exists('KW_Security_Telemetry')) {
                KW_Security_Telemetry::schedule_heartbeat_cron();
                KW_Security_Telemetry::send_ping('activation');
            }

            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file, false, false);
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

    add_action('rest_api_init', array('KW_Security_Plugin_File_Update', 'init'));
}
