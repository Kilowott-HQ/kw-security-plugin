<?php
/**
 * KW Security — Dashboard-triggered feature toggle
 *
 * Registers POST /wp-json/kw-security/v1/toggle-feature
 *
 * Lets the Security Dashboard flip a single KW_Security_Settings toggle
 * (Hide Login URL, Login Rate Limiting, etc.) remotely. Same signed-request
 * model as update-trigger.php — there is no shared secret between the
 * dashboard and this site, so the dashboard signs the request with a
 * private key and this verifies it against a bundled public key. The
 * signed message includes the feature key and desired state, so a captured
 * signature can't be replayed to flip a different toggle or the opposite way.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Feature_Toggle')) {

    class KW_Security_Feature_Toggle {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/toggle-feature';
        const TS_WINDOW     = 300; // seconds — reject stale/replayed requests

        // Same keypair as KW_Security_Update_Trigger — same trust boundary
        // (the dashboard's private key), but a different signed message
        // shape, so a signature for one action never verifies for the other.
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
         * THIS exact feature+state, within a short freshness window.
         */
        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $feature          = sanitize_key((string) $request->get_param('feature'));
            $enabled_param    = $request->get_param('enabled');
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$feature || null === $enabled_param || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            // Whitelist against the plugin's own known toggle keys — never
            // trust the feature name beyond what KW_Security_Settings defines.
            if (!class_exists('KW_Security_Settings') || !array_key_exists($feature, KW_Security_Settings::get_defaults())) {
                return new WP_Error('unknown_feature', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $enabled   = self::to_bool($enabled_param);
            $message   = $installation_id . '|' . $feature . '|' . ($enabled ? '1' : '0') . '|' . $timestamp;
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
         * Applies the toggle through the plugin's own admin-side sanitizer,
         * so a remote change is held to exactly the same rules as the
         * settings page — including the Activity Log / aryo-activity-log
         * conflict guard.
         */
        public static function handle(WP_REST_Request $request) {
            $feature = sanitize_key((string) $request->get_param('feature'));
            $enabled = self::to_bool($request->get_param('enabled'));

            $stored = get_option(KW_Security_Settings::OPTION_NAME, array());
            if (!is_array($stored)) {
                $stored = array();
            }
            $resolved            = wp_parse_args($stored, KW_Security_Settings::get_defaults());
            $resolved[$feature]  = $enabled;

            $settings_instance = new KW_Security_Settings();
            $clean = $settings_instance->sanitize_features($resolved);

            update_option(KW_Security_Settings::OPTION_NAME, $clean);

            $response = array(
                'ok'      => true,
                'feature' => $feature,
                'enabled' => !empty($clean[$feature]),
            );

            // Enabling was silently blocked by the Activity Log conflict guard.
            if ($enabled && empty($clean[$feature]) && 'activity_log' === $feature) {
                $response['message'] = 'Not enabled: the "Activity Log" plugin (aryo-activity-log) is active on this site.';
            }

            // The one toggle with a real navigation consequence — tell the
            // dashboard exactly where the login page now lives instead of a
            // bare on/off confirmation.
            if ('hide_login_url' === $feature && !empty($clean[$feature])) {
                $response['login_url'] = KW_Security_Settings::get_login_url();
            }

            return new WP_REST_Response($response, 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Feature_Toggle', 'init'));
}
