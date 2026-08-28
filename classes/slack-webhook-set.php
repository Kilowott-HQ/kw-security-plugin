<?php
/**
 * KW Security — Dashboard-set Slack webhook
 *
 * Registers POST /wp-json/kw-security/v1/set-slack-webhook
 *
 * Lets the Security Dashboard set this site's own Slack Incoming Webhook
 * URL and channel-ID bookmark remotely, instead of requiring a login to
 * this site's own Settings → KW Security page. Same signed-request model
 * as toggle-feature.php — the signed message includes both values, so a
 * captured signature can't be replayed with a different webhook or channel.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Slack_Webhook_Set')) {

    class KW_Security_Slack_Webhook_Set {

        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/set-slack-webhook';
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
         * THESE exact values, within a short freshness window.
         */
        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $webhook_url      = (string) $request->get_param('webhook_url');
            $channel_id       = (string) $request->get_param('channel_id');
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

            $message   = $installation_id . '|set-slack-webhook|' . $webhook_url . '|' . $channel_id . '|' . $timestamp;
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
         * Stores the webhook and channel ID through the same validation the
         * settings page's own sanitizer uses, so a remote change can't end
         * up in a state the settings page itself would never allow.
         */
        public static function handle(WP_REST_Request $request) {
            if (!class_exists('KW_Security_Alerts')) {
                return new WP_REST_Response(array('ok' => false, 'message' => 'Not available on this plugin version.'), 500);
            }

            // A constant/env value always wins over the stored option (see
            // KW_Security_Alerts::get_webhook_url()), so writing the option
            // here would silently do nothing — tell the caller instead of
            // pretending it worked.
            if (KW_Security_Alerts::is_webhook_overridden()) {
                return new WP_REST_Response(array(
                    'ok'      => false,
                    'message' => "This site's webhook is set via wp-config.php or an environment variable and can't be changed from the dashboard.",
                ), 409);
            }

            $webhook_url = esc_url_raw(trim((string) $request->get_param('webhook_url')));
            $channel_id  = sanitize_text_field(trim((string) $request->get_param('channel_id')));

            if ('' !== $webhook_url && !KW_Security_Alerts::is_valid_webhook($webhook_url)) {
                return new WP_REST_Response(array(
                    'ok'      => false,
                    'message' => 'Slack webhook URL must be a https://hooks.slack.com/… address.',
                ), 400);
            }

            update_option(KW_Security_Alerts::OPTION_WEBHOOK, $webhook_url);
            update_option(KW_Security_Alerts::OPTION_CHANNEL_ID, $channel_id);

            return new WP_REST_Response(array(
                'ok'          => true,
                'webhook_url' => $webhook_url,
                'channel_id'  => $channel_id,
            ), 200);
        }
    }

    add_action('rest_api_init', array('KW_Security_Slack_Webhook_Set', 'init'));
}
