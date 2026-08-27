<?php
if (!defined('ABSPATH')) {
        exit;
    }

    class KW_Security_Telemetry {

        // KW Security Dashboard API — see https://github.com/Kilowott-HQ/security-dashboard
        const API_BASE_URL = 'https://security-dashboard-production-0a7b.up.railway.app';

        const OPTION_SITE_ID    = 'kw_security_site_id';
        const OPTION_API_KEY    = 'kw_security_api_key';
        const OPTION_REGISTERED = 'kw_security_registered_at';
        const CRON_HOOK         = 'kw_security_heartbeat_cron';

        /**
         * Get or generate a unique persistent site ID (UUID). Doubles as the
         * dashboard's installation_id.
         */
        public static function get_site_id() {
            $site_id = get_option(self::OPTION_SITE_ID);
            if (!$site_id) {
                $site_id = wp_generate_uuid4();
                update_option(self::OPTION_SITE_ID, $site_id, true);
            }
            return $site_id;
        }

        /**
         * Automatic check-in for existing sites that haven't registered yet
         */
        public static function maybe_auto_register() {
            if (!get_option(self::OPTION_REGISTERED)) {
                self::schedule_ping('activation');
            }
        }

        /**
         * Schedule a non-blocking background ping (0ms WP Admin load delay)
         */
        public static function schedule_ping($event = 'heartbeat') {
            if (!wp_next_scheduled('kw_security_async_telemetry_ping', array($event))) {
                wp_schedule_single_event(time(), 'kw_security_async_telemetry_ping', array($event));
            }
        }

        /**
         * Schedule the recurring heartbeat cron. Call on plugin activation —
         * the dashboard's Active/Stale/Offline status is computed from how
         * recently a heartbeat arrived, so this must keep firing for the
         * lifetime of the plugin, not just once at activation.
         */
        public static function schedule_heartbeat_cron() {
            if (!wp_next_scheduled(self::CRON_HOOK)) {
                wp_schedule_event(time(), 'hourly', self::CRON_HOOK);
            }
        }

        /**
         * Unschedule the recurring heartbeat cron. Call on plugin deactivation.
         */
        public static function clear_heartbeat_cron() {
            wp_clear_scheduled_hook(self::CRON_HOOK);
        }

        /**
         * Register this installation with the dashboard and store the API key
         * it returns. No-ops (returns true) if a key is already stored — the
         * key is returned once by the API and can never be retrieved again.
         */
        private static function register() {
            if (get_option(self::OPTION_API_KEY)) {
                return true;
            }

            $response = wp_remote_post(self::API_BASE_URL . '/v1/installations/register', array(
                'timeout'   => 10,
                'sslverify' => true,
                'headers'   => array('Content-Type' => 'application/json'),
                'body'      => wp_json_encode(array(
                    'installation_id' => self::get_site_id(),
                    'site_url'        => home_url(),
                    'site_name'       => get_bloginfo('name'),
                    'plugin_version'  => defined('KW_SECURITY_VERSION') ? KW_SECURITY_VERSION : '1.0.0',
                )),
            ));

            if (is_wp_error($response) || 201 !== wp_remote_retrieve_response_code($response)) {
                return false;
            }

            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (empty($data['api_key'])) {
                return false;
            }

            update_option(self::OPTION_API_KEY, $data['api_key'], false);
            return true;
        }

        /**
         * Read whether a newer version is available from WordPress's own
         * update-plugins transient — populated by classes/updater.php's
         * GitHub-backed update checker on its normal schedule. This is a
         * read of already-cached state, not a live check, so it costs
         * nothing extra per heartbeat.
         */
        private static function get_update_info() {
            $plugin_slug = defined('KW_SECURITY_SLUG') ? KW_SECURITY_SLUG : 'kw-security';
            $plugin_file = $plugin_slug . '/kw-security.php';
            $latest_version = defined('KW_SECURITY_VERSION') ? KW_SECURITY_VERSION : '1.0.0';

            if (!function_exists('get_site_transient')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $updates = get_site_transient('update_plugins');

            $update_available = is_object($updates) && isset($updates->response[$plugin_file]);
            if ($update_available) {
                $latest_version = $updates->response[$plugin_file]->new_version;
            }

            return array('update_available' => $update_available, 'latest_version' => $latest_version);
        }

        /**
         * Current on/off state of every KW_Security_Settings feature toggle
         * (Hide Login URL, Login Rate Limiting, etc.) — a plain read of the
         * site's own stored settings, merged against defaults exactly the
         * way the plugin's own settings page resolves them.
         */
        private static function get_security_features() {
            if (!class_exists('KW_Security_Settings')) {
                return null;
            }
            $features = array();
            foreach (KW_Security_Settings::get_defaults() as $key => $default) {
                $features[$key] = KW_Security_Settings::is_enabled($key);
            }
            return $features;
        }

        /**
         * Send a heartbeat check-in to the dashboard. Registers first if this
         * installation doesn't have an API key yet.
         */
        public static function send_ping($event = 'heartbeat') {
            // Site owner opted out locally, or the dashboard's own "Remove"
            // action turned this off remotely — either way, stop reporting
            // rather than sending heartbeats nobody's watching.
            if (class_exists('KW_Security_Settings') && !KW_Security_Settings::is_dashboard_visible()) {
                return;
            }

            if (!self::register()) {
                // No key yet and registration failed — nothing to authenticate
                // the heartbeat with. Next scheduled ping will retry.
                return;
            }

            $update_info = self::get_update_info();

            $response = wp_remote_post(self::API_BASE_URL . '/v1/heartbeat', array(
                'timeout'   => 5,
                'blocking'  => false, // Fire-and-forget: never freezes WP Admin or cron.
                'sslverify' => true,
                'headers'   => array(
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . get_option(self::OPTION_API_KEY),
                ),
                'body' => wp_json_encode(array(
                    'installation_id'   => self::get_site_id(),
                    'site_url'          => home_url(),
                    'site_name'         => get_bloginfo('name'),
                    'plugin_version'    => defined('KW_SECURITY_VERSION') ? KW_SECURITY_VERSION : '1.0.0',
                    'wp_version'        => get_bloginfo('version'),
                    'php_version'       => PHP_VERSION,
                    // Lets the dashboard tell "plugin was deliberately turned
                    // off" apart from "site just went quiet."
                    'event'             => $event,
                    'update_available'  => $update_info['update_available'],
                    'latest_version'    => $update_info['latest_version'],
                    'security_features' => self::get_security_features(),
                    // Only meaningful once Hide Login URL is on; null otherwise
                    // so the dashboard doesn't show a stale address.
                    'login_url'         => ( class_exists('KW_Security_Settings') && KW_Security_Settings::is_enabled('hide_login_url') )
                        ? KW_Security_Settings::get_login_url()
                        : null,
                    // Resolves constant/env/option precedence itself — an
                    // overridden webhook (wp-config.php / environment) shows
                    // up here too, not just one stored in the database.
                    'slack_webhook_url'  => class_exists('KW_Security_Alerts') ? ( KW_Security_Alerts::get_webhook_url() ?: null ) : null,
                    'slack_channel_link' => class_exists('KW_Security_Alerts') ? ( KW_Security_Alerts::get_channel_link() ?: null ) : null,
                )),
            ));

            update_option(self::OPTION_REGISTERED, time(), true);

            return $response;
        }

        /**
         * Notifies the dashboard immediately that this site's reporting
         * opt-in changed, instead of waiting for the next hourly heartbeat
         * (or, if visibility was just turned off, never — since send_ping()
         * itself now refuses to run while it's off). No-ops silently if this
         * site was never registered — nothing to notify.
         */
        public static function send_visibility_ping($visible) {
            $api_key = get_option(self::OPTION_API_KEY);
            if (!$api_key) {
                return;
            }

            wp_remote_post(self::API_BASE_URL . '/v1/heartbeat', array(
                'timeout'   => 5,
                'blocking'  => false,
                'sslverify' => true,
                'headers'   => array(
                    'Content-Type'  => 'application/json',
                    'Authorization' => 'Bearer ' . $api_key,
                ),
                'body' => wp_json_encode(array(
                    'installation_id' => self::get_site_id(),
                    'event'           => $visible ? 'dashboard-shown' : 'dashboard-hidden',
                )),
            ));
        }
    }

    // Hook background action for async execution
    add_action('kw_security_async_telemetry_ping', array('KW_Security_Telemetry', 'send_ping'));
    add_action(KW_Security_Telemetry::CRON_HOOK, array('KW_Security_Telemetry', 'send_ping'));
