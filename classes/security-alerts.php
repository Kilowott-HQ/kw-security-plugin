<?php
/**
 * KW Security – Slack Security Alerts
 *
 * Central dispatcher that forwards *critical security events* to a Slack
 * channel via an Incoming Webhook. This is deliberately NOT a mirror of the
 * Activity Log — it sends only high-signal breach indicators (brute-force
 * lockouts, administrator privilege changes, blocked malicious uploads,
 * file-integrity anomalies, disabled defenses, and — in future — malware).
 *
 * Design: each producing module fires a lightweight do_action at the exact
 * point it already detects the condition. This class listens, maps the
 * event to a category, and dispatches if that category is enabled. The
 * routing is per-site (no central pipeline), mirroring the File Integrity
 * email-alert approach.
 *
 * Sends are non-blocking and de-duplicated within a short window so an
 * active attack (e.g. a brute-force burst) cannot flood the channel.
 *
 * Webhook URL resolution (highest precedence first):
 *   1. KW_SLACK_WEBHOOK_URL constant (wp-config.php).
 *   2. KW_SLACK_WEBHOOK_URL environment variable.
 *   3. kw_slack_webhook option (Settings → KW Security).
 *
 * The entire payload is encoded with wp_json_encode(), so usernames, IPs,
 * and file paths cannot break out of or inject into the JSON body.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Alerts' ) ) {

    class KW_Security_Alerts {

        const OPTION_WEBHOOK    = 'kw_slack_webhook';
        const OPTION_CHANNEL_ID = 'kw_slack_channel_id'; // display-only bookmark, not used to send anything.
        const OPTION_CATEGORIES = 'kw_slack_alert_categories';
        const OPTION_MENTION    = 'kw_slack_mention';
        const OPTION_FM_BASELINE = 'kw_slack_fm_baseline_done'; // one-time file-manager sweep flag.
        const OPTION_WF_CRITICAL_ONLY = 'kw_slack_wordfence_critical_only'; // relay only critical WF emails.
        // Per-version de-dupe sets for the two update alerts. Deliberately
        // separate options: one shared set would let either producer suppress
        // the other's alerts.
        const OPTION_WATCHED_UPDATES  = 'kw_slack_alerted_watched_updates';
        const OPTION_CRITICAL_UPDATES = 'kw_slack_alerted_updates';
        const CONST_WEBHOOK     = 'KW_SLACK_WEBHOOK_URL';
        const ENV_WEBHOOK       = 'KW_SLACK_WEBHOOK_URL';
        const CONST_MENTION     = 'KW_SLACK_MENTION';
        const ENV_MENTION       = 'KW_SLACK_MENTION';
        const DEDUPE_WINDOW     = 300; // seconds — collapse identical alerts.
        // How long a "we already said this" entry stands before the same,
        // still-unapplied update becomes worth mentioning again: 90 days.
        const UPDATE_ALERT_TTL  = 7776000;
        const MAX_QUEUE         = 50;  // hard cap on per-request queued alerts.

        /** @var array<int,array{url:string,body:string,key:string}> Pending sends, flushed on shutdown. */
        private $queue = array();

        /** @var array<string,bool> Dedupe keys already queued this request. */
        private $queued_keys = array();

        /** @var bool Whether the shutdown flush callback is registered. */
        private $shutdown_hooked = false;

        public function __construct() {
            // ── Producer hooks fired by sibling modules ──────────────────
            add_action( 'kw_login_lockout',          array( $this, 'on_login_lockout' ),  10, 3 );
            add_action( 'kw_upload_blocked',         array( $this, 'on_upload_blocked' ), 10, 2 );
            add_action( 'kw_file_integrity_anomaly', array( $this, 'on_file_anomaly' ),   10, 2 );
            add_action( 'kw_malware_detected',       array( $this, 'on_malware' ),        10, 1 );

            // ── Login attempt blocked because the IP is already locked ───
            add_action( 'kw_login_blocked', array( $this, 'on_login_blocked' ), 10, 2 );

            // ── WordPress core signals (no producer edit needed) ─────────
            add_action( 'wp_login',            array( $this, 'on_login' ),          10, 2 );
            add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 1 );
            add_action( 'profile_update',      array( $this, 'on_profile_update' ), 10, 2 );
            add_action( 'set_user_role',       array( $this, 'on_set_user_role' ),  10, 3 );
            add_action( 'delete_user',         array( $this, 'on_delete_user' ),    10, 1 );
            // On multisite, network-wide deletion runs through
            // wpmu_delete_user() and never fires 'delete_user', so
            // admin_deleted would never fire on a network install. Both hooks
            // pass the user ID first and fire before the row is removed, so a
            // single handler serves both; wpmu_delete_user() does not call
            // wp_delete_user(), so they cannot double-fire.
            add_action( 'wpmu_delete_user',    array( $this, 'on_delete_user' ),    10, 1 );
            // Super Admin is network-wide privilege and is granted/revoked
            // outside the role system, so set_user_role never sees it.
            add_action( 'granted_super_admin', array( $this, 'on_granted_super_admin' ), 10, 1 );
            add_action( 'revoked_super_admin', array( $this, 'on_revoked_super_admin' ), 10, 1 );
            add_action( 'update_option_' . KW_Security_Settings::OPTION_NAME, array( $this, 'on_features_changed' ), 10, 2 );

            // ── Plugin / credential / update signals ─────────────────────
            add_action( 'deactivated_plugin',             array( $this, 'on_plugin_deactivated' ), 10, 1 );
            add_action( 'activated_plugin',               array( $this, 'on_plugin_activated' ),   10, 1 );
            // One-time sweep of already-active plugins; thereafter only newly
            // activated plugins are checked (via activated_plugin above).
            add_action( 'admin_init', array( $this, 'maybe_baseline_file_managers' ) );
            add_action( 'wp_create_application_password', array( $this, 'on_app_password' ),       10, 4 );
            // WooCommerce REST API key creation has no post-create hook, so we
            // listen just before WC's own AJAX handler (its priority is 10).
            add_action( 'wp_ajax_woocommerce_update_api_key', array( $this, 'on_woo_api_key' ), 9 );
            add_action( 'set_site_transient_update_plugins', array( $this, 'on_plugins_update_check' ), 10, 1 );

            // Wordfence's wordfence_security_event action is intentionally NOT
            // consumed: its event names vary across versions (admin-login events
            // are email-only on current trunk, and 'block' covers every
            // firewall action, not just logins). Login/lockout detection stays
            // native (robust, version-independent); only Wordfence *scan*
            // findings are relayed, via its alert emails.
            add_filter( 'wp_mail', array( $this, 'on_wp_mail' ), 99, 1 );
        }

        // ----------------------------------------------------------------
        // Category registry
        // ----------------------------------------------------------------

        /**
         * Alert categories and their human-readable labels. Order is the
         * order shown in the settings checklist.
         *
         * @return array<string,string>
         */
        public static function get_categories() {
            return array(
                // ── Authentication / login ──────────────────────────────
                'admin_login_new_ip' => __( 'Administrator login from a new / unrecognized IP (possible credential compromise)', 'kw-security' ),
                'admin_login'        => __( 'Administrator login, successful (every privileged sign-in)', 'kw-security' ),
                'login_lockout'      => __( 'Brute-force lockout (IP blocked after repeated failed logins)', 'kw-security' ),
                'login_blocked'      => __( 'Login attempt from an already locked-out IP (ongoing brute-force)', 'kw-security' ),
                'password_reset'     => __( 'Administrator password changed or reset (account-takeover vector)', 'kw-security' ),
                // ── Privilege / account / credentials ───────────────────
                'admin_granted'      => __( 'Administrator privilege granted (new admin or promotion)', 'kw-security' ),
                'admin_deleted'      => __( 'Administrator account deleted', 'kw-security' ),
                'super_admin_granted' => __( 'Super Admin / network privilege granted (multisite only — full-network takeover vector)', 'kw-security' ),
                'super_admin_revoked' => __( 'Super Admin / network privilege revoked (multisite only — often precedes account deletion)', 'kw-security' ),
                'app_password_created' => __( 'Application Password created (REST/API credential)', 'kw-security' ),
                'rest_key_generated' => __( 'WooCommerce REST API key created (consumer key/secret)', 'kw-security' ),
                // ── Files / integrity ───────────────────────────────────
                'upload_blocked'     => __( 'Dangerous file upload blocked', 'kw-security' ),
                'file_changed'       => __( 'File integrity anomaly (unknown or modified core file)', 'kw-security' ),
                // ── Configuration / plugins / malware ───────────────────
                'security_disabled'  => __( 'A KW Security defense was switched off', 'kw-security' ),
                // Key kept as-is for backward compatibility: it predates KW
                // Security being watched too, and renaming it would silently
                // reset the saved preference on every existing site.
                'wordfence_deactivated' => __( 'Security plugin deactivated (Wordfence or KW Security)', 'kw-security' ),
                'security_plugin_activated' => __( 'Security plugin activated (Wordfence or KW Security)', 'kw-security' ),
                'watched_plugin_update' => __( 'Update available for KW Security or Wordfence (any version, with release notes)', 'kw-security' ),
                'plugin_update_critical' => __( 'Plugin update available — security patch or major version (any other plugin)', 'kw-security' ),
                'file_manager_active' => __( 'File-manager plugin active (direct file CRUD — high risk)', 'kw-security' ),
                'wordfence_alert'    => __( 'Relay Wordfence alerts (mirrors Wordfence email alerts to Slack)', 'kw-security' ),
                'malware'            => __( 'Malware detected', 'kw-security' ),
            );
        }

        /**
         * Category keys grouped under human-readable section headings, in
         * display order. This is a presentation-only grouping consumed by the
         * settings UI; the canonical category list remains get_categories().
         * Any category not listed here still renders (under "Other") so a new
         * key is never silently hidden from the settings screen.
         *
         * @return array<string,string[]> Section label => ordered category keys.
         */
        public static function get_category_groups() {
            return array(
                __( 'Authentication / login', 'kw-security' ) => array(
                    'admin_login_new_ip',
                    'admin_login',
                    'login_lockout',
                    'login_blocked',
                    'password_reset',
                ),
                __( 'Privilege / account / credentials', 'kw-security' ) => array(
                    'admin_granted',
                    'admin_deleted',
                    'super_admin_granted',
                    'super_admin_revoked',
                    'app_password_created',
                    'rest_key_generated',
                ),
                __( 'Files / integrity', 'kw-security' ) => array(
                    'upload_blocked',
                    'file_changed',
                ),
                __( 'Configuration / plugins / malware', 'kw-security' ) => array(
                    'security_disabled',
                    'wordfence_deactivated',
                    'security_plugin_activated',
                    'watched_plugin_update',
                    'plugin_update_critical',
                    'file_manager_active',
                    'wordfence_alert',
                    'malware',
                ),
            );
        }

        /**
         * Per-category default state. Every item is a genuine breach
         * indicator, so all default ON except 'admin_login' — a routine
         * successful admin sign-in can be chatty on multi-admin sites, so it
         * is opt-in. 'admin_login_new_ip' (the high-signal, low-noise
         * variant) stays on.
         *
         * @return array<string,bool>
         */
        public static function get_default_categories() {
            $defaults = array_fill_keys( array_keys( self::get_categories() ), true );
            $defaults['admin_login'] = false;
            return $defaults;
        }

        /**
         * Resolved per-category enable map (stored option merged on defaults).
         *
         * @return array<string,bool>
         */
        public static function get_enabled_categories() {
            $stored = get_option( self::OPTION_CATEGORIES, array() );
            if ( ! is_array( $stored ) ) {
                $stored = array();
            }
            return wp_parse_args( $stored, self::get_default_categories() );
        }

        public static function is_category_enabled( $category ) {
            $map = self::get_enabled_categories();
            return ! empty( $map[ $category ] );
        }

        /**
         * Categories detected SOLELY by Wordfence (relayed via its scan alert
         * emails) rather than natively. The native handler for each short-
         * circuits when Wordfence is active, so there is no double-alerting.
         * Filterable so a site without Wordfence — or one that prefers native
         * detection — can reclaim any of them.
         *
         * file_changed is deliberately NOT in this list: it is dual-sourced.
         * KW's native root scan fires immediately when you run a scan, and
         * Wordfence's later full-tree scan relays on its own schedule. The two
         * cover different scopes (WP root vs. whole tree) and are distinguished
         * in Slack by a "Source" line. A site that wants the old relay-only
         * behaviour can add 'file_changed' back via the filter below.
         *
         * @return array<int,string>
         */
        public static function get_wordfence_sourced() {
            // Only Wordfence *scan* findings are relayed (via alert emails),
            // because those are reliable across versions. Login/lockout/block
            // detection stays native — it does not depend on Wordfence-internal
            // event names that change between releases.
            return (array) apply_filters( 'kw_slack_wordfence_sourced', array(
                'plugin_update_critical',
                'malware',
            ) );
        }

        /**
         * Whether to relay ONLY critical Wordfence alert emails — malware,
         * file changes, and vulnerable/abandoned plugins. When enabled (the
         * default), Wordfence emails that don't route to one of those specific
         * categories (status notices, summaries, routine plugin-update nags,
         * and other low-signal mail) are dropped instead of being relayed
         * under the generic wordfence_alert category. Turn it off to relay
         * every qualifying Wordfence email.
         *
         * @return bool
         */
        public static function is_wordfence_critical_only() {
            return (bool) get_option( self::OPTION_WF_CRITICAL_ONLY, true );
        }

        private function from_wordfence( $category ) {
            // When Wordfence is not active there is nothing to relay, so fall
            // back to native detection rather than silently dropping the event.
            if ( ! class_exists( 'wfConfig' ) ) {
                return false;
            }
            return in_array( $category, self::get_wordfence_sourced(), true );
        }

        // ----------------------------------------------------------------
        // Webhook resolution
        // ----------------------------------------------------------------

        public static function get_webhook_url() {
            if ( defined( self::CONST_WEBHOOK ) && constant( self::CONST_WEBHOOK ) ) {
                return (string) constant( self::CONST_WEBHOOK );
            }
            $env = getenv( self::ENV_WEBHOOK );
            if ( $env ) {
                return (string) $env;
            }
            return (string) get_option( self::OPTION_WEBHOOK, '' );
        }

        public static function is_webhook_overridden() {
            return ( defined( self::CONST_WEBHOOK ) && constant( self::CONST_WEBHOOK ) )
                || (bool) getenv( self::ENV_WEBHOOK );
        }

        /**
         * ID of the Slack channel alerts land in — a Slack Incoming Webhook
         * URL itself doesn't encode which channel it posts to (that binding
         * lives only on Slack's servers), so this is a second, separately-
         * entered value the dashboard uses to build its "View Channel" link
         * (combined with the Team ID embedded in the webhook URL itself).
         * Never used to send anything.
         *
         * @return string
         */
        public static function get_channel_id() {
            return (string) get_option( self::OPTION_CHANNEL_ID, '' );
        }

        /**
         * Raw comma-separated mention targets (constant → env → option).
         *
         * @return string
         */
        public static function get_mention_string() {
            if ( defined( self::CONST_MENTION ) && constant( self::CONST_MENTION ) ) {
                return (string) constant( self::CONST_MENTION );
            }
            $env = getenv( self::ENV_MENTION );
            if ( $env ) {
                return (string) $env;
            }
            return (string) get_option( self::OPTION_MENTION, '' );
        }

        public static function is_mention_overridden() {
            return ( defined( self::CONST_MENTION ) && constant( self::CONST_MENTION ) )
                || (bool) getenv( self::ENV_MENTION );
        }

        /**
         * Build the Slack mention prefix from the configured CSV. Slack
         * incoming webhooks only notify by member/group ID, so:
         *   - <…> tokens are passed through unchanged,
         *   - here / channel / everyone become <!…>,
         *   - user IDs (U…/W…) become <@…>, group IDs (S…) become <!subteam^…>,
         *   - anything else is left as plain text (shown but won't ping).
         *
         * @return string Space-separated mention tokens, or ''.
         */
        private function format_mentions() {
            $raw = self::get_mention_string();
            if ( '' === trim( $raw ) ) {
                return '';
            }
            $out = array();
            foreach ( explode( ',', $raw ) as $token ) {
                $token = trim( $token );
                if ( '' === $token ) {
                    continue;
                }
                $bare = ltrim( $token, '!@' );
                if ( in_array( strtolower( $bare ), array( 'here', 'channel', 'everyone' ), true ) ) {
                    $out[] = '<!' . strtolower( $bare ) . '>';
                } elseif ( preg_match( '/^[UW][A-Z0-9]{6,}$/', $bare ) ) {
                    $out[] = '<@' . $bare . '>';
                } elseif ( preg_match( '/^S[A-Z0-9]{6,}$/', $bare ) ) {
                    $out[] = '<!subteam^' . $bare . '>';
                } elseif ( preg_match( '/^<(@[UW][A-Z0-9]+|#[CG][A-Z0-9]+|!subteam\^[A-Z0-9]+|!(?:here|channel|everyone))>$/', $token ) ) {
                    // Already a well-formed Slack control sequence — pass through.
                    $out[] = $token;
                }
                // Anything else (plain names, "<https://evil|click>" link
                // tokens) is dropped: it would not ping and could inject markup.
            }
            return implode( ' ', $out );
        }

        // ----------------------------------------------------------------
        // Dispatch
        // ----------------------------------------------------------------

        /**
         * Send one alert to Slack, subject to category enablement, webhook
         * configuration, and burst de-duplication.
         *
         * @param string $category One of get_categories() keys.
         * @param string $title    One-line headline.
         * @param array  $context  Optional label => value detail lines.
         */
        public function notify( $category, $title, array $context = array() ) {
            if ( ! self::is_category_enabled( $category ) ) {
                return;
            }
            $url = self::get_webhook_url();
            if ( ! self::is_valid_webhook( $url ) ) {
                return;
            }

            // Cap the headline so a crafted/huge value (e.g. a 65 KB email
            // subject or filename) can't produce a payload Slack rejects.
            $title = self::truncate( (string) $title, 280 );

            /**
             * Final say on whether an alert is sent. Return false to drop it.
             *
             * @param bool   $send
             * @param string $category
             * @param string $title
             * @param array  $context
             */
            if ( ! apply_filters( 'kw_slack_alert_send', true, $category, $title, $context ) ) {
                return;
            }

            // De-duplicate. Burst-prone categories key on the category alone so
            // a botnet rotating IPs can't flood the channel with near-identical
            // alerts; everything else keys on the headline too. The transient is
            // written only AFTER successful delivery (in flush()), so a request
            // that fatals mid-shutdown doesn't suppress the retry.
            $dedupe_key = self::dedupe_key( $category, $title );
            if ( isset( $this->queued_keys[ $dedupe_key ] ) || get_transient( $dedupe_key ) ) {
                return;
            }

            // Bound the in-memory queue so an event flood can't exhaust memory.
            if ( count( $this->queue ) >= self::MAX_QUEUE ) {
                return;
            }

            $body = wp_json_encode( $this->build_payload( $category, $title, $context ) );
            if ( false === $body ) {
                return;
            }

            // Queue the send and flush on shutdown rather than posting inline.
            // A non-blocking POST here is unreliable: most admin write-actions
            // (create/delete user, role change, settings save) call
            // wp_redirect()+exit immediately after the event hook, tearing down
            // the socket before a fire-and-forget request can transmit.
            $this->queued_keys[ $dedupe_key ] = true;
            $this->queue[] = array(
                'url'  => $url,
                'body' => $body,
                'key'  => $dedupe_key,
            );
            if ( ! $this->shutdown_hooked ) {
                add_action( 'shutdown', array( $this, 'flush' ), 0 );
                $this->shutdown_hooked = true;
            }
        }

        /**
         * Deliver queued alerts at shutdown. Closes the visitor connection
         * first (on FPM) so the blocking sends add no perceptible latency,
         * then posts each alert with blocking => true so the request fully
         * transmits before PHP exits.
         */
        public function flush() {
            if ( empty( $this->queue ) ) {
                return;
            }
            $queue       = $this->queue;
            $this->queue = array();

            if ( function_exists( 'fastcgi_finish_request' ) ) {
                fastcgi_finish_request();
            }

            foreach ( $queue as $item ) {
                $response = wp_remote_post( $item['url'], array(
                    'timeout'     => 4,
                    'blocking'    => true,
                    'headers'     => array( 'Content-Type' => 'application/json' ),
                    'body'        => $item['body'],
                    'data_format' => 'body',
                ) );

                if ( is_wp_error( $response ) ) {
                    if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                        error_log( '[kw-security] Slack alert delivery failed: ' . $response->get_error_message() );
                    }
                    continue; // Leave dedupe unset so a later event can retry.
                }

                $code = (int) wp_remote_retrieve_response_code( $response );
                if ( $code < 200 || $code >= 300 ) {
                    if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                        error_log( '[kw-security] Slack alert rejected (HTTP ' . $code . ')' );
                    }
                    continue;
                }

                // Delivered — now suppress identical repeats for the window.
                if ( ! empty( $item['key'] ) ) {
                    set_transient( $item['key'], 1, self::DEDUPE_WINDOW );
                }
            }
        }

        /**
         * Build the Slack Incoming Webhook payload. The whole array is
         * wp_json_encode()d by notify(), so every value is escaped as data.
         *
         * @param string $category
         * @param string $title
         * @param array  $context
         * @return array
         */
        private function build_payload( $category, $title, $context ) {
            $labels = self::get_categories();
            $label  = isset( $labels[ $category ] ) ? $labels[ $category ] : $category;
            $site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

            // Mentions are intentional Slack control sequences and must NOT be
            // escaped. Everything else interpolated below is data (site name,
            // title, labels, context values) and IS escaped so a value such as
            // a filename or username cannot inject Slack mrkdwn — e.g. a
            // "<!channel>" upload name forcing a channel-wide ping.
            $mentions = $this->format_mentions();
            $text     = ( '' !== $mentions ? $mentions . ' ' : '' )
                . ':rotating_light: *' . self::esc_slack( $site ) . '* — ' . self::esc_slack( $title ) . "\n";
            $text    .= '_' . self::esc_slack( $label ) . '_';
            foreach ( $context as $k => $v ) {
                if ( '' === $v || null === $v ) {
                    continue;
                }
                $text .= "\n• *" . self::esc_slack( (string) $k ) . ":* " . self::esc_slack( self::truncate( (string) $v, 400 ) );
            }

            return array(
                'text'   => $text,
                'blocks' => array(
                    array(
                        'type' => 'section',
                        'text' => array( 'type' => 'mrkdwn', 'text' => $text ),
                    ),
                    array(
                        'type'     => 'context',
                        'elements' => array(
                            array( 'type' => 'mrkdwn', 'text' => self::esc_slack( home_url() ) . '  •  ' . date_i18n( 'Y-m-d H:i:s' ) ),
                        ),
                    ),
                ),
            );
        }

        /**
         * Escape Slack mrkdwn control characters in interpolated data so user-
         * controlled values cannot inject mentions, links, or formatting.
         * Slack requires only &, <, > to be escaped (in that order — & first).
         *
         * @param string $text
         * @return string
         */
        private static function esc_slack( $text ) {
            return str_replace(
                array( '&', '<', '>' ),
                array( '&amp;', '&lt;', '&gt;' ),
                (string) $text
            );
        }

        /**
         * A webhook URL must be an HTTPS Slack-hosted endpoint. Prevents an
         * admin (or a tampered option) from repointing security-event payloads
         * at an arbitrary or internal host (SSRF / data exfiltration).
         *
         * @param string $url
         * @return bool
         */
        public static function is_valid_webhook( $url ) {
            $url = (string) $url;
            if ( '' === $url ) {
                return false;
            }
            $parts = wp_parse_url( $url );
            return ! empty( $parts['scheme'] ) && 'https' === strtolower( $parts['scheme'] )
                && ! empty( $parts['host'] ) && 'hooks.slack.com' === strtolower( $parts['host'] );
        }

        /**
         * Build the de-dupe transient key. Burst-prone categories collapse to a
         * single alert per window regardless of headline (so a botnet rotating
         * IPs can't flood the channel); others include the headline.
         *
         * @param string $category
         * @param string $title
         * @return string
         */
        private static function dedupe_key( $category, $title ) {
            $burst = array( 'login_lockout', 'login_blocked' );
            $basis = in_array( $category, $burst, true ) ? $category : ( $category . '|' . $title );
            return 'kw_slack_seen_' . md5( $basis );
        }

        /**
         * Length-cap a string (multibyte-aware), appending an ellipsis when cut.
         *
         * @param string $text
         * @param int    $len
         * @return string
         */
        private static function truncate( $text, $len ) {
            $text = (string) $text;
            if ( function_exists( 'mb_strlen' ) ) {
                return mb_strlen( $text ) > $len ? mb_substr( $text, 0, $len ) . '…' : $text;
            }
            return strlen( $text ) > $len ? substr( $text, 0, $len ) . '…' : $text;
        }

        // ----------------------------------------------------------------
        // Listeners → categories
        // ----------------------------------------------------------------

        public function on_login_lockout( $ip, $count, $username = '' ) {
            if ( $this->from_wordfence( 'login_lockout' ) ) {
                return; // Relayed from Wordfence instead.
            }
            $this->notify(
                'login_lockout',
                sprintf( 'IP %s locked out after %d failed login attempts', $ip, (int) $count ),
                array(
                    'IP'            => $ip,
                    'Attempts'      => (int) $count,
                    'Last username' => $username,
                )
            );
        }

        public function on_login_blocked( $ip, $username = '' ) {
            if ( $this->from_wordfence( 'login_blocked' ) ) {
                return; // Relayed from Wordfence instead.
            }
            $this->notify(
                'login_blocked',
                sprintf( 'Login attempt from already locked-out IP %s', $ip ),
                array(
                    'IP'                 => $ip,
                    'Attempted username' => $username,
                )
            );
        }

        /**
         * Successful login. Alerts only for privileged accounts, splitting
         * into a high-signal "new IP" alert (possible credential compromise)
         * versus a routine "admin login" alert from a recognized IP.
         *
         * @param string  $user_login
         * @param WP_User $user
         */
        public function on_login( $user_login, $user ) {
            if ( $this->from_wordfence( 'admin_login' ) && $this->from_wordfence( 'admin_login_new_ip' ) ) {
                return; // Relayed from Wordfence instead.
            }
            if ( ! ( $user instanceof WP_User ) || ! $this->is_privileged( $user ) ) {
                return;
            }
            $ip = $this->client_ip();

            if ( $this->login_ip_is_new( $user->ID, $ip ) ) {
                $this->notify(
                    'admin_login_new_ip',
                    sprintf( 'Administrator %s logged in from a new IP (%s)', $user_login, $ip ? $ip : 'unknown' ),
                    array(
                        'User' => $user_login,
                        'Role' => $this->primary_role( $user ),
                        'IP'   => $ip ? $ip : 'unknown',
                    )
                );
            } else {
                $this->notify(
                    'admin_login',
                    sprintf( 'Administrator login: %s', $user_login ),
                    array(
                        'User' => $user_login,
                        'Role' => $this->primary_role( $user ),
                        'IP'   => $ip ? $ip : 'unknown',
                    )
                );
            }
        }

        /**
         * Password reset completed. Alerts for privileged accounts only —
         * a reset on an admin account is a classic takeover vector.
         *
         * @param WP_User $user
         */
        public function on_password_reset( $user ) {
            if ( ! ( $user instanceof WP_User ) || ! $this->is_privileged( $user ) ) {
                return;
            }
            $this->notify(
                'password_reset',
                sprintf( 'Password reset completed for administrator %s', $user->user_login ),
                array(
                    'User' => $user->user_login,
                    'IP'   => $this->client_ip(),
                )
            );
        }

        /**
         * Password changed via the profile / edit-user screen. This is the
         * path the "Lost password" reset flow does NOT take — reset_password()
         * fires after_password_reset (above) instead — so the two listeners
         * are disjoint and never double-fire.
         *
         * Only fires when the password hash actually changed, so ordinary
         * profile edits (email, display name, etc.) are ignored.
         *
         * @param int     $user_id
         * @param WP_User $old_user_data User record before the update.
         */
        public function on_profile_update( $user_id, $old_user_data ) {
            $user = get_userdata( $user_id );
            if ( ! $user || ! $this->is_privileged( $user ) ) {
                return;
            }
            if ( ! ( $old_user_data instanceof WP_User ) || $old_user_data->user_pass === $user->user_pass ) {
                return;
            }
            $this->notify(
                'password_reset',
                sprintf( 'Password changed for administrator %s', $user->user_login ),
                array(
                    'User'       => $user->user_login,
                    'Changed by' => $this->current_user_label(),
                    'IP'         => $this->client_ip(),
                )
            );
        }

        public function on_upload_blocked( $filename, $reason = '' ) {
            $this->notify(
                'upload_blocked',
                sprintf( 'Blocked dangerous file upload: %s', $filename ),
                array(
                    'File'   => $filename,
                    'Reason' => $reason,
                    'User'   => $this->current_user_label(),
                    'IP'     => $this->client_ip(),
                )
            );
        }

        public function on_file_anomaly( $unknown, $modified ) {
            // file_changed is dual-sourced by default (native + Wordfence relay).
            // This only short-circuits if a site has opted file_changed back into
            // Wordfence-only sourcing via the kw_slack_wordfence_sourced filter.
            if ( $this->from_wordfence( 'file_changed' ) ) {
                return; // Site chose Wordfence-only sourcing for file changes.
            }
            $unknown  = is_array( $unknown )  ? $unknown  : array();
            $modified = is_array( $modified ) ? $modified : array();
            if ( ! $unknown && ! $modified ) {
                return;
            }
            $this->notify(
                'file_changed',
                sprintf( 'File integrity anomaly: %d issue(s) in the WordPress root', count( $unknown ) + count( $modified ) ),
                array(
                    // Distinguishes this immediate root scan from the later
                    // Wordfence full-tree scan that may relay the same finding.
                    'Source'         => 'KW file-integrity scan (WordPress root)',
                    'Unknown files'  => $unknown  ? implode( ', ', $unknown )  : '',
                    'Modified files' => $modified ? implode( ', ', $modified ) : '',
                )
            );
        }

        public function on_malware( $threats ) {
            $threats = is_array( $threats ) ? $threats : array( (string) $threats );
            $this->notify(
                'malware',
                sprintf( 'Malware detected: %d threat(s)', count( $threats ) ),
                array( 'Details' => implode( ', ', array_map( 'strval', $threats ) ) )
            );
        }

        public function on_set_user_role( $user_id, $role, $old_roles ) {
            if ( 'administrator' !== $role ) {
                return;
            }
            // Only alert when administrator is newly granted (creation or
            // promotion), not when re-saving a user who is already an admin.
            if ( is_array( $old_roles ) && in_array( 'administrator', $old_roles, true ) ) {
                return;
            }
            $user  = get_userdata( $user_id );
            $login = $user ? $user->user_login : ( '#' . (int) $user_id );
            $this->notify(
                'admin_granted',
                sprintf( 'Administrator privilege granted to %s', $login ),
                array(
                    'User'       => $login,
                    'Granted by' => $this->current_user_label(),
                    'IP'         => $this->client_ip(),
                )
            );
        }

        /**
         * Super Admin (network-wide) privilege granted. Multisite only.
         *
         * This is the highest privilege on the install — it confers every
         * capability on every site in the network, including sites the user is
         * not a member of — so it alerts regardless of any per-site role.
         *
         * Bound to the past-tense hook so only real changes are reported.
         * Caveat: defining $GLOBALS['super_admins'] in wp-config.php makes
         * grant_super_admin()/revoke_super_admin() bail before doing anything,
         * so networks pinning super admins that way change them outside
         * WordPress entirely and cannot be alerted on from here.
         *
         * @param int $user_id
         */
        public function on_granted_super_admin( $user_id ) {
            $this->notify_super_admin_change( 'super_admin_granted', $user_id, 'granted to', 'Granted by' );
        }

        /**
         * Super Admin privilege revoked. Multisite only. Worth alerting on in
         * its own right: core refuses to delete a live super admin, so
         * revocation is the required first step of removing one.
         *
         * @param int $user_id
         */
        public function on_revoked_super_admin( $user_id ) {
            $this->notify_super_admin_change( 'super_admin_revoked', $user_id, 'revoked from', 'Revoked by' );
        }

        /**
         * Shared body for the two super-admin privilege alerts.
         *
         * @param string $category
         * @param int    $user_id
         * @param string $verb       e.g. 'granted to'.
         * @param string $actor_label Context key naming who did it.
         */
        private function notify_super_admin_change( $category, $user_id, $verb, $actor_label ) {
            $user  = get_userdata( $user_id );
            $login = $user ? $user->user_login : ( '#' . (int) $user_id );
            $this->notify(
                $category,
                sprintf( 'Super Admin (network-wide) privilege %s %s', $verb, $login ),
                array(
                    'User'       => $login,
                    $actor_label => $this->current_user_label(),
                    'IP'         => $this->client_ip(),
                )
            );
        }

        public function on_delete_user( $user_id ) {
            $user = get_userdata( $user_id );
            if ( ! $user ) {
                return;
            }
            // Checked explicitly rather than via is_privileged() so the
            // kw_slack_alert_login_roles filter — which is scoped to logins —
            // does not silently start governing deletions too. Multisite super
            // admins are included because they may hold no role on any site.
            //
            // Serves both 'delete_user' and 'wpmu_delete_user'. Note core's
            // wpmu_delete_user() bails on a live super admin, so a super admin
            // is always demoted before deletion — the demotion is what
            // super_admin_revoked reports.
            $privileged = in_array( 'administrator', (array) $user->roles, true )
                || ( is_multisite() && is_super_admin( $user->ID ) );
            if ( ! $privileged ) {
                return;
            }
            $this->notify(
                'admin_deleted',
                sprintf( 'Administrator account deleted: %s', $user->user_login ),
                array(
                    'User'       => $user->user_login,
                    'Deleted by' => $this->current_user_label(),
                    'IP'         => $this->client_ip(),
                )
            );
        }

        public function on_features_changed( $old_value, $new_value ) {
            $old_value = is_array( $old_value ) ? $old_value : array();
            $new_value = is_array( $new_value ) ? $new_value : array();
            $disabled  = array();
            foreach ( $old_value as $key => $was_on ) {
                if ( $was_on && empty( $new_value[ $key ] ) ) {
                    $disabled[] = $key;
                }
            }
            if ( ! $disabled ) {
                return;
            }
            $this->notify(
                'security_disabled',
                sprintf( 'KW Security defense(s) switched off: %s', implode( ', ', $disabled ) ),
                array(
                    'Disabled'   => implode( ', ', $disabled ),
                    'Changed by' => $this->current_user_label(),
                    'IP'         => $this->client_ip(),
                )
            );
        }

        /**
         * Security plugins whose state and updates are reported to Slack:
         * Wordfence and KW Security itself. One list drives three alerts —
         * activation, deactivation, and update-available — so adding a plugin
         * here (via the filter) covers all three at once.
         *
         * @return array<int,string> Plugin files, e.g. 'wordfence/wordfence.php'.
         */
        private function watched_plugins() {
            return (array) apply_filters( 'kw_slack_alert_watch_plugins', array(
                'wordfence/wordfence.php',
                'kw-security/kw-security.php',
            ) );
        }

        /**
         * Display name for a watched plugin, falling back to its directory so a
         * non-standard install path still reads sensibly in Slack.
         *
         * @param string $plugin Plugin file.
         * @return string
         */
        private function watched_plugin_label( $plugin ) {
            if ( 'kw-security/kw-security.php' === $plugin ) {
                return 'KW Security';
            }
            if ( 'wordfence/wordfence.php' === $plugin ) {
                return 'Wordfence';
            }
            return ( '.' !== dirname( $plugin ) ) ? dirname( $plugin ) : $plugin;
        }

        /**
         * A plugin was deactivated. Alerts only for watched security plugins
         * (Wordfence and KW Security by default; extend via the filter).
         *
         * KW Security can report its own deactivation because this class is
         * instantiated when the plugin file is included, which happens before
         * deactivate_plugins() fires this hook — and the queued alert still
         * flushes on 'shutdown' for that same request.
         *
         * @param string $plugin Plugin file, e.g. 'wordfence/wordfence.php'.
         */
        public function on_plugin_deactivated( $plugin ) {
            if ( ! in_array( $plugin, $this->watched_plugins(), true ) ) {
                return;
            }
            $name = $this->watched_plugin_label( $plugin );
            $this->notify(
                'wordfence_deactivated',
                sprintf( 'Security plugin deactivated: %s', $name ),
                array(
                    'Plugin'         => $plugin,
                    'Deactivated by' => $this->current_user_label(),
                    'IP'             => $this->client_ip(),
                    'Impact'         => sprintf( '%s is no longer protecting this site.', $name ),
                )
            );
        }

        /**
         * A plugin was just activated. Two independent checks, either of which
         * may fire:
         *   - a watched security plugin came back on (Wordfence / KW Security),
         *   - a known file manager was switched on, which exposes direct
         *     create/read/update/delete access to the filesystem and is a
         *     frequent post-compromise backdoor.
         *
         * @param string $plugin Plugin file, e.g. 'wp-file-manager/file_folder_manager.php'.
         */
        public function on_plugin_activated( $plugin ) {
            if ( in_array( $plugin, $this->watched_plugins(), true ) ) {
                $name = $this->watched_plugin_label( $plugin );
                $this->notify(
                    'security_plugin_activated',
                    sprintf( 'Security plugin activated: %s', $name ),
                    array(
                        'Plugin'       => $plugin,
                        'Activated by' => $this->current_user_label(),
                        'IP'           => $this->client_ip(),
                    )
                );
            }

            $name = $this->matched_file_manager( $plugin );
            if ( null === $name ) {
                return;
            }
            $this->notify(
                'file_manager_active',
                sprintf( 'File-manager plugin activated: %s', $name ),
                array(
                    'Plugin'       => $plugin,
                    'Activated by' => $this->current_user_label(),
                    'IP'           => $this->client_ip(),
                    'Risk'         => 'Grants direct file CRUD via wp-admin — verify this was intentional.',
                )
            );
        }

        /**
         * One-time sweep of currently active plugins for file managers that
         * were already installed before this plugin started watching. Guarded
         * by an option flag so it runs once; afterwards on_plugin_activated()
         * covers every newly activated plugin.
         */
        public function maybe_baseline_file_managers() {
            if ( get_option( self::OPTION_FM_BASELINE ) ) {
                return;
            }
            // Mark done first so a failure mid-loop can't re-fire the sweep on
            // every admin request (the per-event de-dupe still guards repeats).
            update_option( self::OPTION_FM_BASELINE, 1, false );

            foreach ( (array) get_option( 'active_plugins', array() ) as $plugin ) {
                $name = $this->matched_file_manager( $plugin );
                if ( null === $name ) {
                    continue;
                }
                $this->notify(
                    'file_manager_active',
                    sprintf( 'File-manager plugin already active: %s', $name ),
                    array(
                        'Plugin' => $plugin,
                        'Note'   => 'Detected during initial scan of installed plugins.',
                        'Risk'   => 'Grants direct file CRUD via wp-admin — verify this is intentional.',
                    )
                );
            }
        }

        /**
         * If the given plugin file belongs to a known file-manager plugin,
         * return its display name; otherwise null. Matching is on the directory
         * slug (dirname), which is stable across the varying main-file names
         * these plugins use. The list is filterable so sites can extend it.
         *
         * @param string $plugin Plugin file relative to the plugins dir.
         * @return string|null Display name when matched, else null.
         */
        private function matched_file_manager( $plugin ) {
            $slug = strtolower( dirname( (string) $plugin ) );
            if ( '' === $slug || '.' === $slug ) {
                $slug = strtolower( basename( (string) $plugin, '.php' ) );
            }

            /**
             * Known file-manager plugin slugs => display name.
             *
             * @param array<string,string> $known slug => human-readable name.
             */
            // Slugs verified against wordpress.org. Scope is deliberately
            // server-filesystem CRUD file managers only — media-library folder
            // organizers (FileBird, Real Media Library, Media Library
            // Organizer) and download managers (Download Manager/Monitor) are a
            // different, lower risk class and are intentionally excluded to
            // avoid false positives. Closed/legacy slugs are retained because a
            // still-installed copy remains exploitable.
            $known = apply_filters( 'kw_slack_filemanager_known', array(
                'wp-file-manager'       => 'File Manager (WP File Manager)',
                'file-manager-advanced' => 'Advanced File Manager',
                'advanced-file-manager' => 'Advanced File Manager',
                'filester'              => 'File Manager Pro — Filester',
                'fileorganizer'         => 'FileOrganizer',
                'file-manager'          => 'File Manager',
                'wp-filemanager'        => 'wp-FileManager (legacy/closed)',
                'simple-file-list'      => 'Simple File List',
                'file-away'             => 'File Away (legacy/closed)',
                'wp-file-upload'        => 'WordPress File Upload (Iptanus)',
                'wpide'                 => 'WPide — File Manager & Code Editor',
            ) );

            return isset( $known[ $slug ] ) ? $known[ $slug ] : null;
        }

        /**
         * An Application Password was created (a REST/API credential that can
         * act as the user). The password itself is never included.
         *
         * @param int    $user_id
         * @param array  $new_item     The new application-password record.
         * @param string $new_password The plaintext password (NOT logged).
         * @param array  $args
         */
        public function on_app_password( $user_id, $new_item, $new_password, $args ) {
            $user  = get_userdata( $user_id );
            $login = $user ? $user->user_login : ( '#' . (int) $user_id );
            $name  = ( is_array( $new_item ) && ! empty( $new_item['name'] ) ) ? $new_item['name'] : '';
            $this->notify(
                'app_password_created',
                sprintf( 'Application Password created for %s', $login ),
                array(
                    'User'        => $login,
                    'Role'        => $user ? $this->primary_role( $user ) : '',
                    'Application' => $name,
                    'IP'          => $this->client_ip(),
                )
            );
        }

        /**
         * A WooCommerce REST API key (consumer key/secret) is being created
         * via WooCommerce → Settings → Advanced → REST API. WooCommerce fires
         * no action on creation, so this runs on its AJAX action at priority 9
         * (before WC's handler at 10). We only alert on the create path
         * (no key_id) and only when the request is authorized and complete,
         * mirroring WC's own validation. The consumer secret is never sent.
         */
        public function on_woo_api_key() {
            // Only a brand-new key (no key_id) is a new credential; >0 is an edit.
            $key_id = isset( $_POST['key_id'] ) ? absint( $_POST['key_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verified immediately below.
            if ( $key_id > 0 ) {
                return;
            }
            // Mirror WooCommerce's own gate so we don't alert on rejected requests.
            if ( ! check_ajax_referer( 'update-api-key', 'security', false ) || ! current_user_can( 'manage_woocommerce' ) ) {
                return;
            }
            if ( empty( $_POST['description'] ) || empty( $_POST['user'] ) || empty( $_POST['permissions'] ) ) {
                return;
            }

            $desc           = sanitize_text_field( wp_unslash( $_POST['description'] ) );
            $perm           = sanitize_text_field( wp_unslash( $_POST['permissions'] ) );
            $target_user_id = absint( $_POST['user'] );
            $target         = $target_user_id ? get_userdata( $target_user_id ) : null;

            $this->notify(
                'rest_key_generated',
                sprintf( 'WooCommerce REST API key created: %s', '' !== $desc ? $desc : '(no description)' ),
                array(
                    'Description' => $desc,
                    'Permissions' => $perm,
                    'For user'    => $target ? $target->user_login : ( '#' . $target_user_id ),
                    'Created by'  => $this->current_user_label(),
                    'IP'          => $this->client_ip(),
                )
            );
        }

        /**
         * Inspect the plugin-update transient and alert on available updates.
         * Two independent producers share this one hook:
         *
         *   watched_plugin_update  — KW Security or Wordfence, ANY version
         *                            delta, carrying the release notes so the
         *                            team can see what the update contains.
         *   plugin_update_critical — every OTHER plugin, but only when the
         *                            update is a security patch or a major
         *                            version jump.
         *
         * Watched plugins are excluded from the critical branch so a Wordfence
         * security release produces one alert, not two. Each branch keeps its
         * own persistent per-version set (keyed file@version) so a standing
         * update isn't re-alerted on every refresh; sharing one set would let
         * either branch suppress the other. That set is only ever pruned on
         * positive evidence — see prune_alerted_updates(), which explains why
         * absence from the transient being written proves nothing.
         *
         * @param object $transient The update_plugins site transient.
         */
        public function on_plugins_update_check( $transient ) {
            if ( ! self::get_webhook_url() ) {
                return;
            }
            if ( ! is_object( $transient ) || empty( $transient->response ) || ! is_array( $transient->response ) ) {
                return;
            }

            $this->check_watched_plugin_updates( $transient );

            // plugin_update_critical is Wordfence-sourced: when Wordfence is
            // active it relays vulnerable/outdated findings by email instead, so
            // native detection stands down to avoid double-alerting. This must
            // stay AFTER the watched-plugin check above — that category is never
            // Wordfence-sourced, because Wordfence will never email about an
            // update to KW Security itself.
            if ( $this->from_wordfence( 'plugin_update_critical' ) ) {
                return;
            }
            if ( ! self::is_category_enabled( 'plugin_update_critical' ) ) {
                return;
            }

            $checked = ( isset( $transient->checked ) && is_array( $transient->checked ) ) ? $transient->checked : array();
            $alerted = self::get_alerted_updates( self::OPTION_CRITICAL_UPDATES );
            $pruned  = $this->prune_alerted_updates( $alerted, $checked );
            $changed = ( $pruned !== $alerted );
            $alerted = $pruned;

            $to_send = array();

            $watched = $this->watched_plugins();

            foreach ( $transient->response as $file => $update ) {
                if ( empty( $update->new_version ) ) {
                    continue;
                }
                // Covered by watched_plugin_update above, in more detail.
                if ( in_array( $file, $watched, true ) ) {
                    continue;
                }
                $new_ver = (string) $update->new_version;
                $cur_ver = $this->installed_plugin_version( $file, $checked );
                $key     = $file . '@' . $new_ver;

                $is_major    = ( '' !== $cur_ver && $this->is_major_bump( $cur_ver, $new_ver ) );
                $is_security = ( ! empty( $update->upgrade_notice )
                    && preg_match( '/security|vulnerability|critical/i', wp_strip_all_tags( $update->upgrade_notice ) ) );

                if ( ! $is_major && ! $is_security ) {
                    continue;
                }
                if ( isset( $alerted[ $key ] ) ) {
                    continue;
                }

                $why    = $is_security ? ( $is_major ? 'security + major version' : 'security patch' ) : 'major version';
                $slug   = ( '.' !== dirname( $file ) ) ? dirname( $file ) : $file;
                $to_send[] = array( 'file' => $file, 'name' => $slug, 'cur' => $cur_ver, 'new' => $new_ver, 'why' => $why );

                $alerted[ $key ] = time();
                $changed         = true;
            }

            if ( $changed ) {
                self::save_alerted_updates( self::OPTION_CRITICAL_UPDATES, $alerted );
            }

            foreach ( $to_send as $a ) {
                $this->notify(
                    'plugin_update_critical',
                    sprintf( 'Critical plugin update: %s %s → %s (%s)', $a['name'], '' !== $a['cur'] ? $a['cur'] : '?', $a['new'], $a['why'] ),
                    array(
                        'Plugin'    => $a['file'],
                        'Installed' => '' !== $a['cur'] ? $a['cur'] : 'unknown',
                        'Available' => $a['new'],
                        'Reason'    => $a['why'],
                    )
                );
            }
        }

        /**
         * Alert on any available update to a watched security plugin (KW
         * Security or Wordfence), whatever the size of the version jump, with
         * an excerpt of the release notes so the team can see what the update
         * actually contains rather than just that a number changed.
         *
         * Deliberately NOT gated on from_wordfence(): Wordfence relays findings
         * about OTHER plugins, never about an update to KW Security itself, so
         * standing down here would silence the main case this exists for.
         *
         * @param object $transient The update_plugins site transient.
         */
        private function check_watched_plugin_updates( $transient ) {
            if ( ! self::is_category_enabled( 'watched_plugin_update' ) ) {
                return;
            }

            $watched = $this->watched_plugins();
            $checked = ( isset( $transient->checked ) && is_array( $transient->checked ) ) ? $transient->checked : array();

            $alerted = self::get_alerted_updates( self::OPTION_WATCHED_UPDATES );
            $pruned  = $this->prune_alerted_updates( $alerted, $checked );
            $changed = ( $pruned !== $alerted );
            $alerted = $pruned;

            $to_send = array();

            foreach ( $transient->response as $file => $update ) {
                if ( ! in_array( $file, $watched, true ) || empty( $update->new_version ) ) {
                    continue;
                }
                $new_ver = (string) $update->new_version;
                $cur_ver = $this->installed_plugin_version( $file, $checked );

                // Nothing to say when the "update" is the installed version.
                if ( '' !== $cur_ver && version_compare( $cur_ver, $new_ver, '>=' ) ) {
                    continue;
                }

                $key = $file . '@' . $new_ver;
                if ( isset( $alerted[ $key ] ) ) {
                    continue;
                }

                $to_send[] = array( 'file' => $file, 'cur' => $cur_ver, 'new' => $new_ver );
                $alerted[ $key ] = time();
                $changed         = true;
            }

            if ( $changed ) {
                self::save_alerted_updates( self::OPTION_WATCHED_UPDATES, $alerted );
            }

            foreach ( $to_send as $a ) {
                $name = $this->watched_plugin_label( $a['file'] );
                $this->notify(
                    'watched_plugin_update',
                    sprintf(
                        'Update available: %s %s → %s',
                        $name,
                        '' !== $a['cur'] ? $a['cur'] : '?',
                        $a['new']
                    ),
                    array_merge(
                        array(
                            'Plugin'    => $name,
                            'Installed' => '' !== $a['cur'] ? $a['cur'] : 'unknown',
                            'Available' => $a['new'],
                        ),
                        $this->fetch_release_notes( $a['file'], $a['new'] )
                    )
                );
            }
        }

        /**
         * Read a per-version "already alerted" set.
         *
         * update_plugins is a NETWORK-wide site transient, so on multisite the
         * hook fires on whichever site happens to serve the request while the
         * update itself is network-wide. Per-site options would therefore give
         * one alert per subsite for the same version; the set is kept network
         * wide to match the thing it is tracking.
         *
         * @param string $option Option name.
         * @return array<string,int> key => unix time first alerted.
         */
        private static function get_alerted_updates( $option ) {
            $alerted = is_multisite()
                ? get_site_option( $option, array() )
                : get_option( $option, array() );

            return is_array( $alerted ) ? $alerted : array();
        }

        /**
         * Persist a per-version "already alerted" set. Counterpart to
         * get_alerted_updates(); see there for the multisite reasoning.
         *
         * @param string             $option  Option name.
         * @param array<string,int>  $alerted Set to store.
         */
        private static function save_alerted_updates( $option, array $alerted ) {
            if ( is_multisite() ) {
                update_site_option( $option, $alerted );
                return;
            }
            update_option( $option, $alerted, false );
        }

        /**
         * Installed plugins, or null when they can't be read — so callers can
         * leave state alone rather than act on a guess.
         *
         * @return array<string,array>|null
         */
        private function installed_plugins() {
            if ( ! function_exists( 'get_plugins' ) ) {
                if ( ! defined( 'ABSPATH' ) || ! file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
                    return null;
                }
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            return function_exists( 'get_plugins' ) ? get_plugins() : null;
        }

        /**
         * Installed version of a plugin: the transient's own checked map when
         * it has one, else the plugin header on disk.
         *
         * The fallback matters because the transient written before an update
         * check carries whatever checked map was already stored — none at all
         * when the transient had just been flushed, which is what produced
         * "Installed: unknown" in the Slack alerts.
         *
         * @param string $file    Plugin file.
         * @param array  $checked The transient's checked map.
         * @return string Version, or '' when it can't be determined.
         */
        private function installed_plugin_version( $file, $checked ) {
            if ( is_array( $checked ) && isset( $checked[ $file ] ) ) {
                return (string) $checked[ $file ];
            }

            $plugins = $this->installed_plugins();
            if ( ! is_array( $plugins ) || empty( $plugins[ $file ]['Version'] ) ) {
                return '';
            }

            return (string) $plugins[ $file ]['Version'];
        }

        /**
         * Whether a plugin is still installed. Null when that can't be read.
         *
         * @param string $file Plugin file.
         * @return bool|null
         */
        private function plugin_is_installed( $file ) {
            $plugins = $this->installed_plugins();

            return is_array( $plugins ) ? isset( $plugins[ $file ] ) : null;
        }

        /**
         * Drop "already alerted" entries that have stopped being true.
         *
         * Absence from the transient currently being written is NOT evidence
         * of anything, which is why this doesn't look at it. WordPress writes
         * update_plugins twice per check: once with the value it just read
         * (filtered, so it carries entries injected by bundled updaters such
         * as this plugin's own PUC instance) and once with the wp.org response
         * alone (which never carries them). Purging on absence meant the
         * second write erased what the first had just recorded, and the next
         * check re-announced the same version — hourly, forever.
         *
         * An entry is dropped only on positive evidence: the update was
         * installed, the plugin is gone, or the entry is old enough that a
         * still-unapplied update is worth raising again.
         *
         * @param array<string,int> $alerted Current set.
         * @param array             $checked The transient's checked map.
         * @return array<string,int> Set with dead entries removed.
         */
        private function prune_alerted_updates( array $alerted, array $checked ) {
            $now  = time();
            $keep = array();

            foreach ( $alerted as $key => $when ) {
                $at = strrpos( (string) $key, '@' );
                if ( false === $at || ! is_numeric( $when ) ) {
                    continue; // Malformed — nothing worth preserving.
                }
                if ( ( $now - (int) $when ) > self::UPDATE_ALERT_TTL ) {
                    continue;
                }

                $file = substr( (string) $key, 0, $at );
                $ver  = substr( (string) $key, $at + 1 );

                // The update was applied.
                $installed = $this->installed_plugin_version( $file, $checked );
                if ( '' !== $installed && version_compare( $installed, $ver, '>=' ) ) {
                    continue;
                }
                // The plugin was removed outright.
                if ( false === $this->plugin_is_installed( $file ) ) {
                    continue;
                }

                $keep[ $key ] = (int) $when;
            }

            return $keep;
        }

        /**
         * Release notes for a watched plugin's new version, as Slack context
         * lines (label => text). Returns the two plain-language sections
         * separately where the source has them, so the alert reads as "What's
         * new" and "Why it matters" rather than one undifferentiated blob.
         *
         * Cached per file+version for 12 hours: the update transient refreshes
         * roughly twice a day and this must not re-fetch on every refresh.
         *
         * Never fatal — a failed lookup degrades to a short note rather than
         * dropping an update the team needs to know about.
         *
         * @param string $file    Plugin file.
         * @param string $version New version.
         * @return array<string,string>
         */
        private function fetch_release_notes( $file, $version ) {
            $cache_key = 'kw_slack_notes_' . md5( $file . '@' . $version );
            $cached    = get_transient( $cache_key );
            if ( is_array( $cached ) ) {
                return $cached;
            }

            if ( 'kw-security/kw-security.php' === $file ) {
                $sections = $this->fetch_own_release_notes( $version );
            } else {
                $sections = array( "What's new" => $this->fetch_wporg_changelog( $file, $version ) );
            }

            $sections = array_filter( array_map( function ( $text ) {
                return self::truncate( trim( (string) $text ), 700 );
            }, $sections ) );

            if ( ! $sections ) {
                $sections = array( "What's new" => 'Release notes unavailable — see the plugin page for details.' );
            }

            set_transient( $cache_key, $sections, 12 * HOUR_IN_SECONDS );
            return $sections;
        }

        /**
         * KW Security's own release notes, from the update server's info.json.
         *
         * Distinct from fetch_release_notes() above, which is the dispatcher
         * for any watched plugin; this is the branch it takes for KW Security
         * itself, where the notes come from our endpoint rather than wp.org.
         *
         * This used to read the GitHub Releases API, which worked only while
         * the repository was public. It is now the same document PUC reads for
         * update metadata, so the notes and the version on offer can never
         * disagree.
         *
         * The notes lead with the plain-language "What's new" / "Why it
         * matters" sections and keep the technical changelog in a collapsed
         * <details> block underneath; everything from that marker on is cut,
         * since the audience for this alert is the same non-technical audience
         * the summary was written for.
         *
         * @param string $version
         * @return array<string,string>
         */
        private function fetch_own_release_notes( $version ) {
            $url = apply_filters(
                'kw_slack_release_notes_url',
                KW_UPDATE_METADATA_URL,
                $version
            );

            $response = wp_remote_get( $url, array(
                'timeout' => 5,
                'headers' => array(
                    'Accept'     => 'application/json',
                    'User-Agent' => 'kw-security/' . KW_SECURITY_VERSION,
                ),
            ) );

            if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
                return array();
            }

            $data = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( ! is_array( $data ) ) {
                return array();
            }

            // info.json only ever describes the current release. If this alert
            // is for a different version — a site catching up from several
            // releases back, or a release published while this request was in
            // flight — the notes on hand describe someone else's release.
            // Sending nothing is better than sending the wrong changelog.
            if ( isset( $data['version'] ) && (string) $data['version'] !== (string) $version ) {
                return array();
            }

            // 'release_notes' is what the update server publishes. 'body' is
            // the shape the GitHub Releases API returned, kept so a site whose
            // filter still points at GitHub kept working.
            $body = '';
            foreach ( array( 'release_notes', 'body' ) as $key ) {
                if ( ! empty( $data[ $key ] ) ) {
                    $body = (string) $data[ $key ];
                    break;
                }
            }

            if ( '' === $body ) {
                return array();
            }

            // Cut the collapsed technical block and the footer.
            foreach ( array( '<details', "\n---" ) as $marker ) {
                $pos = strpos( $body, $marker );
                if ( false !== $pos ) {
                    $body = substr( $body, 0, $pos );
                }
            }

            // Split on the release body's own two headings, so each becomes its
            // own labelled line instead of the heading text surviving as prose
            // ("What's new: What's new ...").
            $sections = array();
            if ( preg_match( "/^#{1,6}\\s*What's new\\s*$(.*?)(?=^#{1,6}\\s|\\z)/ims", $body, $m ) ) {
                $sections["What's new"] = $this->tidy_notes( $m[1] );
            }
            if ( preg_match( "/^#{1,6}\\s*Why it matters\\s*$(.*?)(?=^#{1,6}\\s|\\z)/ims", $body, $m ) ) {
                $sections['Why it matters'] = $this->tidy_notes( $m[1] );
            }

            // Older releases (and the fallback body) have no such headings —
            // send the whole thing under one label rather than nothing.
            if ( ! $sections ) {
                $sections["What's new"] = $this->tidy_notes( $body );
            }

            return $sections;
        }

        /**
         * Changelog entry for a wordpress.org-hosted plugin (Wordfence), read
         * from the plugin-information API and narrowed to the section for the
         * new version where one can be identified.
         *
         * plugins_api() lives in an admin-only include, and this runs on the
         * update-check path — which fires on cron and front-end requests too,
         * where that file is not loaded. Hence the explicit require_once.
         *
         * @param string $file    Plugin file.
         * @param string $version New version.
         * @return string
         */
        private function fetch_wporg_changelog( $file, $version ) {
            if ( ! function_exists( 'plugins_api' ) ) {
                $include = ABSPATH . 'wp-admin/includes/plugin-install.php';
                if ( ! is_readable( $include ) ) {
                    return '';
                }
                require_once $include;
            }
            if ( ! function_exists( 'plugins_api' ) ) {
                return '';
            }

            $slug = ( '.' !== dirname( $file ) ) ? dirname( $file ) : $file;
            $info = plugins_api( 'plugin_information', array(
                'slug'   => $slug,
                'fields' => array( 'sections' => true, 'short_description' => false ),
            ) );

            if ( is_wp_error( $info ) || ! isset( $info->sections['changelog'] ) ) {
                return '';
            }

            $changelog = (string) $info->sections['changelog'];

            // Narrow to the heading for this version, up to the next heading, so
            // the alert shows what THIS update contains and not the whole file.
            if ( preg_match(
                '/<h\d[^>]*>[^<]*' . preg_quote( $version, '/' ) . '.*?<\/h\d>(.*?)(?=<h\d|$)/is',
                $changelog,
                $m
            ) ) {
                $changelog = $m[1];
            }

            return $this->tidy_notes( $changelog );
        }

        /**
         * Normalize release-note markup into the plain bulleted text the Slack
         * payload expects: list items become bullets, tags are stripped, and
         * runs of blank lines collapse.
         *
         * @param string $text
         * @return string
         */
        private function tidy_notes( $text ) {
            $text = preg_replace( '/<li[^>]*>/i', "\n• ", (string) $text );
            $text = preg_replace( '/<\/(p|div|h\d|ul|ol)>/i', "\n", $text );
            $text = wp_strip_all_tags( $text );
            $text = html_entity_decode( $text, ENT_QUOTES, 'UTF-8' );
            // Markdown headings and bullets read fine as-is, but normalize the
            // bullet marker so GitHub and wordpress.org notes look the same.
            $text = preg_replace( '/^[ \t]*[-*][ \t]+/m', '• ', $text );
            $text = preg_replace( '/^[ \t]*#{1,6}[ \t]*/m', '', $text );
            $text = preg_replace( '/[ \t]+/', ' ', $text );
            $text = preg_replace( '/\n{3,}/', "\n\n", $text );
            return trim( $text );
        }

        /**
         * Relay a Wordfence alert email to Slack. Hooked on the core wp_mail
         * filter, so it fires for any outgoing mail; it returns $atts
         * unchanged (never blocks the email) and only forwards mail that is
         * actually a Wordfence alert.
         *
         * Detection (defensive, no dependence on Wordfence internals): the
         * mail is addressed to one of Wordfence's own configured alert
         * recipients (wfConfig::get('alertEmails')) AND the subject/body
         * mentions Wordfence. Override via the kw_slack_is_wordfence_alert
         * filter for non-standard setups.
         *
         * @param array $atts wp_mail arguments (to, subject, message, …).
         * @return array Unchanged $atts.
         */
        public function on_wp_mail( $atts ) {
            if ( ! is_array( $atts ) || ! class_exists( 'wfConfig' ) ) {
                return $atts;
            }

            $subject = isset( $atts['subject'] ) ? (string) $atts['subject'] : '';
            $message = isset( $atts['message'] ) ? (string) $atts['message'] : '';
            $to      = isset( $atts['to'] ) ? $atts['to'] : '';
            $to_list = array_map( 'strtolower', array_filter( is_array( $to ) ? $to : preg_split( '/[,\s]+/', (string) $to ) ) );

            $alert_emails = wfConfig::get( 'alertEmails' );
            $wf_emails    = $alert_emails ? array_map( 'strtolower', array_filter( preg_split( '/[,\s]+/', $alert_emails ) ) ) : array();

            $looks_like_wf = ( false !== stripos( $subject, 'wordfence' ) ) || ( false !== stripos( $message, 'wordfence' ) );
            $to_wf         = (bool) array_intersect( $to_list, $wf_emails );

            /**
             * Final say on whether a wp_mail is a Wordfence alert to relay.
             *
             * @param bool  $is_alert
             * @param array $atts
             */
            if ( ! apply_filters( 'kw_slack_is_wordfence_alert', ( $looks_like_wf && $to_wf ), $atts ) ) {
                return $atts;
            }

            // Route scan-finding emails into their specific categories; fall
            // back to the generic wordfence_alert. Login/lockout emails are
            // skipped because those events are detected natively. Match on the
            // subject (Wordfence subjects are distinctive) to avoid misrouting
            // on incidental body wording.
            $hay     = strtolower( $subject );
            $routes  = (array) apply_filters( 'kw_slack_wordfence_email_routes', array(
                'malware'                => array( 'malware', 'infected', 'backdoor', 'trojan', 'malicious' ),
                'file_changed'           => array( 'file change', 'unknown file', 'modified', 'core file', 'contents have changed' ),
                // Strict: only genuinely security-relevant plugin states — a
                // known vulnerability, or a plugin pulled from the repository /
                // abandoned. Routine "update available / out of date" notices
                // are deliberately NOT here, so they fall through to the
                // critical-only filter below rather than paging as critical.
                'plugin_update_critical' => array( 'vulnerab', 'no longer available', 'abandoned', 'removed from' ),
            ) );

            $category = 'wordfence_alert';
            $matched  = false;
            foreach ( $routes as $cat => $keywords ) {
                foreach ( (array) $keywords as $kw ) {
                    if ( '' !== $kw && false !== strpos( $hay, strtolower( $kw ) ) ) {
                        $category = $cat;
                        $matched  = true;
                        break 2;
                    }
                }
            }
            if ( ! $matched ) {
                // Events KW already detects natively — skip the WF email so it
                // doesn't double up on our own alert. 'deactivat' covers the
                // Wordfence self-deactivation email, which we catch immediately
                // via the deactivated_plugin hook (wordfence_deactivated) and
                // which adds no extra coverage over the native signal.
                $realtime = (array) apply_filters( 'kw_slack_wordfence_email_skip', array( 'signed in', 'logged in', ' login', 'locked out', 'lockout', 'blocked', 'deactivat' ) );
                foreach ( $realtime as $kw ) {
                    if ( '' !== $kw && false !== strpos( $hay, strtolower( $kw ) ) ) {
                        return $atts; // detected natively — don't relay the WF email too.
                    }
                }

                // Critical-only mode: a Wordfence email that didn't route to a
                // specific critical category (malware, file change, vulnerable
                // plugin) is a status/low-signal notice. Drop it instead of
                // relaying under the generic wordfence_alert category.
                if ( self::is_wordfence_critical_only() ) {
                    return $atts;
                }
            }

            $snippet = trim( wp_strip_all_tags( $message ) );
            if ( strlen( $snippet ) > 600 ) {
                $snippet = substr( $snippet, 0, 600 ) . '…';
            }

            $this->notify(
                $category,
                '' !== $subject ? $subject : 'Wordfence alert',
                array(
                    // Marks this as relayed from Wordfence so a dual-sourced
                    // category (file_changed) reads as "Wordfence's full-tree
                    // scan" next to KW's immediate native root scan.
                    'Source'  => 'Wordfence scan',
                    'Details' => $snippet,
                )
            );

            return $atts;
        }

        // ----------------------------------------------------------------
        // Helpers
        // ----------------------------------------------------------------

        private function current_user_label() {
            $user = wp_get_current_user();
            if ( ! $user || ! $user->exists() ) {
                return 'system/guest';
            }
            return $user->user_email
                ? $user->user_login . ' (' . $user->user_email . ')'
                : $user->user_login;
        }

        private function client_ip() {
            $ip = isset( $_SERVER['REMOTE_ADDR'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
                : '';
            // Reuse the rate limiter's proxy filter so the real client IP is
            // detected consistently on sites behind Cloudflare / a load balancer.
            $ip = apply_filters( 'kw_security_client_ip', $ip );
            return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
        }

        /**
         * Whether a user is privileged enough to alert on. Defaults to the
         * administrator role (extend via the filter) plus, on multisite, any
         * network Super Admin regardless of their per-site role.
         *
         * @param WP_User $user
         * @return bool
         */
        private function is_privileged( $user ) {
            if ( ! ( $user instanceof WP_User ) ) {
                return false;
            }
            // On multisite, Super Admin is not a role — it lives in the
            // network's `site_admins` option. A super admin who is not an
            // explicit member of the site being acted on therefore has an
            // empty $user->roles, so a role-only check silently skips the
            // highest-privilege accounts on the install (they can sign in at
            // any site in the network). Resolve network status first.
            //
            // Deliberately not routed through kw_slack_alert_login_roles: a
            // list of role names cannot express "super admin", so filtering
            // it could never opt these accounts in. Use the
            // kw_slack_alert_send filter to drop specific alerts instead.
            if ( is_multisite() && is_super_admin( $user->ID ) ) {
                return true;
            }
            $roles = apply_filters( 'kw_slack_alert_login_roles', array( 'administrator' ) );
            foreach ( (array) $user->roles as $role ) {
                if ( in_array( $role, (array) $roles, true ) ) {
                    return true;
                }
            }
            return false;
        }

        private function primary_role( $user ) {
            if ( ! empty( $user->roles ) && is_array( $user->roles ) ) {
                // reset() rather than [0]: before WP 6.9, WP_User::get_role_caps()
                // built $roles with array_filter( array_keys( $caps ) ), which
                // preserves keys. A capability granted ahead of the role in the
                // capabilities meta therefore yields e.g. array( 1 =>
                // 'administrator' ), where [0] is an undefined index — a PHP 8
                // warning and a blank Role field on the alert.
                return reset( $user->roles );
            }
            // A multisite super admin holds no role on sites they are not a
            // member of, which would otherwise leave the alert's Role field
            // blank for the most privileged account on the network.
            if ( is_multisite() && $user instanceof WP_User && is_super_admin( $user->ID ) ) {
                return 'super-admin';
            }
            return '';
        }

        /**
         * Whether $new is a higher major version than $current (e.g. 1.9 → 2.0).
         *
         * @param string $current
         * @param string $new
         * @return bool
         */
        private function is_major_bump( $current, $new ) {
            $c = explode( '.', preg_replace( '/[^0-9.].*$/', '', $current ) );
            $n = explode( '.', preg_replace( '/[^0-9.].*$/', '', $new ) );
            $c_major = isset( $c[0] ) && '' !== $c[0] ? (int) $c[0] : 0;
            $n_major = isset( $n[0] ) && '' !== $n[0] ? (int) $n[0] : 0;
            return $n_major > $c_major;
        }

        /**
         * Whether this IP is new for the given user, recording it for next
         * time. The first IP ever seen for a user seeds the baseline silently
         * (returns false) so a fresh install doesn't fire on the first login.
         * An empty/invalid IP can't be classified, so it's never "new".
         *
         * @param int    $user_id
         * @param string $ip
         * @return bool
         */
        private function login_ip_is_new( $user_id, $ip ) {
            if ( ! $ip ) {
                return false;
            }
            $hash  = sha1( $ip . wp_salt() );
            $known = get_user_meta( $user_id, 'kw_login_known_ips', true );
            if ( ! is_array( $known ) ) {
                $known = array();
            }

            $first_time = empty( $known );
            $is_new     = ! in_array( $hash, $known, true );

            if ( $is_new ) {
                $known[] = $hash;
                if ( count( $known ) > 20 ) {
                    $known = array_slice( $known, -20 );
                }
                update_user_meta( $user_id, 'kw_login_known_ips', $known );
            }

            // Only flag as suspicious once a baseline exists.
            return $is_new && ! $first_time;
        }
    }

    if ( KW_Security_Settings::is_enabled( 'slack_alerts' ) ) {
        new KW_Security_Alerts();
    }
}
