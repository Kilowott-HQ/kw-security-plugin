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
        const OPTION_CATEGORIES = 'kw_slack_alert_categories';
        const OPTION_MENTION    = 'kw_slack_mention';
        const CONST_WEBHOOK     = 'KW_SLACK_WEBHOOK_URL';
        const ENV_WEBHOOK       = 'KW_SLACK_WEBHOOK_URL';
        const CONST_MENTION     = 'KW_SLACK_MENTION';
        const ENV_MENTION       = 'KW_SLACK_MENTION';
        const DEDUPE_WINDOW     = 300; // seconds — collapse identical alerts.
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
            add_action( 'update_option_' . KW_Security_Settings::OPTION_NAME, array( $this, 'on_features_changed' ), 10, 2 );

            // ── Plugin / credential / update signals ─────────────────────
            add_action( 'deactivated_plugin',             array( $this, 'on_plugin_deactivated' ), 10, 1 );
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
                'app_password_created' => __( 'Application Password created (REST/API credential)', 'kw-security' ),
                'rest_key_generated' => __( 'WooCommerce REST API key created (consumer key/secret)', 'kw-security' ),
                // ── Files / integrity ───────────────────────────────────
                'upload_blocked'     => __( 'Dangerous file upload blocked', 'kw-security' ),
                'file_changed'       => __( 'File integrity anomaly (unknown or modified core file)', 'kw-security' ),
                // ── Configuration / plugins / malware ───────────────────
                'security_disabled'  => __( 'A KW Security defense was switched off', 'kw-security' ),
                'wordfence_deactivated' => __( 'Wordfence plugin deactivated', 'kw-security' ),
                'plugin_update_critical' => __( 'Plugin update available — security patch or major version', 'kw-security' ),
                'wordfence_alert'    => __( 'Relay Wordfence alerts (mirrors Wordfence email alerts to Slack)', 'kw-security' ),
                'malware'            => __( 'Malware detected', 'kw-security' ),
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
         * Categories whose detection is delegated to Wordfence (relayed via
         * its security-event action or scan emails) rather than detected
         * natively. Native handlers for these short-circuit so there is no
         * double-alerting. Filterable so a site without Wordfence — or one
         * that prefers native detection — can reclaim any of them.
         *
         * @return array<int,string>
         */
        public static function get_wordfence_sourced() {
            // Only Wordfence *scan* findings are relayed (via alert emails),
            // because those are reliable across versions. Login/lockout/block
            // detection stays native — it does not depend on Wordfence-internal
            // event names that change between releases.
            return (array) apply_filters( 'kw_slack_wordfence_sourced', array(
                'file_changed',
                'plugin_update_critical',
                'malware',
            ) );
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
            if ( $this->from_wordfence( 'file_changed' ) ) {
                return; // Relayed from Wordfence scan emails instead.
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

        public function on_delete_user( $user_id ) {
            $user = get_userdata( $user_id );
            if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
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
         * A plugin was deactivated. Alerts only for watched security plugins
         * (Wordfence by default; extend via the filter).
         *
         * @param string $plugin Plugin file, e.g. 'wordfence/wordfence.php'.
         */
        public function on_plugin_deactivated( $plugin ) {
            $watch = apply_filters( 'kw_slack_alert_watch_plugins', array( 'wordfence/wordfence.php' ) );
            if ( ! in_array( $plugin, (array) $watch, true ) ) {
                return;
            }
            $this->notify(
                'wordfence_deactivated',
                sprintf( 'Security plugin deactivated: %s', $plugin ),
                array(
                    'Plugin'         => $plugin,
                    'Deactivated by' => $this->current_user_label(),
                    'IP'             => $this->client_ip(),
                )
            );
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
         * Inspect the plugin-update transient and alert on plugins whose
         * available update is a security patch or a major-version jump.
         * A persistent set (kw_slack_alerted_updates) keyed by file@version
         * prevents re-alerting the same standing update on every refresh.
         *
         * @param object $transient The update_plugins site transient.
         */
        public function on_plugins_update_check( $transient ) {
            if ( $this->from_wordfence( 'plugin_update_critical' ) ) {
                return; // Relayed from Wordfence scan emails instead.
            }
            if ( ! self::is_category_enabled( 'plugin_update_critical' ) || ! self::get_webhook_url() ) {
                return;
            }
            if ( ! is_object( $transient ) || empty( $transient->response ) || ! is_array( $transient->response ) ) {
                return;
            }

            $checked = ( isset( $transient->checked ) && is_array( $transient->checked ) ) ? $transient->checked : array();
            $alerted = get_option( 'kw_slack_alerted_updates', array() );
            if ( ! is_array( $alerted ) ) {
                $alerted = array();
            }

            $relevant   = array();
            $to_send    = array();
            $changed    = false;

            foreach ( $transient->response as $file => $update ) {
                if ( empty( $update->new_version ) ) {
                    continue;
                }
                $new_ver = (string) $update->new_version;
                $cur_ver = isset( $checked[ $file ] ) ? (string) $checked[ $file ] : '';
                $key     = $file . '@' . $new_ver;
                $relevant[ $key ] = true;

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

            // Drop entries no longer offered (plugin updated or removed).
            foreach ( array_keys( $alerted ) as $k ) {
                if ( ! isset( $relevant[ $k ] ) ) {
                    unset( $alerted[ $k ] );
                    $changed = true;
                }
            }
            if ( $changed ) {
                update_option( 'kw_slack_alerted_updates', $alerted, false );
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
                'plugin_update_critical' => array( 'out of date', 'vulnerab', 'no longer available', 'abandoned', 'update is available', 'needs an update' ),
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
                $realtime = (array) apply_filters( 'kw_slack_wordfence_email_skip', array( 'signed in', 'logged in', ' login', 'locked out', 'lockout', 'blocked' ) );
                foreach ( $realtime as $kw ) {
                    if ( '' !== $kw && false !== strpos( $hay, strtolower( $kw ) ) ) {
                        return $atts; // login/lockout detected natively — don't relay the WF email too.
                    }
                }
            }

            $snippet = trim( wp_strip_all_tags( $message ) );
            if ( strlen( $snippet ) > 600 ) {
                $snippet = substr( $snippet, 0, 600 ) . '…';
            }

            $this->notify(
                $category,
                '' !== $subject ? $subject : 'Wordfence alert',
                array( 'Details' => $snippet )
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
         * Whether a user holds a role we treat as privileged for login
         * alerts. Defaults to administrator; extend via the filter.
         *
         * @param WP_User $user
         * @return bool
         */
        private function is_privileged( $user ) {
            $roles = apply_filters( 'kw_slack_alert_login_roles', array( 'administrator' ) );
            foreach ( (array) $user->roles as $role ) {
                if ( in_array( $role, (array) $roles, true ) ) {
                    return true;
                }
            }
            return false;
        }

        private function primary_role( $user ) {
            return ( ! empty( $user->roles ) && is_array( $user->roles ) ) ? $user->roles[0] : '';
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
