<?php
/**
 * KW Security – File Integrity Monitor
 *
 * Daily WP-Cron scan of the WordPress root directory for unknown PHP
 * files and modifications to critical files (index.php, wp-config.php).
 * Sends an email alert to the site admin when anything anomalous is
 * found.
 *
 * This module addresses the specific failure mode in the Preikestolen
 * Basecamp RCA (24 April 2026): malware injection into the root
 * index.php and unfamiliar PHP files appearing alongside core WordPress
 * files. Wordfence missed both — file-level baseline checking catches
 * exactly that class of attack.
 *
 * Scope is intentionally narrow — only ABSPATH (top-level, not
 * recursive) is monitored. Scanning all of wp-content would generate
 * false positives on every plugin update; deep monitoring of that kind
 * belongs in a dedicated tool.
 *
 * On WordPress core update the baseline is automatically reset (via
 * _core_updated_successfully) since index.php legitimately changes.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_File_Integrity' ) ) {

    class KW_File_Integrity {

        const CRON_HOOK     = 'kw_security_file_integrity_scan';
        const OPTION_HASHES = 'kw_security_file_hashes';
        const OPTION_LAST   = 'kw_security_file_last_scan';

        /**
         * Option holding the comma-separated list of email recipients for
         * integrity-alert mail. When empty, no email is sent (the
         * kw_file_integrity_anomaly do_action still fires for Slack listeners).
         */
        const OPTION_RECIPIENTS = 'kw_file_integrity_recipients';

        /**
         * Stores the *normalized* baseline content for files where we strip
         * volatile lines before hashing (currently just wp-config.php). Lets
         * us diff against the previous content and show what actually changed.
         *
         * @var string
         */
        const OPTION_BASELINE_CONTENT = 'kw_security_file_baseline_content';

        /**
         * Files for which volatile-constant normalization applies BEFORE
         * hashing. wp-config.php legitimately churns whenever someone toggles
         * WP_DEBUG, a managed host injects a cache constant, etc. — so we
         * hash the normalized version. index.php is intentionally NOT in this
         * list: it should be invariant outside WP core updates.
         */
        const NORMALIZED_FILES = array(
            'wp-config.php',
        );

        /**
         * Schema version of the baseline format. Incremented when the way
         * hashes are computed changes, so existing sites can migrate their
         * stored baseline on first load after upgrade.
         *
         *   1 = whole-file SHA1 of every tracked file.
         *   2 = normalized SHA1 for NORMALIZED_FILES (wp-config.php),
         *       whole-file SHA1 for the rest.
         */
        const BASELINE_SCHEMA        = 2;
        const OPTION_BASELINE_SCHEMA = 'kw_security_file_baseline_schema';

        /**
         * Autonomous scan cadence, stored as a WP-Cron schedule name so it can
         * be handed straight to wp_schedule_event(). Whitelisted set: the
         * custom CRON_SCHEDULE_15MIN (registered via register_cron_schedule)
         * plus the WP built-ins 'hourly' and 'daily'. Configurable from the
         * settings page; see get_allowed_intervals() / get_scan_schedule().
         */
        const OPTION_SCAN_INTERVAL = 'kw_security_file_scan_interval';
        const CRON_SCHEDULE_15MIN  = 'kw_15min';

        /**
         * Per-finding alert state: the fingerprint of the last-alerted anomaly
         * set plus the timestamp it was alerted. Lets us alert once per
         * distinct finding set and re-alert only when it changes or a daily
         * reminder is due — so a tight scan cadence (e.g. every 15 minutes)
         * doesn't ping the channel on every run for the same unresolved issue.
         *
         * @var array{fingerprint:string, last_alert:int}
         */
        const OPTION_ALERT_STATE = 'kw_security_file_alert_state';

        /**
         * Files expected to live in the WordPress root. Anything else
         * with a code-like extension is treated as suspicious.
         */
        const KNOWN_ROOT_FILES = array(
            'index.php',
            'wp-config.php',
            'wp-config-sample.php',
            'wp-load.php',
            'wp-blog-header.php',
            'wp-cron.php',
            'wp-mail.php',
            'wp-trackback.php',
            'wp-comments-post.php',
            'wp-links-opml.php',
            'wp-login.php',
            'wp-signup.php',
            'wp-activate.php',
            'wp-settings.php',
            'xmlrpc.php',
            '.htaccess',
            '.htpasswd',
            'license.txt',
            'readme.html',
            'robots.txt',
            'favicon.ico',
        );

        /**
         * Files whose hash is tracked across scans. Modifications here
         * are the highest-signal indicator of injection — index.php is
         * the exact file that was injected in the basecamp RCA.
         */
        const HASHED_FILES = array(
            'index.php',
            'wp-config.php',
        );

        /**
         * File extensions considered executable / suspicious if found
         * in the WP root outside the known files list.
         */
        const SUSPICIOUS_EXTENSIONS = array(
            'php', 'phtml', 'phar', 'phps', 'php3', 'php4', 'php5',
            'html', 'htm',
        );

        public function __construct() {
            add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );

            // Register the custom 15-minute interval so wp_schedule_event can
            // use it. Must be added before ensure_scan_scheduled() runs.
            add_filter( 'cron_schedules', array( $this, 'register_cron_schedule' ) );

            // Schedule the scan at the configured cadence, and reschedule when
            // the admin changes the interval (stored schedule no longer matches)
            // or when it was never scheduled (feature just toggled on).
            $this->ensure_scan_scheduled();

            // Auto-reset baseline after a WP core update (index.php legitimately changes).
            add_action( '_core_updated_successfully', array( $this, 'reset_baseline_silent' ) );

            // Migrate stale baselines from older schemas (e.g. whole-file
            // wp-config hash → normalized hash). Fires on admin requests only
            // so frontend visitors don't pay the one-time scan cost.
            add_action( 'admin_init', array( $this, 'maybe_migrate_baseline' ) );

            // Manual scan + reset triggers from the settings page.
            add_action( 'admin_post_kw_security_run_scan',         array( $this, 'handle_manual_scan' ) );
            add_action( 'admin_post_kw_security_reset_baseline',   array( $this, 'handle_reset_baseline' ) );
        }

        /**
         * Register the custom 15-minute cron interval used when the admin
         * selects the fastest scan cadence.
         *
         * @param array<string,array{interval:int,display:string}> $schedules
         * @return array<string,array{interval:int,display:string}>
         */
        public function register_cron_schedule( $schedules ) {
            if ( ! isset( $schedules[ self::CRON_SCHEDULE_15MIN ] ) ) {
                $schedules[ self::CRON_SCHEDULE_15MIN ] = array(
                    'interval' => 15 * MINUTE_IN_SECONDS,
                    'display'  => __( 'Every 15 Minutes (KW Security)', 'kw-security' ),
                );
            }
            return $schedules;
        }

        /**
         * WP-Cron schedule names the scan may use. Anything outside this set
         * (e.g. a stale/hand-edited option) falls back to the 15-minute default.
         *
         * @return array<int,string>
         */
        public static function get_allowed_intervals() {
            return array( self::CRON_SCHEDULE_15MIN, 'hourly', 'daily' );
        }

        /**
         * The configured scan schedule name, validated against the whitelist.
         *
         * @return string
         */
        public function get_scan_schedule() {
            $stored = (string) get_option( self::OPTION_SCAN_INTERVAL, self::CRON_SCHEDULE_15MIN );
            return in_array( $stored, self::get_allowed_intervals(), true )
                ? $stored
                : self::CRON_SCHEDULE_15MIN;
        }

        /**
         * Ensure the scan is scheduled at the configured cadence. Idempotent:
         * a no-op when the existing schedule already matches, otherwise clears
         * and reschedules — which is how an interval change from the settings
         * page takes effect on the next request.
         */
        public function ensure_scan_scheduled() {
            $desired = $this->get_scan_schedule();
            if ( wp_get_schedule( self::CRON_HOOK ) === $desired ) {
                return;
            }
            wp_clear_scheduled_hook( self::CRON_HOOK );
            wp_schedule_event( time() + MINUTE_IN_SECONDS, $desired, self::CRON_HOOK );
        }

        /**
         * One-time baseline migration when the schema version stored in
         * the database is older than the current code's BASELINE_SCHEMA.
         *
         * For schema 1 → 2 (this release): the wp-config.php baseline was a
         * whole-file SHA1 and now is a normalized SHA1, so any existing
         * baseline produces a permanent mismatch — flagging wp-config.php
         * as modified on every scan with an empty diff. We drop the stale
         * wp-config baseline (hash AND content cache) and re-seed it from
         * current state via a silent scan.
         *
         * index.php's baseline is deliberately preserved: it was always
         * whole-file hashed and stays so. If index.php is being concurrently
         * tampered with at upgrade time, this migration must not bless it.
         */
        public function maybe_migrate_baseline() {
            $stored = (int) get_option( self::OPTION_BASELINE_SCHEMA, 1 );
            if ( $stored >= self::BASELINE_SCHEMA ) {
                return;
            }

            $hashes  = get_option( self::OPTION_HASHES, array() );
            $content = get_option( self::OPTION_BASELINE_CONTENT, array() );
            if ( ! is_array( $hashes ) ) {
                $hashes = array();
            }
            if ( ! is_array( $content ) ) {
                $content = array();
            }

            // Drop only the baselines for files whose hashing rule changed
            // in this schema bump. Everything else stays put.
            foreach ( self::NORMALIZED_FILES as $relative ) {
                unset( $hashes[ $relative ] );
                unset( $content[ $relative ] );
            }

            update_option( self::OPTION_HASHES, $hashes, false );
            update_option( self::OPTION_BASELINE_CONTENT, $content, false );
            update_option( self::OPTION_BASELINE_SCHEMA, self::BASELINE_SCHEMA, false );

            // Silent scan re-seeds the missing entries with the new
            // normalized hash + content, without firing an alert.
            $this->run_scan( true );
        }

        /**
         * Called from KW_Security::plugin_deactivation to clean up cron.
         */
        public static function deactivation() {
            wp_clear_scheduled_hook( self::CRON_HOOK );
        }

        /**
         * Run a scan. Returns the list of anomalies and emails the admin
         * if any are found (unless $silent is true).
         *
         * @param bool $silent Suppress alert email (used when seeding baseline).
         * @return array{unknown:array<string>, modified:array<string>, changes:array<string,mixed>, alerted:bool}
         */
        public function run_scan( $silent = false ) {
            $unknown        = $this->find_unknown_files();
            $current_hashes = $this->compute_current_hashes();
            $baseline       = get_option( self::OPTION_HASHES, array() );

            if ( ! is_array( $baseline ) ) {
                $baseline = array();
            }

            $baseline_content = get_option( self::OPTION_BASELINE_CONTENT, array() );
            if ( ! is_array( $baseline_content ) ) {
                $baseline_content = array();
            }

            // Detect modifications — only flag files that exist in baseline
            // AND have changed. For normalized files we also compute a
            // line-level diff so the alert can name what actually changed.
            $modified = array();
            $changes  = array();
            foreach ( $current_hashes as $file => $hash ) {
                if ( isset( $baseline[ $file ] ) && $baseline[ $file ] !== $hash ) {
                    $modified[] = $file;

                    if (
                        in_array( $file, self::NORMALIZED_FILES, true )
                        && isset( $baseline_content[ $file ] )
                    ) {
                        $current_content = $this->read_normalized_content( $file );
                        if ( null !== $current_content ) {
                            $changes[ $file ] = $this->diff_normalized(
                                (string) $baseline_content[ $file ],
                                $current_content
                            );
                        }
                    }
                }
            }

            // Add any newly-tracked files to baseline (no false positive
            // on first sighting). Modified files keep their original hash
            // so the alert keeps firing until admin resets the baseline.
            foreach ( $current_hashes as $file => $hash ) {
                if ( ! isset( $baseline[ $file ] ) ) {
                    $baseline[ $file ] = $hash;
                }
            }
            // Same first-sighting rule for normalized baseline content — only
            // seed the content cache when there's no entry yet, so the diff
            // on next modification can compare against the original.
            foreach ( self::NORMALIZED_FILES as $relative ) {
                if ( ! isset( $baseline_content[ $relative ] ) && isset( $current_hashes[ $relative ] ) ) {
                    $content = $this->read_normalized_content( $relative );
                    if ( null !== $content ) {
                        $baseline_content[ $relative ] = $content;
                    }
                }
            }

            update_option( self::OPTION_HASHES, $baseline, false );
            update_option( self::OPTION_BASELINE_CONTENT, $baseline_content, false );
            update_option( self::OPTION_LAST, time(), false );

            // Silent scans (baseline seeding/migration) never alert and never
            // touch the alert-dedupe state. Real scans dispatch through the
            // "alert once until it changes or a reminder is due" gate.
            $alerted = $silent
                ? false
                : $this->maybe_dispatch_alert( $unknown, $modified, $changes, $current_hashes );

            return array(
                'unknown'  => $unknown,
                'modified' => $modified,
                'changes'  => $changes,
                'alerted'  => $alerted,
            );
        }

        /**
         * Send the email + Slack alert for a finding set, but only when it is
         * new, has changed since the last alert, or a daily reminder is due.
         * This keeps a tight scan cadence (e.g. every 15 minutes) from
         * re-alerting on every run for the same unresolved anomaly.
         *
         * The current hashes of modified files are folded into the fingerprint
         * so a *further* change to an already-flagged file counts as new and
         * re-alerts immediately rather than waiting for the daily reminder.
         *
         * @param array<string>        $unknown
         * @param array<string>        $modified
         * @param array<string,mixed>  $changes
         * @param array<string,string> $current_hashes
         * @return bool Whether an alert was dispatched.
         */
        private function maybe_dispatch_alert( $unknown, $modified, $changes, $current_hashes ) {
            $has_findings = ! empty( $unknown ) || ! empty( $modified );

            if ( ! $has_findings ) {
                // Resolved — forget prior state so a recurrence alerts at once.
                if ( false !== get_option( self::OPTION_ALERT_STATE, false ) ) {
                    delete_option( self::OPTION_ALERT_STATE );
                }
                return false;
            }

            $fingerprint = $this->finding_fingerprint( $unknown, $modified, $current_hashes );
            $state       = get_option( self::OPTION_ALERT_STATE, array() );
            if ( ! is_array( $state ) ) {
                $state = array();
            }
            $last     = isset( $state['fingerprint'] ) ? (string) $state['fingerprint'] : '';
            $last_ts  = isset( $state['last_alert'] ) ? (int) $state['last_alert'] : 0;
            $now      = time();

            /**
             * How long an unchanged finding stays quiet before a reminder
             * re-fires. Default one day. Return 0 to disable reminders entirely
             * (alert only when the finding set changes).
             *
             * @param int $seconds
             */
            $reminder     = (int) apply_filters( 'kw_file_integrity_reminder_interval', DAY_IN_SECONDS );
            $changed      = ( $fingerprint !== $last );
            $reminder_due = ( $reminder > 0 && ( $now - $last_ts ) >= $reminder );

            if ( ! $changed && ! $reminder_due ) {
                return false; // Same finding, reminder not due — stay silent.
            }

            $this->send_alert( $unknown, $modified, $changes );

            // Notify listeners (e.g. Slack alerts) of the same anomalies.
            // Third arg is optional — existing 2-arg listeners ignore it.
            do_action( 'kw_file_integrity_anomaly', $unknown, $modified, $changes );

            update_option( self::OPTION_ALERT_STATE, array(
                'fingerprint' => $fingerprint,
                'last_alert'  => $now,
            ), false );

            return true;
        }

        /**
         * Stable fingerprint of a finding set: sorted unknown filenames plus
         * each modified file keyed to its current hash. Two scans that surface
         * the same anomalies in the same state produce the same fingerprint.
         *
         * @param array<string>        $unknown
         * @param array<string>        $modified
         * @param array<string,string> $current_hashes
         * @return string
         */
        private function finding_fingerprint( $unknown, $modified, $current_hashes ) {
            sort( $unknown );
            $mod = array();
            foreach ( $modified as $file ) {
                $mod[ $file ] = isset( $current_hashes[ $file ] ) ? $current_hashes[ $file ] : '';
            }
            ksort( $mod );
            return sha1( (string) wp_json_encode( array(
                'unknown'  => array_values( $unknown ),
                'modified' => $mod,
            ) ) );
        }

        /**
         * Reset baseline after a known-good event (e.g. WP core update).
         */
        public function reset_baseline_silent() {
            delete_option( self::OPTION_HASHES );
            delete_option( self::OPTION_BASELINE_CONTENT );
            // Clear alert-dedupe state: current state is the new "known good",
            // so any prior finding is considered acknowledged/resolved.
            delete_option( self::OPTION_ALERT_STATE );
            $this->run_scan( true );
        }

        /**
         * Scan ABSPATH (non-recursive) for unknown executable files.
         *
         * @return array<string>
         */
        private function find_unknown_files() {
            $unknown = array();

            $entries = @scandir( ABSPATH );
            if ( ! is_array( $entries ) ) {
                return $unknown;
            }

            foreach ( $entries as $name ) {
                if ( '.' === $name || '..' === $name ) {
                    continue;
                }
                $full = ABSPATH . $name;

                // Only files (skip wp-admin/, wp-content/, wp-includes/).
                if ( ! is_file( $full ) ) {
                    continue;
                }

                if ( in_array( $name, self::KNOWN_ROOT_FILES, true ) ) {
                    continue;
                }

                $ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, self::SUSPICIOUS_EXTENSIONS, true ) ) {
                    $unknown[] = $name;
                }
            }

            return $unknown;
        }

        /**
         * Volatile constants whose define() lines are stripped from
         * wp-config.php before hashing — they legitimately change for
         * non-malicious reasons (debug toggles, host-injected cache flags,
         * memory tweaks). DB credentials, salts, table prefix, and site URLs
         * are deliberately NOT in this list because a change to those IS a
         * malware indicator.
         *
         * Sites with host-specific volatile constants (Kinsta, WP Engine,
         * Pantheon, etc.) can extend the list via the
         * `kw_file_integrity_volatile_constants` filter.
         *
         * @return string[]
         */
        private function get_volatile_constants() {
            return (array) apply_filters(
                'kw_file_integrity_volatile_constants',
                array(
                    // Debug toggles
                    'WP_DEBUG',
                    'WP_DEBUG_LOG',
                    'WP_DEBUG_DISPLAY',
                    'SCRIPT_DEBUG',
                    'WP_DISABLE_FATAL_ERROR_HANDLER',
                    // Cache
                    'WP_CACHE',
                    'CONCATENATE_SCRIPTS',
                    'COMPRESS_SCRIPTS',
                    'COMPRESS_CSS',
                    // Memory / performance
                    'WP_MEMORY_LIMIT',
                    'WP_MAX_MEMORY_LIMIT',
                    'WP_POST_REVISIONS',
                    'AUTOSAVE_INTERVAL',
                    'EMPTY_TRASH_DAYS',
                    'MEDIA_TRASH',
                    // Updates
                    'WP_AUTO_UPDATE_CORE',
                    'AUTOMATIC_UPDATER_DISABLED',
                    // Filesystem method (host may flip between direct/ssh2/ftp)
                    'FS_METHOD',
                    'FS_CHMOD_DIR',
                    'FS_CHMOD_FILE',
                    // Editor lockdown
                    'DISALLOW_FILE_EDIT',
                    'DISALLOW_FILE_MODS',
                    'DISALLOW_UNFILTERED_HTML',
                )
            );
        }

        /**
         * Strip define()-style lines for any of the volatile constants from
         * wp-config content, then collapse consecutive blank lines so the
         * hash is deterministic. Single-line defines only — multi-line
         * defines are rare; if they trip a false positive a site can add
         * their constant via the filter and re-baseline.
         *
         * Also tolerates an optional trailing line comment so e.g.
         * `define('WP_DEBUG', true); // dev only` is stripped as a unit.
         *
         * @param string $content Raw file content.
         * @return string Normalized content.
         */
        private function normalize_wp_config( $content ) {
            $names = $this->get_volatile_constants();
            if ( empty( $names ) ) {
                return $content;
            }
            $alt     = implode( '|', array_map( 'preg_quote', $names ) );
            $pattern = '/^[ \t]*define\s*\(\s*[\'"](?:' . $alt . ')[\'"][^)]*\)\s*;?[ \t]*(?:\/\/.*|#.*)?\s*\r?\n/m';

            $normalized = preg_replace( $pattern, '', $content );
            if ( null === $normalized ) {
                // Regex failure (shouldn't happen) — fall back to raw content.
                return $content;
            }
            // Collapse runs of blank lines so removing a volatile line doesn't
            // shift the rest of the content visually for the diff.
            $normalized = preg_replace( "/(\r?\n){2,}/", "\n", $normalized );
            return $normalized;
        }

        /**
         * Read a tracked file and return its content (normalized when the
         * file is in NORMALIZED_FILES). Returns null on read failure.
         *
         * @param string $relative Path relative to ABSPATH.
         * @return string|null
         */
        private function read_normalized_content( $relative ) {
            $full = ABSPATH . $relative;
            if ( ! file_exists( $full ) || ! is_readable( $full ) ) {
                return null;
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read for hashing; WP_Filesystem requires FS credentials and is unsuitable for cron-scheduled scans.
            $content = file_get_contents( $full );
            if ( false === $content ) {
                return null;
            }
            if ( in_array( $relative, self::NORMALIZED_FILES, true ) ) {
                return $this->normalize_wp_config( $content );
            }
            return $content;
        }

        /**
         * Compute current sha1 hashes of tracked files. Files in
         * NORMALIZED_FILES are hashed after volatile-constant normalization
         * so e.g. flipping WP_DEBUG doesn't fire a daily alert.
         *
         * @return array<string,string>
         */
        private function compute_current_hashes() {
            $hashes = array();
            foreach ( self::HASHED_FILES as $relative ) {
                if ( in_array( $relative, self::NORMALIZED_FILES, true ) ) {
                    $content = $this->read_normalized_content( $relative );
                    if ( null !== $content ) {
                        $hashes[ $relative ] = sha1( $content );
                    }
                    continue;
                }
                // Plain whole-file hash for non-normalized files (index.php).
                $full = ABSPATH . $relative;
                if ( file_exists( $full ) && is_readable( $full ) ) {
                    // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- file_exists/is_readable already guard; @ catches race-condition warnings if the file disappears between checks.
                    $hash = @sha1_file( $full );
                    if ( false !== $hash ) {
                        $hashes[ $relative ] = $hash;
                    }
                }
            }
            return $hashes;
        }

        /**
         * Diff two normalized file contents and return a compact summary
         * of added/removed lines (max 10 of each). Lines existing in both
         * but reordered count as added+removed; that's fine for an alert
         * preview where the goal is "did something suspicious slip in?".
         *
         * @param string $before
         * @param string $after
         * @return array{added: array<string>, removed: array<string>}
         */
        private function diff_normalized( $before, $after ) {
            $before_lines = array_map( 'trim', preg_split( "/\r?\n/", (string) $before ) );
            $after_lines  = array_map( 'trim', preg_split( "/\r?\n/", (string) $after ) );

            // Drop empty lines from comparison — they're noise, not signal.
            $before_lines = array_values( array_filter( $before_lines, 'strlen' ) );
            $after_lines  = array_values( array_filter( $after_lines, 'strlen' ) );

            $added   = array_values( array_diff( $after_lines, $before_lines ) );
            $removed = array_values( array_diff( $before_lines, $after_lines ) );

            return array(
                'added'   => array_slice( $added, 0, 10 ),
                'removed' => array_slice( $removed, 0, 10 ),
            );
        }

        /**
         * Parse the configured recipient option into a list of valid email
         * addresses. Returns an empty array when no recipients are configured
         * — in that case no email is sent (the kw_file_integrity_anomaly
         * action still fires for Slack listeners).
         *
         * @return string[]
         */
        private function get_recipients() {
            $raw = (string) get_option( self::OPTION_RECIPIENTS, '' );
            if ( '' === $raw ) {
                return array();
            }
            $parts = preg_split( '/[\s,;]+/', $raw );
            $clean = array();
            foreach ( (array) $parts as $email ) {
                $email = sanitize_email( trim( $email ) );
                if ( $email && is_email( $email ) ) {
                    $clean[] = $email;
                }
            }
            return array_values( array_unique( $clean ) );
        }

        /**
         * Send anomaly alert email to the configured recipients. Returns
         * silently when no recipients are configured — by design, so a fresh
         * install doesn't spam admin_email until someone fills the field.
         *
         * @param array<string>                                                  $unknown
         * @param array<string>                                                  $modified
         * @param array<string,array{added:array<string>,removed:array<string>}> $changes  Per-file line diff, normalized files only.
         */
        private function send_alert( $unknown, $modified, $changes = array() ) {
            $recipients = $this->get_recipients();
            if ( empty( $recipients ) ) {
                return; // No recipients configured — Slack/webhook listeners still receive the do_action.
            }

            $site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
            $subject = sprintf( '[KW Security] File integrity alert: %s', $site );

            $body  = "KW Security detected potential anomalies in the WordPress root directory.\n\n";
            $body .= 'Site: ' . home_url() . "\n";
            $body .= 'Scan time: ' . date_i18n( 'Y-m-d H:i:s' ) . "\n\n";

            if ( ! empty( $unknown ) ) {
                $body .= "Unknown files in root directory (not part of WordPress core):\n";
                foreach ( $unknown as $file ) {
                    $body .= '  - ' . $file . "\n";
                }
                $body .= "\nThese files appeared in the WP root and may be malicious. ";
                $body .= "Review each file via FTP/SSH and remove anything you didn't deploy.\n\n";
            }

            if ( ! empty( $modified ) ) {
                $body .= "Modified core files (hash changed since baseline):\n";
                foreach ( $modified as $file ) {
                    $body .= '  - ' . $file . "\n";

                    // Include the line-level diff if we have one (currently
                    // wp-config.php only). Helps the recipient verify in
                    // seconds whether the change looks like malware or a
                    // legitimate host/admin tweak.
                    if ( isset( $changes[ $file ] ) ) {
                        $diff = $changes[ $file ];
                        if ( ! empty( $diff['added'] ) ) {
                            $body .= "      Added lines:\n";
                            foreach ( $diff['added'] as $line ) {
                                $body .= '        + ' . $line . "\n";
                            }
                        }
                        if ( ! empty( $diff['removed'] ) ) {
                            $body .= "      Removed lines:\n";
                            foreach ( $diff['removed'] as $line ) {
                                $body .= '        - ' . $line . "\n";
                            }
                        }
                    }
                }
                $body .= "\nThese files have been modified since the baseline was set. ";
                $body .= "If you did not change them, restore from backup or compare against a clean WordPress install.\n";
                $body .= "If the change is legitimate (e.g. a host-injected constant), add it to the\n";
                $body .= "kw_file_integrity_volatile_constants filter and reset the baseline from Settings.\n\n";
            }

            $body .= 'Manage scan results: ' . admin_url( 'options-general.php?page=kw-security' ) . "\n";

            wp_mail( $recipients, $subject, $body );
        }

        /**
         * Handle "Run Scan Now" form submission from settings page.
         */
        public function handle_manual_scan() {
            check_admin_referer( 'kw_security_run_scan' );
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }

            $result     = $this->run_scan();
            $count      = count( $result['unknown'] ) + count( $result['modified'] );
            $recipients = $this->get_recipients();
            if ( $count > 0 ) {
                if ( empty( $result['alerted'] ) ) {
                    // Finding already reported and unchanged — no duplicate sent.
                    $msg = sprintf(
                        /* translators: %d: number of anomalies */
                        esc_html__( 'Scan complete. %d anomaly/anomalies still present (already alerted — no duplicate notification sent).', 'kw-security' ),
                        $count
                    );
                } elseif ( empty( $recipients ) ) {
                    $msg = sprintf( /* translators: %d: number of anomalies */ esc_html__( 'Scan complete. %d anomaly/anomalies detected (no email sent — no recipients configured).', 'kw-security' ), $count );
                } else {
                    $msg = sprintf(
                        /* translators: 1: number of anomalies, 2: number of recipients */
                        esc_html__( 'Scan complete. %1$d anomaly/anomalies detected; alert emailed to %2$d recipient(s).', 'kw-security' ),
                        $count,
                        count( $recipients )
                    );
                }
            } else {
                $msg = esc_html__( 'Scan complete. No anomalies detected.', 'kw-security' );
            }

            wp_safe_redirect( add_query_arg(
                array( 'kw_scan' => rawurlencode( $msg ) ),
                admin_url( 'options-general.php?page=kw-security' )
            ) );
            exit;
        }

        /**
         * Handle "Reset Baseline" form submission from settings page.
         */
        public function handle_reset_baseline() {
            check_admin_referer( 'kw_security_reset_baseline' );
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }

            delete_option( self::OPTION_HASHES );
            delete_option( self::OPTION_BASELINE_CONTENT );
            delete_option( self::OPTION_ALERT_STATE );
            $this->run_scan( true );

            wp_safe_redirect( add_query_arg(
                array( 'kw_scan' => rawurlencode( esc_html__( 'Baseline reset. Current state recorded as the new baseline.', 'kw-security' ) ) ),
                admin_url( 'options-general.php?page=kw-security' )
            ) );
            exit;
        }
    }

    if ( KW_Security_Settings::is_enabled( 'file_integrity' ) ) {
        new KW_File_Integrity();
    }
}
