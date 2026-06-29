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

            // Reschedule on every page load if missing — handles the case
            // where the feature was just toggled on and cron isn't set up.
            if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
                wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
            }

            // Auto-reset baseline after a WP core update (index.php legitimately changes).
            add_action( '_core_updated_successfully', array( $this, 'reset_baseline_silent' ) );

            // Manual scan + reset triggers from the settings page.
            add_action( 'admin_post_kw_security_run_scan',         array( $this, 'handle_manual_scan' ) );
            add_action( 'admin_post_kw_security_reset_baseline',   array( $this, 'handle_reset_baseline' ) );
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
         * @return array{unknown:array<string>, modified:array<string>}
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

            if ( ! $silent && ( ! empty( $unknown ) || ! empty( $modified ) ) ) {
                $this->send_alert( $unknown, $modified, $changes );

                // Notify listeners (e.g. Slack alerts) of the same anomalies.
                // Third arg is optional — existing 2-arg listeners ignore it.
                do_action( 'kw_file_integrity_anomaly', $unknown, $modified, $changes );
            }

            return array( 'unknown' => $unknown, 'modified' => $modified, 'changes' => $changes );
        }

        /**
         * Reset baseline after a known-good event (e.g. WP core update).
         */
        public function reset_baseline_silent() {
            delete_option( self::OPTION_HASHES );
            delete_option( self::OPTION_BASELINE_CONTENT );
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
                $msg = empty( $recipients )
                    ? sprintf( /* translators: %d: number of anomalies */ esc_html__( 'Scan complete. %d anomaly/anomalies detected (no email sent — no recipients configured).', 'kw-security' ), $count )
                    : sprintf(
                        /* translators: 1: number of anomalies, 2: number of recipients */
                        esc_html__( 'Scan complete. %1$d anomaly/anomalies detected; alert emailed to %2$d recipient(s).', 'kw-security' ),
                        $count,
                        count( $recipients )
                    );
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
