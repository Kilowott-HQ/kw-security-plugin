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

            // Detect modifications — only flag files that exist in baseline AND have changed.
            $modified = array();
            foreach ( $current_hashes as $file => $hash ) {
                if ( isset( $baseline[ $file ] ) && $baseline[ $file ] !== $hash ) {
                    $modified[] = $file;
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
            update_option( self::OPTION_HASHES, $baseline, false );
            update_option( self::OPTION_LAST, time(), false );

            if ( ! $silent && ( ! empty( $unknown ) || ! empty( $modified ) ) ) {
                $this->send_alert( $unknown, $modified );
            }

            return array( 'unknown' => $unknown, 'modified' => $modified );
        }

        /**
         * Reset baseline after a known-good event (e.g. WP core update).
         */
        public function reset_baseline_silent() {
            delete_option( self::OPTION_HASHES );
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
         * Compute current sha1 hashes of tracked files.
         *
         * @return array<string,string>
         */
        private function compute_current_hashes() {
            $hashes = array();
            foreach ( self::HASHED_FILES as $relative ) {
                $full = ABSPATH . $relative;
                if ( file_exists( $full ) && is_readable( $full ) ) {
                    // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Belt-and-suspenders: file_exists + is_readable already guard, but @ swallows race-condition warnings if the file disappears between the check and the hash.
                    $hash = @sha1_file( $full );
                    if ( false !== $hash ) {
                        $hashes[ $relative ] = $hash;
                    }
                }
            }
            return $hashes;
        }

        /**
         * Send anomaly alert to the site admin email.
         *
         * @param array<string> $unknown
         * @param array<string> $modified
         */
        private function send_alert( $unknown, $modified ) {
            $to      = get_option( 'admin_email' );
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
                }
                $body .= "\nThese files have been modified since the baseline was set. ";
                $body .= "If you did not change them, restore from backup or compare against a clean WordPress install.\n\n";
            }

            $body .= 'Manage scan results: ' . admin_url( 'options-general.php?page=kw-security' ) . "\n";

            wp_mail( $to, $subject, $body );
        }

        /**
         * Handle "Run Scan Now" form submission from settings page.
         */
        public function handle_manual_scan() {
            check_admin_referer( 'kw_security_run_scan' );
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }

            $result = $this->run_scan();
            $count  = count( $result['unknown'] ) + count( $result['modified'] );
            $msg    = $count > 0
                ? sprintf( /* translators: %d: number of anomalies */ esc_html__( 'Scan complete. %d anomaly/anomalies detected and email sent to site admin.', 'kw-security' ), $count )
                : esc_html__( 'Scan complete. No anomalies detected.', 'kw-security' );

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
