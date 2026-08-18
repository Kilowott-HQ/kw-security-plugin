<?php
/**
 * KW Security – MU-Plugin Loader
 *
 * Copies the bundled must-use activator (mu-plugins/kw-security-activator.php,
 * shipped inside this plugin's own folder — see kw-security.php's directory
 * layout) into WordPress's real wp-content/mu-plugins/ directory
 * automatically, so the remote-activation feature (activate-plugin,
 * activate-wordfence) works without a separate manual upload step.
 *
 * Runs on plugin activation, and again after every self-triggered update
 * (see update-trigger.php) so a newer bundled copy overwrites whatever is
 * already sitting in mu-plugins/, keeping it in sync automatically.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Mu_Loader' ) ) {

    class KW_Security_Mu_Loader {

        const SOURCE_RELATIVE = 'mu-plugins/kw-security-activator.php';
        const DEST_FILENAME   = 'kw-security-activator.php';

        /**
         * Copies the bundled activator into wp-content/mu-plugins/, creating
         * that directory first if it doesn't exist yet (WordPress doesn't
         * create it until something needs it). Always overwrites an existing
         * copy — this is meant to keep the deployed file in sync with
         * whatever version ships inside the current plugin package, not to
         * preserve a hand-edited copy.
         *
         * Silent on failure (e.g. restrictive file permissions on some
         * hosts) — this is a convenience on top of the documented manual
         * upload path, not a hard requirement for the rest of the plugin.
         */
        public static function install() {
            if ( ! defined( 'KW_SECURITY_PLUGIN_DIR' ) || ! defined( 'WPMU_PLUGIN_DIR' ) ) {
                return false;
            }

            $source = KW_SECURITY_PLUGIN_DIR . self::SOURCE_RELATIVE;
            if ( ! file_exists( $source ) ) {
                return false;
            }

            if ( ! wp_mkdir_p( WPMU_PLUGIN_DIR ) ) {
                return false;
            }

            $dest = trailingslashit( WPMU_PLUGIN_DIR ) . self::DEST_FILENAME;

            // Skip the write if the destination already matches — avoids
            // needlessly touching the file's mtime on every activation.
            if ( file_exists( $dest ) && @md5_file( $dest ) === @md5_file( $source ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- tolerate an unreadable existing file; a failed comparison just falls through to re-copying.
                return true;
            }

            return (bool) @copy( $source, $dest ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- permission failures are an expected soft-failure on some hosts, not a fatal condition.
        }
    }
}
