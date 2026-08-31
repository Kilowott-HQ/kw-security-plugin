<?php
/**
 * KW Security – Plugin Lockout
 *
 * When enabled, blocks managing exactly three plugins — KW Security, KW
 * Performance, and Wordfence, the site's own security/monitoring tooling —
 * even for logged-in Administrators, via wp-admin. Every other installed
 * plugin is completely unaffected.
 *
 * install_plugins, update_plugins, delete_plugins, edit_plugins, and
 * activate_plugins are all bare, whole-site WordPress capabilities — none
 * of them are scoped per-plugin, so "can manage plugin A but not plugin B"
 * isn't expressible as a capability at all. This never strips any of them
 * (every wp-admin plugin screen works normally for anything other than the
 * three locked plugins, including Add Plugins and the Plugin File Editor)
 * and instead blocks specific *requests* on admin_init, before the target
 * page's own handler runs, by checking which plugin(s) the request
 * actually names against the locked list:
 *
 *   - plugins.php    — activate/deactivate/delete (single: `plugin`,
 *                       bulk: `checked[]`, WP_List_Table's standard
 *                       checkbox field name).
 *   - update.php     — single update (`action=upgrade-plugin`, `plugin`),
 *                       bulk update (`action=update-selected`, `plugins`
 *                       or `checked[]`), and install (`action=install-plugin`,
 *                       `plugin` — here it's a slug, e.g. "wordfence", not
 *                       a folder/file.php path).
 *   - plugin-editor.php — the `file` param's leading path segment.
 *
 * The dashboard's own remote endpoints (classes/plugin-toggle.php,
 * classes/update-trigger.php, classes/plugin-file-update.php,
 * classes/plugin-install.php) call activate_plugin() / deactivate_plugins()
 * / Plugin_Upgrader::upgrade() / Plugin_Upgrader::install() directly — none
 * of which check capabilities or run through wp-admin at all — so they're
 * unaffected regardless of any of this, for any of the three plugins.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Plugin_Lockout' ) ) {

    class KW_Plugin_Lockout {

        const LOCKED_PLUGIN_FILES = array(
            'kw-security/kw-security.php',
            'kw-performance/kw-performance.php',
            'wordfence/wordfence.php',
        );

        // Directory-name form, for the two surfaces (install, file editor)
        // that key off a plugin's slug rather than its main file.
        const LOCKED_PLUGIN_SLUGS = array( 'kw-security', 'kw-performance', 'wordfence' );

        public function __construct() {
            add_filter( 'plugin_action_links', array( $this, 'strip_row_actions' ), 999, 2 );
            add_action( 'admin_init', array( $this, 'block_mutating_requests' ), 1 );
            add_action( 'admin_notices', array( $this, 'notice' ) );
        }

        /**
         * Hides the Activate/Deactivate/Delete row links, but only on the
         * three locked plugins' own rows — $plugin_file identifies exactly
         * which row this is, so every other plugin's row is untouched.
         */
        public function strip_row_actions( $actions, $plugin_file ) {
            if ( in_array( $plugin_file, self::LOCKED_PLUGIN_FILES, true ) ) {
                unset( $actions['activate'], $actions['deactivate'], $actions['delete'] );
            }
            return $actions;
        }

        public function block_mutating_requests() {
            global $pagenow;

            if ( 'plugins.php' === $pagenow ) {
                $action  = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
                $action2 = isset( $_REQUEST['action2'] ) ? sanitize_key( wp_unslash( $_REQUEST['action2'] ) ) : '';
                $has_action = ( '' !== $action && '-1' !== $action ) || ( '' !== $action2 && '-1' !== $action2 );
                if ( ! $has_action ) {
                    return;
                }
                if ( self::targets_locked_file( self::requested_plugin_files() ) ) {
                    self::die_locked();
                }
                return;
            }

            if ( 'update.php' === $pagenow ) {
                $action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

                if ( 'upgrade-plugin' === $action ) {
                    $plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) ) : '';
                    if ( in_array( $plugin, self::LOCKED_PLUGIN_FILES, true ) ) {
                        self::die_locked();
                    }
                } elseif ( 'update-selected' === $action ) {
                    $plugins = array();
                    if ( isset( $_GET['plugins'] ) ) {
                        $plugins = explode( ',', stripslashes( (string) wp_unslash( $_GET['plugins'] ) ) );
                    } elseif ( isset( $_POST['checked'] ) ) {
                        $plugins = (array) wp_unslash( $_POST['checked'] );
                    }
                    if ( self::targets_locked_file( $plugins ) ) {
                        self::die_locked();
                    }
                } elseif ( 'install-plugin' === $action ) {
                    $slug = isset( $_REQUEST['plugin'] ) ? sanitize_key( wp_unslash( $_REQUEST['plugin'] ) ) : '';
                    if ( in_array( $slug, self::LOCKED_PLUGIN_SLUGS, true ) ) {
                        self::die_locked();
                    }
                }
                return;
            }

            if ( 'plugin-editor.php' === $pagenow ) {
                $file = isset( $_REQUEST['file'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['file'] ) ) : '';
                foreach ( self::LOCKED_PLUGIN_SLUGS as $slug ) {
                    if ( 0 === strpos( $file, $slug . '/' ) ) {
                        self::die_locked();
                    }
                }
            }
        }

        /**
         * Every plugin file named anywhere in the current request —
         * `plugin` for a single-item action, `checked[]` for a bulk one
         * (WP_List_Table's standard checkbox field name across every
         * screen that uses it, not just this one).
         *
         * @return string[]
         */
        private static function requested_plugin_files() {
            $targets = array();
            if ( isset( $_REQUEST['plugin'] ) ) {
                $targets[] = sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) );
            }
            if ( isset( $_REQUEST['checked'] ) ) {
                foreach ( (array) wp_unslash( $_REQUEST['checked'] ) as $checked ) {
                    $targets[] = sanitize_text_field( $checked );
                }
            }
            return $targets;
        }

        private static function targets_locked_file( $files ) {
            foreach ( (array) $files as $file ) {
                if ( in_array( $file, self::LOCKED_PLUGIN_FILES, true ) ) {
                    return true;
                }
            }
            return false;
        }

        private static function die_locked() {
            wp_die(
                esc_html__( 'KW Security — Plugin Lockout is on: KW Security, KW Performance, and Wordfence can only be managed through the KW Security Dashboard, not from this site directly.', 'kw-security' ),
                esc_html__( 'Plugin Lockout is on', 'kw-security' ),
                array( 'response' => 403 )
            );
        }

        /**
         * The lockout only applies to three specific rows on a page that's
         * otherwise fully normal, so there's no single relevant screen to
         * anchor a notice to the way User Lockout can — shown on the main
         * Dashboard screen instead, same as before.
         */
        public function notice() {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            if ( ! $screen || 'dashboard' !== $screen->id ) {
                return;
            }
            echo '<div class="notice notice-info"><p>'
                . esc_html__( 'KW Security — Plugin Lockout is on: KW Security, KW Performance, and Wordfence can only be installed, activated, deactivated, updated, or removed through the KW Security Dashboard. Every other plugin is unaffected.', 'kw-security' )
                . '</p></div>';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'plugin_lockout' ) ) {
        new KW_Plugin_Lockout();
    }
}
