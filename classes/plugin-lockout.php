<?php
/**
 * KW Security – Plugin Lockout
 *
 * When enabled, disables managing plugins on this site entirely — even for
 * logged-in Administrators — via wp-admin. Every plugin-management screen
 * gates on one of five bare primitive capabilities: install_plugins,
 * activate_plugins (covers deactivate too — there is no separate cap),
 * update_plugins, delete_plugins, and edit_plugins (the Plugin File
 * Editor). One map_meta_cap() filter closes all of them.
 *
 * Unlike users, WordPress has no separate "view" capability for plugins —
 * wp-admin/menu.php gates the entire "Plugins" top-level menu, including
 * the plugin list itself, on activate_plugins. So turning this on hides
 * the whole Plugins screen from wp-admin, not just the mutating actions.
 * That is a WordPress core constraint, not a design choice here.
 *
 * The dashboard's own remote endpoints (classes/plugin-toggle.php,
 * classes/update-trigger.php, classes/plugin-file-update.php,
 * classes/plugin-install.php) call activate_plugin() / deactivate_plugins()
 * / Plugin_Upgrader::upgrade() / Plugin_Upgrader::install() directly, none
 * of which check capabilities, so none of them are affected by this — no
 * bypass or allowlist logic is needed here.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Plugin_Lockout' ) ) {

    class KW_Plugin_Lockout {

        const LOCKED_CAPS = array( 'install_plugins', 'activate_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins' );

        public function __construct() {
            add_filter( 'map_meta_cap', array( $this, 'strip_plugin_management_caps' ), 10, 2 );
            add_action( 'admin_notices', array( $this, 'notice' ) );
        }

        /**
         * Revokes the five plugin-management capabilities for every user by
         * mapping them to a capability no role holds — the same mechanism
         * core itself uses to revoke a capability outright. These are all
         * bare primitives (no per-object meta-cap mapping like edit_user
         * has), so checking $cap directly is sufficient here.
         *
         * @param array  $caps Required capabilities so far.
         * @param string $cap  Requested capability.
         * @return array
         */
        public function strip_plugin_management_caps( $caps, $cap ) {
            if ( in_array( $cap, self::LOCKED_CAPS, true ) ) {
                return array( 'do_not_allow' );
            }
            return $caps;
        }

        /**
         * The entire "Plugins" menu disappears rather than merely
         * disabling, so there is no page left to show a notice on for
         * anyone who'd wonder where it went — this shows on the main
         * wp-admin Dashboard screen instead, the one place a locked-out
         * admin can still reach.
         */
        public function notice() {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            if ( ! $screen || 'dashboard' !== $screen->id ) {
                return;
            }
            echo '<div class="notice notice-info"><p>'
                . esc_html__( 'KW Security — Plugin Lockout is on: plugins can only be installed, activated, deactivated, or updated through the KW Security Dashboard, not from this site directly.', 'kw-security' )
                . '</p></div>';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'plugin_lockout' ) ) {
        new KW_Plugin_Lockout();
    }
}
