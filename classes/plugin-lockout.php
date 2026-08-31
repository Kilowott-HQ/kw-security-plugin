<?php
/**
 * KW Security – Plugin Lockout
 *
 * When enabled, disables managing plugins on this site — even for
 * logged-in Administrators — via wp-admin, while leaving the Installed
 * Plugins list itself visible.
 *
 * install_plugins, update_plugins, delete_plugins, and edit_plugins (the
 * Plugin File Editor) are each their own bare primitive capability, so
 * stripping them via map_meta_cap() closes the Add Plugins screen, plugin
 * updates, plugin deletion, and the file editor without touching anything
 * else — those screens have no separate "view" mode to preserve.
 *
 * activate_plugins is different: WordPress maps activate_plugin,
 * deactivate_plugin, and deactivate_plugins to that same single primitive
 * (see map_meta_cap()'s 'activate_plugins' case in wp-includes/capabilities.php),
 * and wp-admin/plugins.php's own top-of-file gate is
 * current_user_can('activate_plugins') — the same capability that controls
 * merely loading the page at all. There is no way to grant "can see the
 * list" without also granting "can activate/deactivate" through
 * capabilities alone. So activate_plugins is left granted (the list stays
 * visible, matching every other Installed Plugins view in wp-admin), and
 * activate/deactivate are blocked at the request level instead: an
 * admin_init hook rejects any plugins.php request that isn't a plain page
 * view before plugins.php's own handler ever runs, and the Activate/
 * Deactivate row and bulk-action links are hidden so there is nothing
 * clickable that would hit that block anyway.
 *
 * The dashboard's own remote endpoints (classes/plugin-toggle.php,
 * classes/update-trigger.php, classes/plugin-file-update.php,
 * classes/plugin-install.php) call activate_plugin() / deactivate_plugins()
 * / Plugin_Upgrader::upgrade() / Plugin_Upgrader::install() directly — none
 * of which check capabilities — and never touch wp-admin/plugins.php, so
 * none of them are affected by any of this.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Plugin_Lockout' ) ) {

    class KW_Plugin_Lockout {

        const LOCKED_CAPS = array( 'install_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins' );

        public function __construct() {
            add_filter( 'map_meta_cap', array( $this, 'strip_plugin_management_caps' ), 10, 2 );
            add_filter( 'plugin_action_links', array( $this, 'strip_row_actions' ), 999 );
            add_filter( 'bulk_actions-plugins', array( $this, 'strip_bulk_actions' ), 999 );
            add_action( 'admin_init', array( $this, 'block_mutating_requests' ), 1 );
            add_action( 'admin_notices', array( $this, 'notice' ) );
        }

        /**
         * Revokes install_plugins, update_plugins, delete_plugins, and
         * edit_plugins by mapping them to a capability no role holds — the
         * same mechanism core itself uses to revoke a capability outright.
         * Deliberately does NOT touch activate_plugins — see the file
         * docblock for why that one has to be handled differently.
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
         * Hides the per-row Activate/Deactivate/Delete links on the
         * Installed Plugins list so nothing clickable leads to
         * block_mutating_requests() below. Delete is already unreachable
         * via delete_plugins being stripped, but core still shows the link
         * unless removed here too.
         */
        public function strip_row_actions( $actions ) {
            unset( $actions['activate'], $actions['deactivate'], $actions['delete'] );
            return $actions;
        }

        /**
         * Same idea for the "Bulk actions" dropdown above the list.
         */
        public function strip_bulk_actions( $actions ) {
            unset(
                $actions['activate-selected'],
                $actions['deactivate-selected'],
                $actions['delete-selected'],
                $actions['update-selected']
            );
            return $actions;
        }

        /**
         * plugins.php handles activate/deactivate itself, gated only by
         * activate_plugins — the same capability required just to load the
         * page — so it can't be blocked by stripping a capability without
         * also hiding the list. This runs on admin_init, before
         * plugins.php's own action-handling code, and rejects any request
         * carrying a real action (activate, deactivate, activate-selected,
         * deactivate-selected, etc. — the list table's own "-1"
         * placeholder means no action was actually chosen). A bare page
         * view — including the harmless Screen Options POST, which
         * carries no action/action2 at all — is left alone.
         */
        public function block_mutating_requests() {
            global $pagenow;
            if ( 'plugins.php' !== $pagenow ) {
                return;
            }

            $action  = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
            $action2 = isset( $_REQUEST['action2'] ) ? sanitize_key( wp_unslash( $_REQUEST['action2'] ) ) : '';
            $has_action = ( '' !== $action && '-1' !== $action ) || ( '' !== $action2 && '-1' !== $action2 );

            if ( ! $has_action ) {
                return;
            }

            wp_die(
                esc_html__( 'KW Security — Plugin Lockout is on: plugins can be viewed here, but can only be activated, deactivated, or otherwise managed through the KW Security Dashboard.', 'kw-security' ),
                esc_html__( 'Plugin Lockout is on', 'kw-security' ),
                array( 'response' => 403 )
            );
        }

        /**
         * The Installed Plugins list stays reachable, so — unlike User
         * Lockout — this can show up right where it's relevant.
         */
        public function notice() {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            if ( ! $screen || 'plugins' !== $screen->id ) {
                return;
            }
            echo '<div class="notice notice-info"><p>'
                . esc_html__( 'KW Security — Plugin Lockout is on: plugins can be viewed here, but can only be installed, activated, deactivated, updated, or removed through the KW Security Dashboard.', 'kw-security' )
                . '</p></div>';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'plugin_lockout' ) ) {
        new KW_Plugin_Lockout();
    }
}
