<?php
/**
 * KW Security – User Lockout
 *
 * When enabled, disables managing WordPress users on this site entirely —
 * even for logged-in Administrators — via wp-admin or the REST API:
 *
 *   - Creating a user (Users → Add New, wp-admin/user-new.php,
 *     POST /wp/v2/users) — all gate on the create_users capability.
 *   - Editing or deleting an existing user, and the "Send password reset"
 *     row action — all gate on the edit_users/delete_users capabilities.
 *     (Editing your OWN profile is untouched: WordPress's own capability
 *     mapping never requires edit_users for that, only for editing someone
 *     else — see the self-edit branch in map_meta_cap().)
 *
 * One map_meta_cap() filter closes all of the above, since every one of
 * them ultimately resolves to checking create_users, edit_users, or
 * delete_users.
 *
 * The Users list's "View" row action isn't gated by any capability in core
 * (it just links to the user's public author archive), and a "Login
 * Security" row action some plugins add (e.g. Wordfence's 2FA management
 * link) is entirely third-party — neither can be closed by stripping a
 * capability, so both are removed directly via the user_row_actions filter.
 *
 * The dashboard's own remote endpoints (classes/create-user.php,
 * classes/admin-users.php's update/delete/set-password routes) call
 * wp_insert_user() / wp_update_user() / wp_delete_user() / wp_set_password()
 * directly, none of which check capabilities, so none of them are affected
 * by any of this — no bypass or allowlist logic is needed here.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_User_Lockout' ) ) {

    class KW_User_Lockout {

        public function __construct() {
            add_filter( 'map_meta_cap', array( $this, 'strip_user_management_caps' ), 10, 2 );
            add_filter( 'user_row_actions', array( $this, 'strip_row_actions' ), 999, 2 );
            add_action( 'admin_notices', array( $this, 'notice' ) );
        }

        /**
         * Revokes create_users, edit_users, and delete_users for every user
         * by mapping them to a capability no role holds — the same
         * mechanism core itself uses to revoke a capability outright.
         *
         * $cap is the ORIGINALLY REQUESTED capability, which for a per-user
         * meta check (edit_user/delete_user) is the singular form even
         * though $caps ends up containing the plural primitive — so this
         * checks $caps' contents for edit_users/delete_users rather than
         * $cap, to catch both the meta-cap and bare-primitive call shapes
         * in one place. create_users has no such split (there's no
         * "create_user" meta cap), so it's checked directly via $cap.
         *
         * @param array  $caps Required capabilities so far.
         * @param string $cap  Requested (meta or primitive) capability.
         * @return array
         */
        public function strip_user_management_caps( $caps, $cap ) {
            if ( 'create_users' === $cap ) {
                return array( 'do_not_allow' );
            }
            if ( in_array( 'edit_users', $caps, true ) || in_array( 'delete_users', $caps, true ) ) {
                return array( 'do_not_allow' );
            }
            return $caps;
        }

        /**
         * Removes the "View" row action (never capability-gated in core)
         * and any "Login Security" action a third-party plugin added to
         * this same row — matched by its visible text rather than an
         * assumed array key, since the key isn't part of any plugin's
         * public API and could change between versions. Priority 999 so
         * this runs after whatever added it.
         */
        public function strip_row_actions( $actions, $user_object ) {
            unset( $actions['view'] );
            foreach ( $actions as $key => $markup ) {
                if ( false !== stripos( wp_strip_all_tags( $markup ), 'login security' ) ) {
                    unset( $actions[ $key ] );
                }
            }
            return $actions;
        }

        /**
         * The "Add New" menu item and button, and the Edit/Delete/Send
         * password reset/View/Login Security row actions, all disappear
         * entirely rather than merely disable, so this explains why on the
         * one screen an admin would land on and wonder where they went.
         */
        public function notice() {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            if ( ! $screen || 'users' !== $screen->id ) {
                return;
            }
            echo '<div class="notice notice-info"><p>'
                . esc_html__( 'KW Security — User Lockout is on: WordPress users can only be added, edited, or removed through the KW Security Dashboard, not from this site directly.', 'kw-security' )
                . '</p></div>';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'user_lockout' ) ) {
        new KW_User_Lockout();
    }
}
