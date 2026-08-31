<?php
/**
 * KW Security – User Lockout
 *
 * When enabled, blocks creating new WordPress users on this site entirely —
 * even for logged-in Administrators — via wp-admin (Users → Add New) or the
 * REST API (POST /wp/v2/users). Every one of those surfaces gates on the
 * single primitive capability `create_users` via current_user_can(), so
 * stripping it in map_meta_cap() closes all of them with one filter.
 *
 * The dashboard's own remote user-creation endpoint
 * (classes/create-user.php) calls wp_insert_user() directly, which never
 * checks capabilities, so it is unaffected by this filter — no bypass or
 * allowlist logic is needed here.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_User_Lockout' ) ) {

    class KW_User_Lockout {

        public function __construct() {
            add_filter( 'map_meta_cap', array( $this, 'strip_create_users' ), 10, 2 );
            add_action( 'admin_notices', array( $this, 'notice' ) );
        }

        /**
         * Revokes create_users for every user by mapping it to a capability
         * no role holds — the same mechanism core itself uses to revoke a
         * capability outright.
         *
         * @param array  $caps Required capabilities.
         * @param string $cap  Requested meta capability.
         * @return array
         */
        public function strip_create_users( $caps, $cap ) {
            if ( 'create_users' === $cap ) {
                return array( 'do_not_allow' );
            }
            return $caps;
        }

        /**
         * The "Add New" menu item and button disappear entirely rather than
         * merely disable, so this explains why on the one screen an admin
         * would land on and wonder where it went.
         */
        public function notice() {
            $screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
            if ( ! $screen || 'users' !== $screen->id ) {
                return;
            }
            echo '<div class="notice notice-info"><p>'
                . esc_html__( 'KW Security — User Lockout is on: new WordPress users can only be added through the KW Security Dashboard\'s Add User page, not from this site directly.', 'kw-security' )
                . '</p></div>';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'user_lockout' ) ) {
        new KW_User_Lockout();
    }
}
