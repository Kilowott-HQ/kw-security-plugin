<?php
/**
 * KW Security – User Enumeration Protection
 *
 * Closes two user-enumeration vectors that ship enabled in core WordPress:
 *
 *   1. ?author=N redirect leak
 *      Visiting /?author=1 normally redirects to /author/<username>/, which
 *      exposes the login slug for that user ID. We send 404 instead for
 *      anonymous visitors. Author archives reached via /author/<slug>/ keep
 *      working — only the numeric form is blocked. Logged-in users (admins
 *      inspecting the site) keep normal behavior.
 *
 *   2. Unauthenticated /wp/v2/users REST listing
 *      The default endpoint exposes user_login, display_name, avatar URLs,
 *      and description for any user who has published a post. We require
 *      authentication. Logged-in REST callers (Gutenberg, block editor,
 *      authenticated front-end requests) keep full access.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_User_Enumeration' ) ) {

    class KW_User_Enumeration {

        public function __construct() {
            // Run before redirect_canonical (priority 10) so the leak never happens.
            add_action( 'template_redirect', array( $this, 'block_author_query' ), 1 );

            // Gate /wp/v2/users behind authentication.
            add_filter( 'rest_authentication_errors', array( $this, 'restrict_users_endpoint' ) );
        }

        /**
         * Convert /?author=N requests into 404s for anonymous visitors.
         */
        public function block_author_query() {
            if ( is_user_logged_in() ) {
                return;
            }
            if ( ! isset( $_GET['author'] ) || ! is_numeric( $_GET['author'] ) ) {
                return;
            }

            // Stop core's canonical redirect from leaking the username.
            remove_action( 'template_redirect', 'redirect_canonical' );

            global $wp_query;
            if ( $wp_query ) {
                $wp_query->is_author  = false;
                $wp_query->is_archive = false;
                $wp_query->set_404();
            }
            status_header( 404 );
            nocache_headers();
        }

        /**
         * Require authentication for /wp/v2/users(/.*)?.
         *
         * @param mixed $errors Existing auth errors (true|null|WP_Error).
         * @return mixed
         */
        public function restrict_users_endpoint( $errors ) {
            // Don't override an existing auth result.
            if ( is_wp_error( $errors ) || true === $errors ) {
                return $errors;
            }
            if ( is_user_logged_in() ) {
                return $errors;
            }

            $route = isset( $GLOBALS['wp']->query_vars['rest_route'] )
                ? $GLOBALS['wp']->query_vars['rest_route']
                : '';

            if ( $route && preg_match( '#^/wp/v2/users(?:/|$)#', $route ) ) {
                return new WP_Error(
                    'rest_user_cannot_view',
                    esc_html__( 'Authentication required to view user data.', 'kw-security' ),
                    array( 'status' => 401 )
                );
            }

            return $errors;
        }
    }

    if ( KW_Security_Settings::is_enabled( 'user_enumeration' ) ) {
        new KW_User_Enumeration();
    }
}
