<?php
/**
 * KW Security – User Enumeration Protection
 *
 * Closes two user-enumeration vectors that ship enabled in core WordPress:
 *
 *   1. ?author=N redirect leak
 *      Visiting /?author=1 normally redirects to /author/<username>/, which
 *      exposes the login slug for that user ID. We redirect to the homepage
 *      instead for anonymous visitors. Author archives reached via
 *      /author/<slug>/ keep working — only the numeric form is blocked.
 *      Logged-in users (admins inspecting the site) keep normal behavior.
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
            // Hook on 'wp' (fires before template_redirect and redirect_canonical)
            // so the block cannot be raced by earlier canonical redirects.
            add_action( 'wp', array( $this, 'block_author_query' ), 1 );

            // Gate /wp/v2/users behind authentication.
            add_filter( 'rest_authentication_errors', array( $this, 'restrict_users_endpoint' ) );
        }

        /**
         * Redirect /?author=N requests to the homepage for anonymous visitors.
         */
        public function block_author_query() {
            if ( is_user_logged_in() ) {
                return;
            }
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing check on a public query var; no state change.
            if ( ! isset( $_GET['author'] ) || ! is_numeric( $_GET['author'] ) ) {
                return;
            }

            nocache_headers();
            wp_safe_redirect( home_url( '/' ), 301 );
            exit;
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

if ( ! class_exists( 'KW_Disable_Author_URL' ) ) {

    class KW_Disable_Author_URL {

        public function __construct() {
            add_action( 'template_redirect', array( $this, 'redirect_author_archive' ), 1 );
        }

        /**
         * Redirect /author/<slug> archive pages to the homepage for all visitors.
         */
        public function redirect_author_archive() {
            if ( ! is_author() ) {
                return;
            }
            nocache_headers();
            wp_safe_redirect( home_url( '/' ), 301 );
            exit;
        }
    }

    if ( KW_Security_Settings::is_enabled( 'disable_author_url' ) ) {
        new KW_Disable_Author_URL();
    }
}
