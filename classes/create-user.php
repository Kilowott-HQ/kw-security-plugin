<?php
/**
 * KW Security – Dashboard-triggered user creation
 *
 * Registers POST /wp-json/kw-security/v1/create-user
 *
 * Lets the Security Dashboard create a real WordPress user on this site
 * remotely — the sanctioned path once User Lockout (classes/user-lockout.php)
 * has disabled every other way to add one. Same signed-request model as the
 * plugin's other dashboard-triggered endpoints: no shared secret exists
 * between the dashboard and this site, so the dashboard signs the request
 * with a private key and this verifies it against a bundled public key. The
 * signed message includes every field that determines the resulting
 * account, so a captured signature can't be replayed to create a different
 * user, with a different role, or a different password.
 *
 * Calls wp_insert_user() directly rather than going through wp-admin's
 * user-new.php form or the REST /wp/v2/users endpoint, so it is never
 * affected by User Lockout's map_meta_cap() filter — that filter only
 * strips the create_users capability, and wp_insert_user() never checks
 * capabilities at all.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Create_User' ) ) {

    class KW_Security_Create_User {

        const API_NAMESPACE      = 'kw-security/v1';
        const ROUTE               = '/create-user';
        const TS_WINDOW           = 300; // seconds — reject stale/replayed requests
        const MIN_PASSWORD_LENGTH = 12;  // same precedent as admin-users.php's set-password

        const VALID_ROLES = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );

        // Same keypair as the plugin's other dashboard-triggered endpoints.
        // Safe to publish — verifies signatures, cannot forge them.
        const DASHBOARD_UPDATE_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjtG3XkYTGtr3YoN5/BgJ
OHXBKcHKaY90xyw/6zxRFTHxVwGGCGqm1MGhcx/9EHHPNKJzBTzFSrzUY46Pc9lE
KWD4CdJnmgDKNzNw5xJR2cjlsVDK+fABDh2GC23XztAc0o/2m0tr57Gm2Ivcnael
vu81LbCfysLRAm6O75s8UawN/UEqpp0eaeMedBzWAB1RBEaDoe4aBPJc2ZQo+uLr
UirIbOYn69OyNWoxqG7AwwoKwXvun6WSONnnRC3btH88D1hKq3oAMALp0zHw8Fkc
Grty7dMqCwbdNKtwr9GL2i7Ve8YrhNCt7uT4NEhbi2JXnXDIqxBQwVumXsJ1taPx
YQIDAQAB
-----END PUBLIC KEY-----';

        public static function init() {
            register_rest_route( self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( __CLASS__, 'handle' ),
                'permission_callback' => array( __CLASS__, 'authenticate' ),
            ) );
        }

        private static function to_bool( $value ) {
            return in_array( $value, array( true, 1, '1', 'true' ), true );
        }

        /**
         * Verifies the request came from the dashboard for THIS site, for
         * THIS exact account, within a short freshness window. Every
         * mutable field is bound into the signed message.
         */
        public static function authenticate( WP_REST_Request $request ) {
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error( 'https_required', 'This endpoint requires HTTPS.', array( 'status' => 403 ) );
            }

            $installation_id = sanitize_text_field( (string) $request->get_param( 'installation_id' ) );
            $username         = (string) $request->get_param( 'username' );
            $email            = (string) $request->get_param( 'email' );
            $role             = (string) $request->get_param( 'role' );
            $new_password     = (string) $request->get_param( 'new_password' );
            $notify_param     = $request->get_param( 'send_notification' );
            $timestamp        = (int) $request->get_param( 'timestamp' );
            $signature        = (string) $request->get_param( 'signature' );

            if ( ! $installation_id || '' === $username || '' === $email || '' === $role || '' === $new_password || null === $notify_param || ! $timestamp || ! $signature ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( ! class_exists( 'KW_Security_Telemetry' ) || $installation_id !== KW_Security_Telemetry::get_site_id() ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( abs( time() - $timestamp ) > self::TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $notify    = self::to_bool( $notify_param );
            $message   = $installation_id . '|create-user|' . $username . '|' . $email . '|' . $role . '|' . $new_password . '|' . ( $notify ? '1' : '0' ) . '|' . $timestamp;
            $sig_bytes = base64_decode( $signature, true );
            if ( false === $sig_bytes ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $pub = openssl_get_publickey( self::DASHBOARD_UPDATE_PUBLIC_KEY );
            if ( false === $pub || 1 !== openssl_verify( $message, $sig_bytes, $pub, OPENSSL_ALGO_SHA256 ) ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            return true;
        }

        public static function handle( WP_REST_Request $request ) {
            $username   = sanitize_user( (string) $request->get_param( 'username' ), true );
            $email      = sanitize_email( (string) $request->get_param( 'email' ) );
            $role       = sanitize_key( (string) $request->get_param( 'role' ) );
            $password   = (string) $request->get_param( 'new_password' );
            $first_name = sanitize_text_field( (string) $request->get_param( 'first_name' ) );
            $last_name  = sanitize_text_field( (string) $request->get_param( 'last_name' ) );
            $website    = (string) $request->get_param( 'website' );
            $notify     = self::to_bool( $request->get_param( 'send_notification' ) );

            if ( '' === $username || ! validate_username( $username ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'That username is not valid.' ), 400 );
            }
            if ( ! is_email( $email ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'That email address is not valid.' ), 400 );
            }
            if ( ! in_array( $role, self::VALID_ROLES, true ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'That role is not valid.' ), 400 );
            }
            if ( strlen( $password ) < self::MIN_PASSWORD_LENGTH ) {
                return new WP_REST_Response( array(
                    'ok'      => false,
                    'message' => 'Password must be at least ' . self::MIN_PASSWORD_LENGTH . ' characters.',
                ), 400 );
            }
            if ( username_exists( $username ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'That username already exists on this site.' ), 409 );
            }
            if ( email_exists( $email ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => 'That email address is already in use on this site.' ), 409 );
            }

            $userdata = array(
                'user_login' => $username,
                'user_email' => $email,
                'user_pass'  => $password,
                'role'       => $role,
                'first_name' => $first_name,
                'last_name'  => $last_name,
            );
            if ( '' !== $website ) {
                $userdata['user_url'] = esc_url_raw( $website );
            }

            // Attribute the resulting Activity Log "Registered" entry to the
            // dashboard role behind this request instead of "Guest" — see
            // KW_Security_Dashboard_Actor in mu-plugins/kw-security-activator.php
            // (always loaded, so it's guaranteed to already exist here).
            if ( class_exists( 'KW_Security_Dashboard_Actor' ) ) {
                KW_Security_Dashboard_Actor::set( $request->get_param( 'actor_role' ) );
            }

            $user_id = wp_insert_user( $userdata );

            if ( is_wp_error( $user_id ) ) {
                return new WP_REST_Response( array( 'ok' => false, 'message' => $user_id->get_error_message() ), 500 );
            }

            if ( $notify && function_exists( 'wp_new_user_notification' ) ) {
                wp_new_user_notification( $user_id, null, 'user' );
            }

            return new WP_REST_Response( array(
                'ok'       => true,
                'user_id'  => $user_id,
                'username' => $username,
            ), 200 );
        }
    }

    // Registered unconditionally — creation itself has no feature toggle;
    // User Lockout only gates the OTHER ways to create a user, by design.
    add_action( 'rest_api_init', array( 'KW_Security_Create_User', 'init' ) );
}
