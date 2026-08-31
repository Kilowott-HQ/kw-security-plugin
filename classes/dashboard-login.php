<?php
/**
 * KW Security — Dashboard one-click WordPress login
 *
 * Registers POST /wp-json/kw-security/v1/request-login
 *
 * Lets the Security Dashboard's "WP admin" button log straight into this
 * site's wp-admin, the same way a hosting platform's own "Log in to
 * WordPress" button works (Kinsta, Elementor Cloud, etc.): the dashboard
 * requests a one-time, 60-second login token here (signed the same way as
 * every other dashboard-triggered endpoint), then sends the browser to a
 * URL carrying that token. init() below consumes it — single-use, and
 * expired the moment it's used or 60 seconds pass, whichever first.
 *
 * Logs in as a dedicated "KW Security Dashboard" administrator account
 * (created once, on first use) rather than impersonating any real person's
 * account — visible in the site's own Users list, same as any other admin,
 * so this is never a hidden backdoor. It has no usable password: the
 * random string set at creation is never recorded anywhere, so the only
 * way into this account is through this token flow.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security_Dashboard_Login')) {

    class KW_Security_Dashboard_Login {

        const API_NAMESPACE  = 'kw-security/v1';
        const ROUTE          = '/request-login';
        const TS_WINDOW      = 300; // seconds — reject stale/replayed requests
        const TOKEN_TTL      = 60;  // seconds — the issued login link's own lifetime
        const OPTION_USER_ID = 'kw_security_dashboard_user_id';
        const QUERY_VAR      = 'kw_security_login';
        const SESSION_TTL    = 8 * HOUR_IN_SECONDS; // this account is never left logged in longer than this

        // Same keypair as the plugin's other dashboard-triggered endpoints —
        // same trust boundary, but a different signed message shape, so a
        // signature for one action never verifies for another.
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
            register_rest_route(self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array(__CLASS__, 'handle'),
                'permission_callback' => array(__CLASS__, 'authenticate'),
            ));
        }

        public static function authenticate(WP_REST_Request $request) {
            if (strpos(home_url(), 'https://') === 0 && !is_ssl()) {
                return new WP_Error('https_required', 'This endpoint requires HTTPS.', array('status' => 403));
            }

            $installation_id = sanitize_text_field((string) $request->get_param('installation_id'));
            $timestamp        = (int) $request->get_param('timestamp');
            $signature        = (string) $request->get_param('signature');

            if (!$installation_id || !$timestamp || !$signature) {
                return new WP_Error('bad_request', 'Forbidden.', array('status' => 403));
            }

            if (!class_exists('KW_Security_Telemetry') || $installation_id !== KW_Security_Telemetry::get_site_id()) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            if (abs(time() - $timestamp) > self::TS_WINDOW) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $message   = $installation_id . '|request-login|' . $timestamp;
            $sig_bytes = base64_decode($signature, true);
            if (false === $sig_bytes) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            $pub = openssl_get_publickey(self::DASHBOARD_UPDATE_PUBLIC_KEY);
            if (false === $pub || 1 !== openssl_verify($message, $sig_bytes, $pub, OPENSSL_ALGO_SHA256)) {
                return new WP_Error('forbidden', 'Forbidden.', array('status' => 403));
            }

            return true;
        }

        /**
         * Issues a one-time login token for the dedicated dashboard account,
         * creating that account first if this site has never needed one.
         * The actor_role (unsigned — see plugin-toggle.php for the same
         * pattern) travels with the token itself, not just this response,
         * since consuming it happens in a later, separate request that has
         * no other way to know who asked for it.
         */
        public static function handle(WP_REST_Request $request) {
            require_once ABSPATH . 'wp-admin/includes/user.php';

            // Set before get_or_create_dashboard_user() below, not after —
            // that call itself creates the "KW Security Dashboard" account
            // (wp_insert_user(), firing user_register) the very first time
            // any site sees this flow, and activity-log.php's
            // on_user_register() only attributes correctly if the actor is
            // already known by the time that fires.
            $actor_role = sanitize_key((string) $request->get_param('actor_role'));
            if (class_exists('KW_Security_Dashboard_Actor')) {
                KW_Security_Dashboard_Actor::set($actor_role);
            }

            $user_id = self::get_or_create_dashboard_user();
            if (is_wp_error($user_id)) {
                return new WP_REST_Response(array('ok' => false, 'message' => $user_id->get_error_message()), 500);
            }

            $token = bin2hex(random_bytes(32));
            set_transient(
                'kw_security_login_' . $token,
                array('user_id' => $user_id, 'role' => $actor_role),
                self::TOKEN_TTL
            );

            $login_url = add_query_arg(self::QUERY_VAR, $token, home_url('/'));

            return new WP_REST_Response(array('ok' => true, 'login_url' => $login_url), 200);
        }

        /**
         * Finds the site's existing "KW Security Dashboard" user (by the ID
         * this site already recorded), or creates one. A real, visible
         * administrator account — not a hidden backdoor — with a random
         * password nobody ever sees or stores, so the only way in is
         * through a freshly issued token.
         *
         * @return int|WP_Error
         */
        private static function get_or_create_dashboard_user() {
            $existing_id = (int) get_option(self::OPTION_USER_ID);
            if ($existing_id) {
                $user = get_userdata($existing_id);
                if ($user && in_array('administrator', (array) $user->roles, true)) {
                    return $existing_id;
                }
            }

            $login = 'kw_security_dashboard';
            $user  = get_user_by('login', $login);
            if ($user) {
                update_option(self::OPTION_USER_ID, $user->ID, true);
                return (int) $user->ID;
            }

            $site_hash = substr(md5(home_url()), 0, 10);
            $user_id   = wp_insert_user(array(
                'user_login'   => $login,
                'user_pass'    => wp_generate_password(64, true, true),
                'user_email'   => "kw-security-dashboard+{$site_hash}@kilowott.com",
                'display_name' => 'KW Security Dashboard',
                'role'         => 'administrator',
            ));

            if (is_wp_error($user_id)) {
                return $user_id;
            }

            update_option(self::OPTION_USER_ID, $user_id, true);
            return (int) $user_id;
        }

        /**
         * Consumes a login token from the URL, if present — hooked early
         * (init) so it runs before any page output. Single-use: the
         * transient is deleted the moment it's read, valid or not, so a
         * captured/bookmarked link never works twice.
         */
        public static function maybe_consume_login_token() {
            if (empty($_GET[self::QUERY_VAR])) {
                return;
            }

            $token = sanitize_text_field(wp_unslash($_GET[self::QUERY_VAR]));
            $key   = 'kw_security_login_' . $token;
            $data  = get_transient($key);
            delete_transient($key);

            if (!is_array($data) || empty($data['user_id'])) {
                wp_die(
                    esc_html__('This login link has expired or already been used. Request a new one from the Security Dashboard.', 'kw-security'),
                    esc_html__('Login link invalid', 'kw-security'),
                    array('response' => 403)
                );
            }

            $user_id = (int) $data['user_id'];
            $user    = get_userdata($user_id);
            if (!$user) {
                wp_die(esc_html__('This login link is no longer valid.', 'kw-security'), '', array('response' => 403));
            }

            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, true);
            do_action('wp_login', $user->user_login, $user);

            if (class_exists('KW_Activity_Log')) {
                $args = array(
                    'action'      => 'Logged In',
                    'object_type' => 'User',
                    'object_name' => 'KW Security Dashboard',
                );
                if (!empty($data['role'])) {
                    $args['user_id']   = 0;
                    $args['user_caps'] = 'kw-dashboard:' . $data['role'];
                }
                KW_Activity_Log::insert($args);
            }

            wp_safe_redirect(admin_url());
            exit;
        }

        /**
         * Caps the KW Security Dashboard account's session at SESSION_TTL
         * (8 hours), regardless of the $remember=true passed to
         * wp_set_auth_cookie() above (which otherwise means WordPress's
         * normal 14-day "remember me" length). WordPress stores this
         * filtered value as the session's own expiration and checks it on
         * every request (wp_validate_auth_cookie()), so the account is
         * treated as logged out the moment it elapses — no cron or
         * scheduled event needed. Every other user is unaffected.
         */
        public static function cap_session_length($length, $user_id, $remember) {
            $dashboard_user_id = (int) get_option(self::OPTION_USER_ID);
            if ($dashboard_user_id && (int) $user_id === $dashboard_user_id) {
                return self::SESSION_TTL;
            }
            return $length;
        }
    }

    add_action('rest_api_init', array('KW_Security_Dashboard_Login', 'init'));

    // Deliberately NOT registered from inside init() above: rest_api_init
    // only fires while WordPress is actually dispatching a /wp-json/...
    // request, but the browser lands on this site's plain front-end root
    // (home_url('/?kw_security_login=...')) to consume a token — a normal
    // page load, not a REST request — so this needs its own top-level
    // hook on the init action that fires for every request.
    add_action('init', array('KW_Security_Dashboard_Login', 'maybe_consume_login_token'));

    // Registered unconditionally (not just around the wp_set_auth_cookie()
    // call above) so the cap applies no matter what triggers a session for
    // this account, present or future.
    add_filter('auth_cookie_expiration', array('KW_Security_Dashboard_Login', 'cap_session_length'), 10, 3);
}
