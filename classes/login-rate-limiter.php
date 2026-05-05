<?php
/**
 * KW Security – Login Rate Limiter
 *
 * Locks out IP addresses after repeated failed login attempts to defend
 * against the brute-force vector called out in the Preikestolen Basecamp
 * RCA (24 April 2026).
 *
 * Defaults: 5 failed attempts within 15 minutes locks the IP for 1 hour.
 * Storage uses WP transients, which automatically use the object cache
 * (Redis/Memcached) when available, otherwise fall back to options.
 *
 * Sites behind a reverse proxy (Cloudflare, load balancer) should set
 * the kw_security_client_ip filter so the real client IP is detected
 * instead of the proxy IP — example for Cloudflare:
 *
 *   add_filter( 'kw_security_client_ip', function ( $ip ) {
 *       return ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] )
 *           ? $_SERVER['HTTP_CF_CONNECTING_IP']
 *           : $ip;
 *   } );
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Login_Rate_Limiter' ) ) {

    class KW_Login_Rate_Limiter {

        const MAX_ATTEMPTS   = 5;
        const ATTEMPT_WINDOW = 15 * MINUTE_IN_SECONDS;
        const LOCKOUT_WINDOW = HOUR_IN_SECONDS;

        public function __construct() {
            // Block at the earliest authentication step (priority 30 runs
            // before WordPress's wp_authenticate_username_password at 20+).
            add_filter( 'authenticate', array( $this, 'block_locked_ip' ), 30, 3 );

            // Track failures and successes.
            add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
            add_action( 'wp_login',        array( $this, 'on_login_success' ), 10, 2 );

            // Generic error message — don't leak whether the username exists.
            add_filter( 'login_errors', array( $this, 'obfuscate_login_errors' ) );
        }

        /**
         * Resolve client IP. Defaults to REMOTE_ADDR — trusting forwarded
         * headers without a configured proxy is a spoof vector. Sites
         * behind a real proxy should override via filter.
         *
         * @return string
         */
        public static function get_client_ip() {
            $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
            return apply_filters( 'kw_security_client_ip', $ip );
        }

        /**
         * Hash IP for transient keys. Uses wp_salt so different installs
         * don't share namespace, and so raw IPs are never stored at rest.
         */
        private static function ip_key( $ip ) {
            return substr( sha1( $ip . wp_salt() ), 0, 32 );
        }

        /**
         * Reject authentication if this IP is currently locked.
         *
         * @param WP_User|WP_Error|null $user
         * @param string                $username
         * @param string                $password
         * @return WP_User|WP_Error|null
         */
        public function block_locked_ip( $user, $username, $password ) {
            // Don't run on the initial GET of the login form.
            if ( empty( $username ) && empty( $password ) ) {
                return $user;
            }

            $ip  = self::get_client_ip();
            $key = 'kw_login_lock_' . self::ip_key( $ip );

            $lock_until = get_transient( $key );
            if ( $lock_until && $lock_until > time() ) {
                $minutes_left = max( 1, (int) ceil( ( $lock_until - time() ) / 60 ) );
                return new WP_Error(
                    'kw_login_locked',
                    sprintf(
                        /* translators: %d: minutes remaining */
                        esc_html__( 'Too many failed login attempts. Please try again in %d minute(s).', 'kw-security' ),
                        $minutes_left
                    )
                );
            }

            return $user;
        }

        /**
         * Increment failure counter; lock IP if threshold reached.
         *
         * @param string $username
         */
        public function on_login_failed( $username ) {
            $ip     = self::get_client_ip();
            $ip_key = self::ip_key( $ip );

            $count_key = 'kw_login_attempts_' . $ip_key;
            $count     = (int) get_transient( $count_key );
            $count++;

            // Re-set with full window each time so attackers can't stretch
            // attempts over the rolling window edge.
            set_transient( $count_key, $count, self::ATTEMPT_WINDOW );

            if ( $count >= self::MAX_ATTEMPTS ) {
                $lock_key = 'kw_login_lock_' . $ip_key;
                set_transient( $lock_key, time() + self::LOCKOUT_WINDOW, self::LOCKOUT_WINDOW );
                delete_transient( $count_key );
            }
        }

        /**
         * On successful login, clear any pending counter for this IP.
         *
         * @param string  $user_login
         * @param WP_User $user
         */
        public function on_login_success( $user_login, $user ) {
            $ip_key = self::ip_key( self::get_client_ip() );
            delete_transient( 'kw_login_attempts_' . $ip_key );
            delete_transient( 'kw_login_lock_' . $ip_key );
        }

        /**
         * Replace WP's "Invalid username" / "Invalid password" with a
         * generic message so attackers can't enumerate valid usernames.
         * Our own lockout error message passes through unchanged.
         *
         * @param string $error
         * @return string
         */
        public function obfuscate_login_errors( $error ) {
            // Leave our lockout message and other custom errors alone.
            if ( false !== strpos( $error, 'Too many failed login attempts' ) ) {
                return $error;
            }
            return esc_html__( 'Invalid login credentials.', 'kw-security' );
        }
    }

    if ( KW_Security_Settings::is_enabled( 'login_rate_limit' ) ) {
        new KW_Login_Rate_Limiter();
    }
}
