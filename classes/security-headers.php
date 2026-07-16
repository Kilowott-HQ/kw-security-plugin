<?php
/**
 * KW Security – HTTP Security Headers
 *
 * Sends a curated set of HTTP response headers to harden the site against
 * clickjacking, MIME-sniffing, referrer leakage, and the legacy IE/Edge
 * XSS auditor. HSTS is sent only on HTTPS requests with conservative
 * settings (no includeSubDomains, no preload) so it stays reversible.
 *
 * Every header value passes through the `kw_security_headers` filter, so a
 * site can override or remove a specific header without forking the plugin:
 *
 *   add_filter( 'kw_security_headers', function ( $headers ) {
 *       unset( $headers['X-Frame-Options'] );          // disable a header
 *       $headers['Referrer-Policy'] = 'no-referrer';   // override a value
 *       return $headers;
 *   } );
 *
 * IP & URL Whitelisting:
 *
 * Requests from a whitelisted IP address or to an allowed URL bypass
 * security-header enforcement entirely. Configure both lists in
 * Settings → KW Security under "IP & URL Whitelist".
 * CIDR notation is supported for IP ranges (e.g. 192.168.1.0/24).
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Headers' ) ) {

    class KW_Security_Headers {

        public function __construct() {
            // Frontend page loads.
            add_action( 'send_headers', array( $this, 'send_security_headers' ) );

            // Admin pages — send_headers does not fire here.
            add_action( 'admin_init', array( $this, 'send_security_headers' ), 1 );

            // REST API responses — attach headers to the response object.
            add_filter( 'rest_post_dispatch', array( $this, 'rest_security_headers' ), 10, 3 );
        }

        /**
         * Build the active headers array.
         *
         * @return array<string,string>
         */
        private function get_headers() {
            $headers = array(
                'X-Frame-Options'         => 'SAMEORIGIN',
                'X-Content-Type-Options'  => 'nosniff',
                'Referrer-Policy'         => 'strict-origin-when-cross-origin',
                'X-XSS-Protection'        => '0',
                'Permissions-Policy'      => 'interest-cohort=(), browsing-topics=()',
                // Deliberately minimal CSP. Only two directives:
                //   - frame-ancestors 'self' is the modern equivalent of
                //     X-Frame-Options: SAMEORIGIN (clickjacking protection).
                //   - upgrade-insecure-requests auto-rewrites stray http://
                //     refs to https:// in the browser; only safe on HTTPS
                //     sites — omitted on HTTP to avoid breaking asset loads.
                // No default-src/script-src/style-src/etc. are set, so
                // scripts, styles, images, fonts, connections, and embeds
                // remain unrestricted — nothing that loads today will break.
                // To harden per-site, override via the kw_security_headers
                // filter after testing the stricter policy on staging.
                'Content-Security-Policy' => ( is_ssl() ? 'upgrade-insecure-requests; ' : '' ) . "frame-ancestors 'self'",
            );

            // HSTS only over HTTPS — moderate max-age, no subdomain coverage,
            // no preload, so the policy can be rolled back if needed.
            if ( is_ssl() ) {
                $headers['Strict-Transport-Security'] = 'max-age=15552000';
            }

            return apply_filters( 'kw_security_headers', $headers );
        }

        // ----------------------------------------------------------------
        // Whitelist bypass
        // ----------------------------------------------------------------

        /**
         * Return true if the current request should skip security-header
         * enforcement because its client IP is whitelisted or its URL
         * matches an entry in the allowed-URL list.
         *
         * @return bool
         */
        private function is_whitelisted_request() {
            // --- IP whitelist ---
            $whitelisted_ips = get_option( KW_Security_Settings::IP_WHITELIST_OPTION, array() );
            if ( is_array( $whitelisted_ips ) && count( $whitelisted_ips ) > 0 ) {
                $client_ip = $this->get_client_ip();
                if ( $client_ip ) {
                    foreach ( $whitelisted_ips as $entry ) {
                        $entry = trim( (string) $entry );
                        if ( $entry && $this->ip_matches( $client_ip, $entry ) ) {
                            return true;
                        }
                    }
                }
            }

            // --- Allowed-URL list ---
            $allowed_urls = get_option( KW_Security_Settings::URL_WHITELIST_OPTION, array() );
            if ( is_array( $allowed_urls ) && count( $allowed_urls ) > 0 ) {
                $current_url = $this->get_current_url();
                foreach ( $allowed_urls as $allowed ) {
                    $allowed = trim( (string) $allowed );
                    if ( ! $allowed ) {
                        continue;
                    }
                    // Strip trailing wildcard marker; match by URL prefix.
                    $prefix = rtrim( $allowed, '*' );
                    if ( $prefix && strncmp( $current_url, $prefix, strlen( $prefix ) ) === 0 ) {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * Resolve the client IP address.
         *
         * REMOTE_ADDR is the TCP-layer peer address and is authoritative.
         * Forwarded headers (X-Forwarded-For, X-Real-IP) are only trusted
         * when REMOTE_ADDR is a private/loopback address — i.e. the request
         * came through a reverse proxy on the local network. Trusting those
         * headers from any remote IP would allow trivial whitelist bypass.
         *
         * @return string|false A validated IP string, or false on failure.
         */
        private function get_client_ip() {
            $remote = isset( $_SERVER['REMOTE_ADDR'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
                : '';

            if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
                return false;
            }

            // Only honour forwarded headers when the TCP peer is a local proxy.
            $is_local_proxy = ( false === filter_var(
                $remote,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) );

            if ( $is_local_proxy ) {
                $forwarded = '';
                if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
                    // XFF may be a comma-separated chain; leftmost is the original client.
                    $xff_parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
                    $forwarded = trim( $xff_parts[0] );
                } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
                    $forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
                }
                if ( $forwarded && filter_var( $forwarded, FILTER_VALIDATE_IP ) ) {
                    return $forwarded;
                }
            }

            return $remote;
        }

        /**
         * Build the full URL of the current request for allowed-URL matching.
         *
         * REQUEST_URI is used without sanitize_text_field() to preserve query
         * strings and special characters needed for accurate prefix matching.
         *
         * @return string
         */
        private function get_current_url() {
            $scheme = is_ssl() ? 'https' : 'http';
            $host   = isset( $_SERVER['HTTP_HOST'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) )
                : '';
            $uri = isset( $_SERVER['REQUEST_URI'] )
                ? wp_unslash( $_SERVER['REQUEST_URI'] )
                : '';
            return $scheme . '://' . $host . $uri;
        }

        /**
         * Test whether $ip matches $entry (a single IP address or CIDR range).
         *
         * @param string $ip    Validated IPv4 or IPv6 address.
         * @param string $entry Single IP or CIDR string (e.g. "192.168.0.0/24").
         * @return bool
         */
        private function ip_matches( $ip, $entry ) {
            if ( strpos( $entry, '/' ) === false ) {
                return ( $ip === $entry );
            }

            list( $range, $prefix ) = explode( '/', $entry, 2 );
            $prefix = (int) $prefix;

            if ( strpos( $ip, ':' ) !== false ) {
                return $this->ipv6_in_cidr( $ip, $range, $prefix );
            }

            $ip_long    = ip2long( $ip );
            $range_long = ip2long( $range );
            if ( false === $ip_long || false === $range_long || $prefix < 0 || $prefix > 32 ) {
                return false;
            }
            $mask = ( 0 === $prefix ) ? 0 : ( ~0 << ( 32 - $prefix ) );
            return ( ( $ip_long & $mask ) === ( $range_long & $mask ) );
        }

        /**
         * Test whether an IPv6 address falls within a CIDR range.
         *
         * @param string $ip     Client IPv6 address.
         * @param string $range  Network address portion of the CIDR.
         * @param int    $prefix Prefix length (0–128).
         * @return bool
         */
        private function ipv6_in_cidr( $ip, $range, $prefix ) {
            if ( $prefix < 0 || $prefix > 128 ) {
                return false;
            }
            $ip_bin    = inet_pton( $ip );
            $range_bin = inet_pton( $range );
            if ( false === $ip_bin || false === $range_bin ) {
                return false;
            }

            $full_bytes   = (int) floor( $prefix / 8 );
            $partial_bits = $prefix % 8;

            if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $range_bin, 0, $full_bytes ) ) {
                return false;
            }
            if ( $partial_bits > 0 ) {
                $mask = 0xff & ( 0xff << ( 8 - $partial_bits ) );
                if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $range_bin[ $full_bytes ] ) & $mask ) ) {
                    return false;
                }
            }

            return true;
        }

        // ----------------------------------------------------------------
        // Header emission
        // ----------------------------------------------------------------

        /**
         * Emit headers via header() for frontend & admin requests.
         */
        public function send_security_headers() {
            if ( headers_sent() ) {
                return;
            }
            // Skip enforcement for whitelisted IPs and allowed URLs.
            if ( $this->is_whitelisted_request() ) {
                return;
            }
            foreach ( $this->get_headers() as $name => $value ) {
                if ( $value === false || $value === '' || $value === null ) {
                    continue;
                }
                header( sprintf( '%s: %s', $name, $value ) );
            }
        }

        /**
         * Attach headers to REST responses.
         *
         * @param mixed            $result  Response object or other value.
         * @param WP_REST_Server   $server  REST server instance.
         * @param WP_REST_Request  $request The current request.
         * @return mixed
         */
        public function rest_security_headers( $result, $server, $request ) {
            if ( $result instanceof WP_HTTP_Response ) {
                // Skip enforcement for whitelisted IPs and allowed URLs.
                if ( $this->is_whitelisted_request() ) {
                    return $result;
                }
                foreach ( $this->get_headers() as $name => $value ) {
                    if ( $value === false || $value === '' || $value === null ) {
                        continue;
                    }
                    $result->header( $name, $value );
                }
            }
            return $result;
        }
    }

    if ( KW_Security_Settings::is_enabled( 'security_headers' ) ) {
        new KW_Security_Headers();
    }
}
