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
                //     refs to https:// in the browser; safe on HTTPS-only sites.
                // No default-src/script-src/style-src/etc. are set, so
                // scripts, styles, images, fonts, connections, and embeds
                // remain unrestricted — nothing that loads today will break.
                // To harden per-site, override via the kw_security_headers
                // filter after testing the stricter policy on staging.
                'Content-Security-Policy' => "upgrade-insecure-requests; frame-ancestors 'self'",
            );

            // HSTS only over HTTPS — moderate max-age, no subdomain coverage,
            // no preload, so the policy can be rolled back if needed.
            if ( is_ssl() ) {
                $headers['Strict-Transport-Security'] = 'max-age=15552000';
            }

            return apply_filters( 'kw_security_headers', $headers );
        }

        /**
         * Emit headers via header() for frontend & admin requests.
         */
        public function send_security_headers() {
            if ( headers_sent() ) {
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
