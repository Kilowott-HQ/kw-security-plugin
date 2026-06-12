<?php
/**
 * KW Security – Maintenance API
 *
 * Registers GET /wp-json/kw-security/v1/site-status
 *
 * Used by the Kilowott maintenance-agent to fetch WordPress version,
 * PHP version, and plugin update status without requiring a per-user
 * Application Password.
 *
 * Auth: Authorization: Bearer <key>  (key stored in kw_maintenance_key option)
 * Security layers:
 *   1. Key compared via hash_equals() — timing-safe, no enumeration.
 *   2. HTTPS enforced on sites whose home URL is https://.
 *   3. Rate limited to 20 requests/hour per IP using WP transients.
 *   4. Read-only — GET only, no writes.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Maintenance_API' ) ) {

    class KW_Maintenance_API {

        const OPTION_KEY    = 'kw_maintenance_key';
        const API_NAMESPACE = 'kw-security/v1';
        const ROUTE         = '/site-status';
        const ROUTE_SET_KEY = '/set-key';
        const RATE_LIMIT    = 20;
        const RATE_WINDOW   = 3600;
        const KEY_TS_WINDOW = 300; // seconds — reject deliveries older than 5 min

        // PHP support status — update annually.
        // supported = current stable, active support.
        // outdated  = security-only support, upgrade recommended.
        // eol       = no patches at all, upgrade urgently.
        // Last reviewed: June 2026. Next review: Jan 2027.
        private static $php_supported = array( '8.4' );
        private static $php_outdated  = array( '8.3', '8.2' );
        // 8.1 and below are eol

        // ----------------------------------------------------------------
        // Bootstrap
        // ----------------------------------------------------------------

        public static function init() {
            register_rest_route( self::API_NAMESPACE, self::ROUTE, array(
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => array( __CLASS__, 'handle' ),
                'permission_callback' => array( __CLASS__, 'authenticate' ),
            ) );
        }

        // Registered unconditionally — needed to receive the initial key delivery
        // before maintenance_api is enabled. RSA verification (not the stored key)
        // protects this endpoint.
        public static function init_set_key() {
            register_rest_route( self::API_NAMESPACE, self::ROUTE_SET_KEY, array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( __CLASS__, 'handle_set_key' ),
                'permission_callback' => '__return_true',
            ) );
        }

        public static function handle_set_key( WP_REST_Request $request ) {
            $key = sanitize_text_field( $request->get_param( 'key' ) );
            $sig = $request->get_param( 'sig' );  // base64-encoded RSA signature
            $ts  = (int) $request->get_param( 'ts' );

            if ( ! $key || ! $sig || ! $ts ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            // Reject stale deliveries — prevents replay attacks.
            if ( abs( time() - $ts ) > self::KEY_TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            // Verify RSA-2048 / SHA-256 signature from the Kilowott scanner.
            // KW_DELIVERY_PUBLIC_KEY is the scanner's public key (safe to ship publicly).
            if ( ! defined( 'KW_DELIVERY_PUBLIC_KEY' ) ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }
            $message   = $key . '|' . (string) $ts;
            $sig_bytes = base64_decode( $sig, true );
            if ( false === $sig_bytes ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }
            $pub = openssl_get_publickey( KW_DELIVERY_PUBLIC_KEY );
            if ( false === $pub || 1 !== openssl_verify( $message, $sig_bytes, $pub, OPENSSL_ALGO_SHA256 ) ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            // Signature valid — store the per-site key.
            update_option( self::OPTION_KEY, $key, false );

            return new WP_REST_Response( array( 'ok' => true ), 200 );
        }


        // ----------------------------------------------------------------
        // Auth + security checks (permission_callback)
        // ----------------------------------------------------------------

        public static function authenticate( WP_REST_Request $request ) {
            // 1. HTTPS — only enforce if the site itself is on https.
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error(
                    'https_required',
                    'This endpoint requires HTTPS.',
                    array( 'status' => 403 )
                );
            }

            // 2. Rate limiting — 20 requests per hour per hashed IP.
            $ip      = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
            $ip_hash = sha1( $ip . wp_salt() );
            $rl_key  = 'kw_maint_rl_' . substr( $ip_hash, 0, 16 );
            $count   = (int) get_transient( $rl_key );

            if ( $count >= self::RATE_LIMIT ) {
                return new WP_Error(
                    'rate_limited',
                    'Too many requests.',
                    array( 'status' => 429 )
                );
            }
            set_transient( $rl_key, $count + 1, self::RATE_WINDOW );

            // 3. Key check — intentionally vague errors to prevent enumeration.
            $stored_key = get_option( self::OPTION_KEY, '' );
            if ( ! $stored_key ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            $auth_header = $request->get_header( 'authorization' );
            if ( ! $auth_header || strpos( $auth_header, 'Bearer ' ) !== 0 ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            $provided_key = substr( $auth_header, 7 );
            if ( ! hash_equals( $stored_key, $provided_key ) ) {
                return new WP_Error(
                    'forbidden',
                    'Forbidden.',
                    array( 'status' => 403 )
                );
            }

            return true;
        }

        // ----------------------------------------------------------------
        // Response handler
        // ----------------------------------------------------------------

        public static function handle( WP_REST_Request $request ) {
            return new WP_REST_Response( self::build_response(), 200 );
        }

        private static function build_response() {
            // Load admin includes not available outside wp-admin context.
            if ( ! function_exists( 'get_core_updates' ) ) {
                require_once ABSPATH . 'wp-admin/includes/update.php';
            }
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            // ── WordPress core ───────────────────────────────────────────
            $wp_version       = get_bloginfo( 'version' );
            $wp_latest        = $wp_version;
            $wp_update_needed = false;

            $core_updates = get_core_updates();
            if ( is_array( $core_updates ) ) {
                foreach ( $core_updates as $update ) {
                    if (
                        isset( $update->response, $update->version ) &&
                        $update->response === 'upgrade'
                    ) {
                        $wp_latest        = $update->version;
                        $wp_update_needed = true;
                        break;
                    }
                }
            }

            // ── PHP ──────────────────────────────────────────────────────
            $php_version = PHP_VERSION;
            $php_status  = self::classify_php( $php_version );

            // ── Plugins ──────────────────────────────────────────────────
            if ( ! function_exists( 'is_plugin_active' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all_plugins      = get_plugins();
            $update_transient = get_site_transient( 'update_plugins' );
            // Transient may not exist yet if WP hasn't run an update check.
            $update_response  = ( $update_transient && isset( $update_transient->response ) )
                ? $update_transient->response
                : array();
            $plugins          = array();

            foreach ( $all_plugins as $plugin_file => $plugin_data ) {
                $slug = dirname( $plugin_file );
                if ( '.' === $slug ) {
                    $slug = basename( $plugin_file, '.php' );
                }
                $installed_ver    = isset( $plugin_data['Version'] ) ? $plugin_data['Version'] : '';
                $latest_ver       = $installed_ver;
                $update_available = false;
                $is_security      = false;

                if ( isset( $update_response[ $plugin_file ]->new_version ) ) {
                    $update_obj       = $update_response[ $plugin_file ];
                    $latest_ver       = $update_obj->new_version;
                    $update_available = ( $latest_ver !== $installed_ver );

                    if ( $update_available && ! empty( $update_obj->upgrade_notice ) ) {
                        $is_security = (bool) preg_match(
                            '/security|vulnerability|critical/i',
                            wp_strip_all_tags( $update_obj->upgrade_notice )
                        );
                    }
                }

                $plugins[] = array(
                    'name'               => isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug,
                    'slug'               => $slug,
                    'version'            => $installed_ver,
                    'latest'             => $latest_ver,
                    'update_available'   => $update_available,
                    'is_security_update' => $is_security,
                    'active'             => is_plugin_active( $plugin_file ),
                );
            }

            // ── KW Security file integrity ───────────────────────────────
            $fi_last_scan   = (int) get_option( KW_File_Integrity::OPTION_LAST, 0 );
            $fi_enabled     = KW_Security_Settings::is_enabled( 'file_integrity' );
            $unknown_files  = array();
            $modified_files = array();

            if ( $fi_enabled && class_exists( 'KW_File_Integrity' ) ) {
                // Scan ABSPATH root for unknown executable files.
                $entries = @scandir( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                if ( is_array( $entries ) ) {
                    foreach ( $entries as $name ) {
                        if ( '.' === $name || '..' === $name ) continue;
                        if ( ! is_file( ABSPATH . $name ) ) continue;
                        if ( in_array( $name, KW_File_Integrity::KNOWN_ROOT_FILES, true ) ) continue;
                        $ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
                        if ( in_array( $ext, KW_File_Integrity::SUSPICIOUS_EXTENSIONS, true ) ) {
                            $unknown_files[] = $name;
                        }
                    }
                }

                // Detect modified tracked files against stored baseline.
                $baseline = get_option( KW_File_Integrity::OPTION_HASHES, array() );
                if ( is_array( $baseline ) ) {
                    foreach ( KW_File_Integrity::HASHED_FILES as $tracked ) {
                        $full = ABSPATH . $tracked;
                        if ( file_exists( $full ) && isset( $baseline[ $tracked ] ) ) {
                            $hash = @sha1_file( $full ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                            if ( false !== $hash && $hash !== $baseline[ $tracked ] ) {
                                $modified_files[] = $tracked;
                            }
                        }
                    }
                }
            }

            $features = wp_parse_args(
                get_option( KW_Security_Settings::OPTION_NAME, array() ),
                KW_Security_Settings::get_defaults()
            );

            $kw_security = array(
                'plugin_version'         => KW_SECURITY_VERSION,
                'file_integrity_enabled' => $fi_enabled,
                'last_scan'              => $fi_last_scan ? gmdate( 'c', $fi_last_scan ) : null,
                'unknown_files'          => $unknown_files,
                'modified_files'         => $modified_files,
                'threat_count'           => count( $unknown_files ) + count( $modified_files ),
                'features_enabled'       => array_keys( array_filter( $features ) ),
            );

            // ── Wordfence (via plugin's own class API) ───────────────────
            //
            // Uses wfConfig::get() and wfIssues::shared() rather than raw
            // SQL so Wordfence's own schema changes are handled internally.
            //
            // Severity constants (stable across v7 + v8):
            //   SEVERITY_CRITICAL = 100, SEVERITY_HIGH = 75, SEVERITY_MEDIUM = 50
            //   SEVERITY_LOW = 25, SEVERITY_NONE = 0
            //
            // Status strings (stable across v7 + v8):
            //   'new' | 'ignoreP' | 'ignoreC'
            //
            // If wfIssues API changes in a future version the catch() below
            // sets wf_api_error so the scanner logs a visible warning instead
            // of silently showing zero threats.
            if ( ! function_exists( 'is_plugin_active' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            $wf_active        = is_plugin_active( 'wordfence/wordfence.php' );
            $wf_last_scan     = null;
            $wf_threats       = array();
            $wf_threat_count  = 0;
            $wf_severe_count  = 0;  // actual malware / backdoors / compromised files
            $wf_api_error     = null;

            if ( $wf_active ) {
                // Severity: Wordfence uses 0/25/50/75/100 — map to our labels.
                // Plugin/theme upgrade notices inherit their Wordfence severity.
                // Actual compromise types (malware, backdoors, modified core files)
                // are escalated to 'severe' regardless of Wordfence's numeric level.
                $severity_map = array(
                    100 => 'critical',
                    75  => 'high',
                    50  => 'medium',
                );

                // Types that indicate an active site compromise — always 'severe'.
                $severe_types = array(
                    'INFECTED_FILE',
                    'BACKDOOR',
                    'BACKDOOR_OBFUSCATED',
                    'FILE_CHANGED',
                    'UNKNOWN_FILE',
                );

                try {
                    // ── Last scan time via wfConfig ──────────────────────
                    // 'wf_scanLastStatusTime' is set by wfIssues::updateScanStillRunning()
                    // on every scan tick — confirmed present in both v7.4 and v8.2.
                    if ( class_exists( 'wfConfig' ) ) {
                        $ts = (int) wfConfig::get( 'wf_scanLastStatusTime', 0 );
                        if ( $ts > 0 ) {
                            $wf_last_scan = gmdate( 'c', $ts );
                        }
                    }

                    // ── Issues via wfIssues::shared() ───────────────────
                    // getIssues() return shape is stable across v7 + v8:
                    //   array( 'new' => [ [...issue], ... ], 'ignored' => [...] )
                    // Each issue is an array; 'data' is already unserialized.
                    // Pass ignoredLimit = 0 to skip fetching ignored issues.
                    if ( class_exists( 'wfIssues' ) && method_exists( 'wfIssues', 'shared' ) ) {
                        $wf_obj     = wfIssues::shared();
                        $result     = $wf_obj->getIssues( 0, 100, 0, 0 );
                        $new_issues = isset( $result['new'] ) ? (array) $result['new'] : array();

                        foreach ( $new_issues as $issue ) {
                            $sev_int  = (int) ( isset( $issue['severity'] ) ? $issue['severity'] : 0 );
                            $iss_type = isset( $issue['type'] ) ? $issue['type'] : '';

                            // Actual compromise types override Wordfence's numeric severity.
                            if ( in_array( $iss_type, $severe_types, true ) ) {
                                $sev_str = 'severe';
                            } elseif ( isset( $severity_map[ $sev_int ] ) ) {
                                $sev_str = $severity_map[ $sev_int ];
                            } else {
                                // Skip low (25) and info/none (0) — too noisy for dashboard.
                                continue;
                            }

                            // 'data' is already unserialized by getIssues().
                            // v8 _hydrateIssue() prefers 'realFile'; v7 uses 'file'.
                            $data = isset( $issue['data'] ) && is_array( $issue['data'] )
                                ? $issue['data']
                                : array();

                            $file = '';
                            if ( ! empty( $data['realFile'] ) ) {
                                $file = $data['realFile'];
                            } elseif ( ! empty( $data['file'] ) ) {
                                $file = $data['file'];
                            } elseif ( ! empty( $data['filename'] ) ) {
                                $file = $data['filename'];
                            }

                            $wf_threats[] = array(
                                'id'          => 'wf-' . ( isset( $issue['id'] ) ? $issue['id'] : uniqid() ),
                                'severity'    => $sev_str,
                                'type'        => isset( $issue['type'] ) ? $issue['type'] : 'UNKNOWN',
                                'description' => isset( $issue['shortMsg'] ) ? $issue['shortMsg'] : '',
                                'file'        => $file,
                                'status'      => 'new',
                            );
                            $wf_threat_count++;
                            if ( 'severe' === $sev_str ) {
                                $wf_severe_count++;
                            }
                        }

                        // Fallback: if wf_scanLastStatusTime was 0 (scan complete
                        // but status ticker already cleared) derive time from the
                        // most recently updated issue instead.
                        if ( ! $wf_last_scan && method_exists( $wf_obj, 'getLastIssueUpdateTimestamp' ) ) {
                            $last_ts = (int) $wf_obj->getLastIssueUpdateTimestamp();
                            if ( $last_ts > 0 ) {
                                $wf_last_scan = gmdate( 'c', $last_ts );
                            }
                        }
                    }
                } catch ( \Throwable $e ) {
                    // Wordfence API changed — surface the error so the scanner
                    // logs a visible warning rather than silently showing zero threats.
                    $wf_api_error = $e->getMessage();
                    error_log( '[kw-maintenance-api] wfIssues API error: ' . $e->getMessage() );
                }
            }

            $wordfence = array(
                'plugin_active'        => $wf_active,
                'last_scan'            => $wf_last_scan,
                'threats'              => $wf_threats,
                'threat_count'         => $wf_threat_count,
                'severe_threat_count'  => $wf_severe_count,
                'api_error'            => $wf_api_error,
            );

            return array(
                'wp_version'       => $wp_version,
                'wp_latest'        => $wp_latest,
                'wp_update_needed' => $wp_update_needed,
                'php_version'      => $php_version,
                'php_status'       => $php_status,
                'plugins'          => $plugins,
                'kw_security'      => $kw_security,
                'wordfence'        => $wordfence,
            );
        }

        // ----------------------------------------------------------------
        // Helpers
        // ----------------------------------------------------------------

        private static function classify_php( $version ) {
            $minor = implode( '.', array_slice( explode( '.', $version ), 0, 2 ) );
            if ( in_array( $minor, self::$php_supported, true ) ) return 'supported';
            if ( in_array( $minor, self::$php_outdated, true ) )  return 'outdated';
            return 'eol';
        }
    }

    if ( KW_Security_Settings::is_enabled( 'maintenance_api' ) ) {
        add_action( 'rest_api_init', array( 'KW_Maintenance_API', 'init' ) );
    }

    // set-key is always registered — needed to receive the first key delivery
    // even before the maintenance API feature flag is turned on.
    add_action( 'rest_api_init', array( 'KW_Maintenance_API', 'init_set_key' ) );
}
