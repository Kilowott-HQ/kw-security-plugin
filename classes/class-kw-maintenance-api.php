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

        // wordfence.blocked_bots — recent blocked bot requests from wfHits.
        const BLOCKED_BOTS_LIMIT     = 50;  // default row cap (override via ?blocked_limit)
        const BLOCKED_BOTS_LIMIT_MAX = 200; // hard ceiling for the override
        const BLOCKED_BOTS_UA_MAX    = 256; // user_agent truncation length
        const BLOCKED_BOTS_PAGE_MAX  = 512; // page path truncation length

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
            return new WP_REST_Response( self::build_response( $request ), 200 );
        }

        private static function build_response( WP_REST_Request $request = null ) {
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
            $wf_blocked_bots  = array();  // recent blocked bot requests (see build_blocked_bots)

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

                // ── Recent blocked bot requests (Live Traffic) ───────────
                // Separate subsystem from the scanner above — read from wfHits
                // and filtered to blocked + bot, wrapped in its own error
                // handling so a wfHits failure never affects the scan data.
                $blocked_limit = self::BLOCKED_BOTS_LIMIT;
                if ( $request instanceof WP_REST_Request ) {
                    $requested = (int) $request->get_param( 'blocked_limit' );
                    if ( $requested > 0 ) {
                        $blocked_limit = min( $requested, self::BLOCKED_BOTS_LIMIT_MAX );
                    }
                }

                $bb = self::build_blocked_bots( $blocked_limit );
                if ( is_array( $bb ) && ! empty( $bb['error'] ) ) {
                    // wfHits read failed — expose via api_error (only if the scan
                    // read didn't already set one). blocked_bots stays [] (never null).
                    if ( null === $wf_api_error ) {
                        $wf_api_error = $bb['error'];
                    }
                    error_log( '[kw-maintenance-api] wfHits blocked_bots read error: ' . $bb['error'] );
                } elseif ( is_array( $bb ) ) {
                    $wf_blocked_bots = $bb['data'];
                }
            }

            $wordfence = array(
                'plugin_active'        => $wf_active,
                'last_scan'            => $wf_last_scan,
                'threats'              => $wf_threats,
                'threat_count'         => $wf_threat_count,
                'severe_threat_count'  => $wf_severe_count,
                'api_error'            => $wf_api_error,
                'blocked_bots'         => $wf_blocked_bots,
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

        /**
         * Build wordfence.blocked_bots — recent requests that Wordfence both
         * BLOCKED and classified as a BOT (not human), newest first.
         *
         * Source: {$base_prefix}wfhits (the table backing Live Traffic).
         *
         * Blocked filter mirrors Wordfence's own wfLiveTrafficQuery (wfLog.php):
         *   (statusCode = 403 OR statusCode = 503)
         *   AND action NOT IN ('logged:waf','scan:detectproxy')
         *
         * Bot classification mirrors Wordfence's Live Traffic human/bot split:
         *   - jsRun = 1 (ran the JS beacon, or a known-human IP/UA) → human, excluded.
         *   - isGoogle = 1 → verified crawler → bot.
         *   - jsRun = 0 with full logging on (wfConfig::liveTrafficEnabled()) → bot.
         *   - jsRun = 0 in security-only mode → refine via wfBrowscap exactly like
         *     Wordfence's delayed filtering: bot iff the UA is a recognised crawler,
         *     human iff a recognised browser, bot if the UA is unrecognised.
         * Because a blocked request is answered before the JS beacon can run, most
         * blocked hits have jsRun = 0; browscap is what separates blocked bots from
         * blocked humans — keeping legitimate visitors' PII out of the list.
         *
         * We fetch the newest blocked hits, drop humans, then cap at $limit. The
         * pool is over-fetched a little so human rows don't shrink the result below
         * the cap; capped by a hard ceiling to bound per-request work.
         *
         * @param int $limit Row cap (already clamped by the caller).
         * @return array { 'data' => array, 'error' => string|null }  ('data' is [] on failure)
         */
        private static function build_blocked_bots( $limit ) {
            global $wpdb;

            $limit = max( 1, (int) $limit );
            $tbl   = $wpdb->base_prefix . 'wfhits';

            try {
                $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $tbl ) );
                if ( $exists !== $tbl ) {
                    return array( 'data' => array(), 'error' => 'wfhits table not found' );
                }

                // Over-fetch so human rows removed below don't drop us under the cap.
                $pool = min( $limit * 4, 800 );

                $rows = $wpdb->get_results( $wpdb->prepare(
                    "SELECT HEX(IP) AS ip_hex, ctime, statusCode, jsRun, isGoogle,
                            URL, UA, action, actionDescription
                       FROM `{$tbl}`
                      WHERE ( statusCode = 403 OR statusCode = 503 )
                        AND action NOT IN ( 'logged:waf', 'scan:detectproxy' )
                      ORDER BY ctime DESC
                      LIMIT %d",
                    $pool
                ) );

                if ( $wpdb->last_error ) {
                    return array( 'data' => array(), 'error' => 'wfhits query failed: ' . $wpdb->last_error );
                }

                // Wordfence classification context (all best-effort / guarded).
                $lt_enabled = class_exists( 'wfConfig' ) && wfConfig::liveTrafficEnabled();
                $browscap   = null;
                if ( class_exists( 'wfBrowscap' ) && method_exists( 'wfBrowscap', 'shared' ) ) {
                    try {
                        $browscap = wfBrowscap::shared();
                    } catch ( \Throwable $e ) {
                        $browscap = null;
                    }
                }
                $now = time();

                $bots = array();
                if ( is_array( $rows ) ) {
                    foreach ( $rows as $row ) {
                        if ( count( $bots ) >= $limit ) {
                            break;
                        }

                        $is_google = ! empty( $row->isGoogle ) && '0' !== (string) $row->isGoogle;

                        // Faithful to Wordfence: with full logging, a jsRun=0 hit is
                        // only a crawler once >30s old (a browser may not have run the
                        // beacon yet). Moot for a daily poll but kept for parity.
                        if ( $lt_enabled && ! $is_google && ( $now - (float) $row->ctime ) <= 30 ) {
                            continue;
                        }

                        if ( ! self::hit_is_bot( $row, $is_google, $lt_enabled, $browscap ) ) {
                            continue; // human — excluded (PII intent)
                        }

                        $ip = self::ip_from_hex( $row->ip_hex );

                        $bots[] = array(
                            'type'       => $is_google ? 'google' : 'bot',
                            'reason'     => self::block_reason( (string) $row->action, (string) $row->actionDescription ),
                            'location'   => self::ip_location( $ip ),
                            'page'       => self::sanitize_page( $row->URL ),
                            'blocked_at' => gmdate( 'c', (int) $row->ctime ),
                            'ip'         => ( '' !== $ip ? $ip : null ),
                            'hostname'   => self::cached_hostname( $row->ip_hex ),
                            'response'   => isset( $row->statusCode ) ? (int) $row->statusCode : null,
                            'user_agent' => self::truncate_ua( $row->UA ),
                        );
                    }
                }

                return array( 'data' => $bots, 'error' => null );
            } catch ( \Throwable $e ) {
                return array( 'data' => array(), 'error' => $e->getMessage() );
            }
        }

        /**
         * Decide whether a wfHits row is a bot (not human), mirroring Wordfence's
         * own Live Traffic classification. See build_blocked_bots() for the rules.
         */
        private static function hit_is_bot( $row, $is_google, $lt_enabled, $browscap ) {
            if ( $is_google ) {
                return true;
            }
            // jsRun truthy → ran the JS beacon or a known-human IP/UA → human.
            if ( ! empty( $row->jsRun ) && '0' !== (string) $row->jsRun ) {
                return false;
            }
            // Full-logging mode: jsRun = 0 is authoritative → crawler.
            if ( $lt_enabled ) {
                return true;
            }
            // Security-only mode: refine via browscap (as Wordfence does).
            $ua = isset( $row->UA ) ? (string) $row->UA : '';
            if ( $browscap && '' !== $ua ) {
                try {
                    $b = $browscap->getBrowser( $ua );
                } catch ( \Throwable $e ) {
                    $b = null;
                }
                if ( is_array( $b ) && isset( $b['Parent'] ) && 'DefaultProperties' !== $b['Parent'] ) {
                    return ! empty( $b['Crawler'] ); // recognised: bot iff crawler
                }
            }
            // Unrecognised UA / no browscap → treat as bot (Wordfence keeps it in
            // the crawler list rather than reclassifying it as human).
            return true;
        }

        /**
         * Normalise a wfHits action into a fixed reason set:
         * firewall | country | bruteforce | other.
         *
         *   firewall   ← blocked:waf, blocked:waf-always, blocked:wfsn, blocked:wfsnrepeat
         *   bruteforce ← lockedOut
         *   country    ← blocked:wordfence / cbl:redirect whose description names a country block
         *   bruteforce ← blocked:wordfence whose description names a login/brute-force block
         *   other      ← everything else (incl. generic/manual/rate-limit blocked:wordfence)
         *
         * blocked:wordfence is Wordfence's catch-all block action; country vs
         * brute-force is teased apart from actionDescription (best-effort, locale
         * dependent), otherwise it falls through to 'other'.
         */
        private static function block_reason( $action, $description ) {
            if ( 0 === strpos( $action, 'blocked:waf' ) ) {
                return 'firewall';
            }
            if ( 'blocked:wfsn' === $action || 'blocked:wfsnrepeat' === $action ) {
                return 'firewall';
            }
            if ( 'lockedOut' === $action ) {
                return 'bruteforce';
            }

            $desc = strtolower( (string) $description );
            if ( 'cbl:redirect' === $action ) {
                return 'country';
            }
            if ( 'blocked:wordfence' === $action ) {
                if ( false !== strpos( $desc, 'country' ) ) {
                    return 'country';
                }
                if ( false !== strpos( $desc, 'brute' ) || false !== strpos( $desc, 'login' ) ) {
                    return 'bruteforce';
                }
            }
            return 'other';
        }

        /**
         * Country lookup via Wordfence's bundled (local) GeoIP database — no
         * external calls. City is never available (country-level DB). Any failure
         * yields all-null sub-keys.
         */
        private static function ip_location( $ip ) {
            $loc = array( 'country_code' => null, 'country_name' => null, 'city' => null );
            if ( '' === $ip || ! class_exists( 'wfUtils' ) ) {
                return $loc;
            }
            try {
                if ( method_exists( 'wfUtils', 'IP2Country' ) ) {
                    $code = wfUtils::IP2Country( $ip );
                    if ( is_string( $code ) && '' !== $code ) {
                        $loc['country_code'] = strtoupper( $code );
                        if ( method_exists( 'wfUtils', 'countryCode2Name' ) ) {
                            $name = wfUtils::countryCode2Name( $code );
                            if ( is_string( $name ) && '' !== $name ) {
                                $loc['country_name'] = $name;
                            }
                        }
                    }
                }
            } catch ( \Throwable $e ) {
                // leave nulls
            }
            return $loc;
        }

        /**
         * Reverse-DNS hostname from Wordfence's cache ONLY — never triggers a live
         * lookup. Returns null on cache miss / 'NONE' / any failure.
         */
        private static function cached_hostname( $ip_hex ) {
            global $wpdb;
            $tbl = $wpdb->base_prefix . 'wfreversecache';
            try {
                $host = $wpdb->get_var( $wpdb->prepare(
                    "SELECT host FROM `{$tbl}` WHERE HEX(IP) = %s",
                    (string) $ip_hex
                ) );
                if ( $wpdb->last_error || ! is_string( $host ) ) {
                    return null;
                }
                $host = trim( $host );
                if ( '' === $host || 'NONE' === $host ) {
                    return null;
                }
                return $host;
            } catch ( \Throwable $e ) {
                return null;
            }
        }

        /**
         * Sanitise the requested page: keep the path only (drop query string and
         * fragment — avoids logging tokens/PII in query params), truncate to
         * BLOCKED_BOTS_PAGE_MAX. Returns null if empty.
         */
        private static function sanitize_page( $url ) {
            $path = (string) $url;
            if ( '' === $path ) {
                return null;
            }
            $cut = strcspn( $path, '?#' ); // first '?' or '#'
            $path = substr( $path, 0, $cut );
            if ( '' === $path ) {
                return null;
            }
            if ( strlen( $path ) > self::BLOCKED_BOTS_PAGE_MAX ) {
                $path = substr( $path, 0, self::BLOCKED_BOTS_PAGE_MAX );
            }
            return $path;
        }

        /**
         * Truncate the user agent to BLOCKED_BOTS_UA_MAX. Returns null if empty.
         */
        private static function truncate_ua( $ua ) {
            $ua = (string) $ua;
            if ( '' === $ua ) {
                return null;
            }
            if ( strlen( $ua ) > self::BLOCKED_BOTS_UA_MAX ) {
                $ua = substr( $ua, 0, self::BLOCKED_BOTS_UA_MAX );
            }
            return $ua;
        }

        /**
         * Convert a HEX(IP) value (16-byte binary, IPv4-mapped-IPv6 for IPv4) to a
         * printable address. Prefers Wordfence's normaliser; falls back to inet_ntop.
         */
        private static function ip_from_hex( $hex ) {
            $bin = @hex2bin( (string) $hex ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            if ( false === $bin || '' === $bin ) {
                return '';
            }
            if ( class_exists( 'wfUtils' ) && method_exists( 'wfUtils', 'inet_ntop' ) ) {
                $ip = @wfUtils::inet_ntop( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                if ( is_string( $ip ) && '' !== $ip ) {
                    return $ip;
                }
            }
            $ip = @inet_ntop( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            if ( ! is_string( $ip ) ) {
                return '';
            }
            if ( 0 === strpos( $ip, '::ffff:' ) && false !== strpos( $ip, '.' ) ) {
                $ip = substr( $ip, 7 );
            }
            return $ip;
        }

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
