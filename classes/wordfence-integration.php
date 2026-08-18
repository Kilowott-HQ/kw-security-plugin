<?php
/**
 * KW Security – Wordfence Integration
 *
 * Read-only bridge that surfaces a summary of Wordfence's own data (firewall
 * blocks, malware/file scan issues, login lockouts) to the Security
 * Dashboard, the same way activity-log.php exposes the KW Security activity
 * log. Nothing here writes to Wordfence's tables or changes its behavior.
 *
 * Wordfence's internal schema (table/column names) is undocumented and has
 * shifted across versions, so every read here is defensive: table existence
 * and column names are checked at runtime rather than assumed, and a
 * missing/renamed table or column degrades that one section to
 * "unavailable" instead of breaking the whole response.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Wordfence_Integration' ) ) {

    class KW_Wordfence_Integration {

        // ----------------------------------------------------------------
        // Dashboard REST API — signed, read-only summary
        // ----------------------------------------------------------------

        const DASHBOARD_API_NAMESPACE = 'kw-security/v1';
        const DASHBOARD_API_ROUTE     = '/wordfence-summary';
        const DASHBOARD_TS_WINDOW     = 300; // seconds — reject stale/replayed requests

        // Same keypair as the plugin's other dashboard-triggered endpoints
        // (update-trigger.php, toggle-feature.php, activity-log.php). Safe to
        // publish — verifies signatures, cannot forge them.
        const DASHBOARD_UPDATE_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjtG3XkYTGtr3YoN5/BgJ
OHXBKcHKaY90xyw/6zxRFTHxVwGGCGqm1MGhcx/9EHHPNKJzBTzFSrzUY46Pc9lE
KWD4CdJnmgDKNzNw5xJR2cjlsVDK+fABDh2GC23XztAc0o/2m0tr57Gm2Ivcnael
vu81LbCfysLRAm6O75s8UawN/UEqpp0eaeMedBzWAB1RBEaDoe4aBPJc2ZQo+uLr
UirIbOYn69OyNWoxqG7AwwoKwXvun6WSONnnRC3btH88D1hKq3oAMALp0zHw8Fkc
Grty7dMqCwbdNKtwr9GL2i7Ve8YrhNCt7uT4NEhbi2JXnXDIqxBQwVumXsJ1taPx
YQIDAQAB
-----END PUBLIC KEY-----';

        public static function init_dashboard_api() {
            register_rest_route( self::DASHBOARD_API_NAMESPACE, self::DASHBOARD_API_ROUTE, array(
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => array( __CLASS__, 'handle_dashboard_request' ),
                'permission_callback' => array( __CLASS__, 'authenticate_dashboard_request' ),
            ) );
        }

        /**
         * Verifies the request came from the dashboard for THIS site,
         * within a short freshness window. Mirrors activity-log.php.
         */
        public static function authenticate_dashboard_request( WP_REST_Request $request ) {
            if ( strpos( home_url(), 'https://' ) === 0 && ! is_ssl() ) {
                return new WP_Error( 'https_required', 'This endpoint requires HTTPS.', array( 'status' => 403 ) );
            }

            $installation_id = sanitize_text_field( (string) $request->get_param( 'installation_id' ) );
            $timestamp        = (int) $request->get_param( 'timestamp' );
            $signature        = (string) $request->get_param( 'signature' );

            if ( ! $installation_id || ! $timestamp || ! $signature ) {
                return new WP_Error( 'bad_request', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( ! class_exists( 'KW_Security_Telemetry' ) || $installation_id !== KW_Security_Telemetry::get_site_id() ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            if ( abs( time() - $timestamp ) > self::DASHBOARD_TS_WINDOW ) {
                return new WP_Error( 'forbidden', 'Forbidden.', array( 'status' => 403 ) );
            }

            $message   = $installation_id . '|wordfence-summary|' . $timestamp;
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

        public static function handle_dashboard_request( WP_REST_Request $request ) {
            if ( ! self::is_wordfence_active() ) {
                return new WP_REST_Response( array( 'ok' => true, 'installed' => false ), 200 );
            }

            global $wpdb;

            return new WP_REST_Response( array(
                'ok'        => true,
                'installed' => true,
                'firewall'  => self::get_firewall_summary( $wpdb ),
                'malware'   => self::get_malware_summary( $wpdb ),
                'login'     => self::get_login_summary( $wpdb ),
                'traffic'   => self::get_traffic_summary( $wpdb ),
            ), 200 );
        }

        // ----------------------------------------------------------------
        // Detection
        // ----------------------------------------------------------------

        private static function is_wordfence_active() {
            if ( defined( 'WORDFENCE_VERSION' ) || class_exists( 'wfConfig' ) ) {
                return true;
            }
            if ( ! function_exists( 'is_plugin_active' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            return is_plugin_active( 'wordfence/wordfence.php' );
        }

        // ----------------------------------------------------------------
        // Schema helpers — defensive access to Wordfence's own tables
        // ----------------------------------------------------------------

        /**
         * Maps lowercased table name => real (as-stored) table name, for
         * every wf*-prefixed table on this site. Confirmed against a real
         * install that MySQL table names can be case-sensitive (depends on
         * the server's lower_case_table_names setting) while Wordfence
         * itself creates tables in all-lowercase — so a literal
         * "SHOW TABLES LIKE 'wfBlockedIPLog'" silently matches nothing on
         * such a server even though the table exists as "wfblockediplog".
         * Resolving through this map sidesteps that regardless of which way
         * a given host's MySQL is configured.
         */
        private static function get_wf_tables_map( $wpdb ) {
            static $map = null;
            if ( null !== $map ) {
                return $map;
            }

            $like = $wpdb->esc_like( $wpdb->prefix . 'wf' ) . '%';
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $like is escaped via esc_like and passed as a bound placeholder value.
            $tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) );

            $map = array();
            foreach ( (array) $tables as $table ) {
                $map[ strtolower( $table ) ] = $table;
            }
            return $map;
        }

        /** Resolves a logical (any-case) table name to its real stored name, or null if it doesn't exist. */
        private static function resolve_table( $wpdb, $logical_name ) {
            $map = self::get_wf_tables_map( $wpdb );
            $key = strtolower( $logical_name );
            return isset( $map[ $key ] ) ? $map[ $key ] : null;
        }

        /** Returns [column_name => column_type] for a table. */
        private static function columns( $wpdb, $table ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name comes from an internal allowlist, not user input.
            $rows = $wpdb->get_results( "SHOW COLUMNS FROM {$table}" );
            $out  = array();
            foreach ( (array) $rows as $row ) {
                $out[ $row->Field ] = $row->Type;
            }
            return $out;
        }

        /** First candidate name that exists in $available (a columns() map), or null. */
        private static function pick_column( $available, $candidates ) {
            foreach ( $candidates as $candidate ) {
                if ( isset( $available[ $candidate ] ) ) {
                    return $candidate;
                }
            }
            return null;
        }

        private static function is_numeric_column_type( $type ) {
            return (bool) preg_match( '/^(int|bigint|smallint|mediumint|tinyint)/i', (string) $type );
        }

        /** Best-effort conversion of a Wordfence-stored IP into a readable string. */
        private static function maybe_decode_ip( $raw ) {
            if ( null === $raw || '' === $raw ) {
                return null;
            }

            $candidate = $raw;
            if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
                // Wordfence has historically stored blocked IPs as packed
                // binary (inet_pton format) rather than a readable string.
                $unpacked = @inet_ntop( $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- tolerate non-binary input from unexpected schema variants.
                if ( false === $unpacked || ! filter_var( $unpacked, FILTER_VALIDATE_IP ) ) {
                    return null;
                }
                $candidate = $unpacked;
            }

            // inet_ntop() renders an IPv4 address stored in a 16-byte (IPv6)
            // column as an IPv4-mapped IPv6 address ("::ffff:9.9.9.9") —
            // confirmed against a real block entry. Unwrap that back down to
            // the plain IPv4 form, which is what Wordfence's own UI shows.
            if ( 0 === strpos( $candidate, '::ffff:' ) ) {
                $v4 = substr( $candidate, 7 );
                if ( filter_var( $v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                    return $v4;
                }
            }

            return $candidate;
        }

        /**
         * Converts a Wordfence timestamp column value into an ISO 8601
         * string, or null if the column is unset. Wordfence uses 0 (not
         * NULL) as "never happened" for several timestamp-ish columns —
         * e.g. a manually-added block's "last attack attempt" stays 0 until
         * the IP is actually seen again — so treat non-positive numeric
         * values as absent rather than rendering them as a 1970 date.
         */
        /**
         * Best-effort Human / Bot / Warning / Blocked bucket for a live
         * traffic hit, mirroring the categories Wordfence's own admin UI
         * uses on its Live Traffic screen. Wordfence doesn't expose a single
         * documented "category" column for this — it derives the label from
         * internal logic this integration can't call directly — so this
         * infers it from the signals that ARE queryable: a verified
         * Googlebot or a hit that never ran Wordfence's human-verification
         * JS reads as a bot; an explicit "block" in the action text or a 403
         * status reads as blocked; a 429 (rate-limited) reads as a warning;
         * anything else with a confirmed JS run reads as human. Returns null
         * (shown as unclassified) rather than guessing when none of these
         * signals are available on a given Wordfence version.
         */
        private static function classify_traffic_hit( $js_run, $is_google, $status_code, $action_text ) {
            $action_text = strtolower( (string) $action_text );

            if ( false !== strpos( $action_text, 'block' ) || 403 === $status_code ) {
                return 'blocked';
            }
            if ( 429 === $status_code ) {
                return 'warning';
            }
            if ( true === $is_google ) {
                return 'bot';
            }
            if ( null !== $js_run ) {
                return $js_run ? 'human' : 'bot';
            }
            return null;
        }

        private static function normalize_timestamp( $value ) {
            if ( is_numeric( $value ) ) {
                return ( (int) $value > 0 ) ? gmdate( 'c', (int) $value ) : null;
            }
            $ts = strtotime( (string) $value );
            return $ts ? gmdate( 'c', $ts ) : null;
        }

        // ----------------------------------------------------------------
        // Firewall & blocked IPs — wfBlocks7 (Wordfence's unified table for
        // every kind of IP block: brute-force lockouts, country blocks,
        // manual blocks, rate-limit blocks, etc. — confirmed against a real
        // install; the older wfBlockedIPLog table is a daily-aggregated
        // stats table without per-block timestamps, not useful here).
        // ----------------------------------------------------------------

        private static function get_firewall_summary( $wpdb ) {
            $table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfBlocks7' );
            if ( ! $table ) {
                return array( 'available' => false );
            }

            try {
                $columns    = self::columns( $wpdb, $table );
                $ip_col     = self::pick_column( $columns, array( 'IP', 'ip' ) );
                // Prefer "when the rule was added" over "last attack
                // attempt" — confirmed against a real block entry that a
                // manually-added rule can sit at lastAttempt=0 indefinitely
                // if the IP never actually gets seen again, which isn't a
                // useful "recent blocks" sort key or display value.
                $time_col   = self::pick_column( $columns, array( 'blockedTime', 'lastAttempt', 'lastBlockTime', 'createdTime', 'ctime' ) );
                $count_col  = self::pick_column( $columns, array( 'blockedHits', 'totalCount', 'count', 'hits' ) );
                $reason_col = self::pick_column( $columns, array( 'reason', 'blockType', 'type', 'action' ) );

                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- fixed internal table name.
                $total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

                $recent = array();
                if ( $ip_col ) {
                    $order = $time_col ? " ORDER BY `{$time_col}` DESC" : '';
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name fixed internally; order column drawn from an internal allowlist.
                    $rows = $wpdb->get_results( "SELECT * FROM {$table}{$order} LIMIT 10" );
                    foreach ( (array) $rows as $row ) {
                        $recent[] = array(
                            'ip'          => self::maybe_decode_ip( $row->{$ip_col} ),
                            'last_block'  => ( $time_col && isset( $row->{$time_col} ) ) ? self::normalize_timestamp( $row->{$time_col} ) : null,
                            'block_count' => ( $count_col && isset( $row->{$count_col} ) ) ? (int) $row->{$count_col} : null,
                            'reason'      => ( $reason_col && isset( $row->{$reason_col} ) ) ? (string) $row->{$reason_col} : null,
                        );
                    }
                }

                return array(
                    'available'     => true,
                    'total_blocked' => $total,
                    'recent'        => $recent,
                );
            } catch ( \Throwable $e ) {
                return array( 'available' => false );
            }
        }

        // ----------------------------------------------------------------
        // Malware / file scan issues — wfIssues
        // ----------------------------------------------------------------

        private static function get_malware_summary( $wpdb ) {
            $table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfIssues' );
            if ( ! $table ) {
                return array( 'available' => false );
            }

            try {
                $columns    = self::columns( $wpdb, $table );
                $status_col = self::pick_column( $columns, array( 'status' ) );
                $time_col   = self::pick_column( $columns, array( 'lastUpdated', 'timestamp', 'dateAdded', 'ctime' ) );
                // Confirmed against a real install: this Wordfence version uses
                // "severity" (not "level") and "type" (not "category"), and
                // stores the human-readable title in a plain "shortMsg" column
                // rather than inside a serialized "data" blob — keeping the
                // older names as fallbacks for other versions.
                $level_col  = self::pick_column( $columns, array( 'severity', 'level' ) );
                $cat_col    = self::pick_column( $columns, array( 'type', 'category' ) );
                $title_col  = self::pick_column( $columns, array( 'shortMsg' ) );
                // longMsg is Wordfence's own longer explanation of the issue
                // and, for most issue types, what to do about it — surfaced
                // read-only as a "possible fix" note.
                $fix_col    = self::pick_column( $columns, array( 'longMsg' ) );
                $data_col   = self::pick_column( $columns, array( 'data' ) );

                $where = $status_col ? " WHERE `{$status_col}` = 'new'" : '';
                $order = $time_col ? " ORDER BY `{$time_col}` DESC" : '';

                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                $open_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}{$where}" );
                // Capped well above any realistic issue count rather than
                // left unbounded — open_count above still reflects the true
                // total even if it exceeds this.
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                $rows = $wpdb->get_results( "SELECT * FROM {$table}{$where}{$order} LIMIT 50" );

                $issues = array();
                foreach ( (array) $rows as $row ) {
                    // Fresh per row — unserialized once and reused for both
                    // title and fix fallback below.
                    $data = ( $data_col && isset( $row->{$data_col} ) ) ? maybe_unserialize( $row->{$data_col} ) : null;

                    $title = ( $title_col && isset( $row->{$title_col} ) ) ? $row->{$title_col} : null;
                    if ( ! $title && is_array( $data ) && ! empty( $data['shortMsg'] ) ) {
                        $title = $data['shortMsg'];
                    }
                    if ( ! $title ) {
                        $title = ( $cat_col && isset( $row->{$cat_col} ) ) ? $row->{$cat_col} : 'Issue';
                    }

                    $fix = ( $fix_col && isset( $row->{$fix_col} ) ) ? $row->{$fix_col} : null;
                    if ( ! $fix && is_array( $data ) && ! empty( $data['longMsg'] ) ) {
                        $fix = $data['longMsg'];
                    }

                    $issues[] = array(
                        'category'    => ( $cat_col && isset( $row->{$cat_col} ) ) ? $row->{$cat_col} : null,
                        'title'       => is_string( $title ) ? wp_strip_all_tags( $title ) : 'Issue',
                        'description' => is_string( $fix ) ? wp_strip_all_tags( $fix ) : null,
                        'level'       => ( $level_col && isset( $row->{$level_col} ) ) ? (int) $row->{$level_col} : null,
                        'timestamp'   => ( $time_col && isset( $row->{$time_col} ) ) ? self::normalize_timestamp( $row->{$time_col} ) : null,
                    );
                }

                $last_scan = null;
                if ( class_exists( 'wfConfig' ) && method_exists( 'wfConfig', 'get' ) ) {
                    $ts = wfConfig::get( 'lastScanCompleted' );
                    if ( $ts ) {
                        $last_scan = self::normalize_timestamp( $ts );
                    }
                }

                return array(
                    'available'  => true,
                    'open_count' => $open_count,
                    'last_scan'  => $last_scan,
                    'issues'     => $issues,
                );
            } catch ( \Throwable $e ) {
                return array( 'available' => false );
            }
        }

        // ----------------------------------------------------------------
        // Login security — wfBlocks7 (login lockouts) / wfLogins (failures)
        //
        // Confirmed against a real install: there is no dedicated
        // "locked out" table in current Wordfence versions — brute-force
        // login lockouts live in the same unified wfBlocks7 table as every
        // other IP block. There's no documented way to distinguish a login
        // lockout from a country/manual/rate-limit block there other than
        // its human-readable "reason" text, so "locked_out_now" is a
        // best-effort match on that text rather than a precise type check —
        // it can under-count if a site's Wordfence version phrases that
        // reason differently, but the failed_logins_24h figure below (a
        // direct count, not a heuristic) is unaffected either way.
        // ----------------------------------------------------------------

        private static function get_login_summary( $wpdb ) {
            $result = array(
                'available'         => false,
                'locked_out_now'    => null,
                'failed_logins_24h' => null,
            );

            $blocks_table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfBlocks7' );
            if ( $blocks_table ) {
                try {
                    $columns    = self::columns( $wpdb, $blocks_table );
                    $end_col    = self::pick_column( $columns, array( 'expiration', 'endTime', 'lockTime', 'expiry' ) );
                    $reason_col = self::pick_column( $columns, array( 'reason' ) );

                    if ( $end_col && $reason_col ) {
                        $active_clause = self::is_numeric_column_type( $columns[ $end_col ] )
                            ? $wpdb->prepare( "`{$end_col}` > %d", time() ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- column name drawn from an internal allowlist.
                            : "`{$end_col}` > NOW()";
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                        $result['locked_out_now'] = (int) $wpdb->get_var(
                            $wpdb->prepare(
                                "SELECT COUNT(*) FROM {$blocks_table} WHERE {$active_clause} AND `{$reason_col}` LIKE %s",
                                '%login%'
                            )
                        );
                        $result['available'] = true;
                    }
                } catch ( \Throwable $e ) {
                    // Leave defaults — this section just won't report.
                }
            }

            $logins_table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfLogins' );
            if ( $logins_table ) {
                try {
                    $columns  = self::columns( $wpdb, $logins_table );
                    $fail_col = self::pick_column( $columns, array( 'fail', 'failed' ) );
                    $time_col = self::pick_column( $columns, array( 'ctime', 'time', 'createdTime' ) );

                    if ( $fail_col && $time_col ) {
                        if ( self::is_numeric_column_type( $columns[ $time_col ] ) ) {
                            $cutoff = time() - DAY_IN_SECONDS;
                            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                            $result['failed_logins_24h'] = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$logins_table} WHERE `{$fail_col}` = 1 AND `{$time_col}` > %d", $cutoff ) );
                        } else {
                            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table/column names fixed internally or drawn from an internal allowlist.
                            $result['failed_logins_24h'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$logins_table} WHERE `{$fail_col}` = 1 AND `{$time_col}` > (NOW() - INTERVAL 1 DAY)" );
                        }
                        $result['available'] = true;
                    }
                } catch ( \Throwable $e ) {
                    // Leave defaults — this section just won't report.
                }
            }

            return $result;
        }

        // ----------------------------------------------------------------
        // Live traffic — wfHits
        // ----------------------------------------------------------------

        private static function get_traffic_summary( $wpdb ) {
            $table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfHits' );
            if ( ! $table ) {
                return array( 'available' => false );
            }

            try {
                $columns     = self::columns( $wpdb, $table );
                $time_col    = self::pick_column( $columns, array( 'ctime', 'attackLogTime', 'time' ) );
                $ip_col      = self::pick_column( $columns, array( 'IP', 'ip' ) );
                $url_col     = self::pick_column( $columns, array( 'URL', 'url', 'request' ) );
                $action_col  = self::pick_column( $columns, array( 'actionDescription', 'action' ) );
                $status_col  = self::pick_column( $columns, array( 'statusCode', 'status' ) );
                $agent_col   = self::pick_column( $columns, array( 'userAgent', 'UA' ) );
                $google_col  = self::pick_column( $columns, array( 'isGoogle' ) );
                $jsrun_col   = self::pick_column( $columns, array( 'jsRun' ) );

                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- fixed internal table name.
                $total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

                $recent = array();
                if ( $time_col || $ip_col ) {
                    $order = $time_col ? " ORDER BY `{$time_col}` DESC" : '';
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name fixed internally; order column drawn from an internal allowlist.
                    $rows = $wpdb->get_results( "SELECT * FROM {$table}{$order} LIMIT 20" );
                    foreach ( (array) $rows as $row ) {
                        $action_text = ( $action_col && isset( $row->{$action_col} ) ) ? (string) $row->{$action_col} : null;
                        $status      = ( $status_col && isset( $row->{$status_col} ) ) ? (int) $row->{$status_col} : null;
                        $is_google   = ( $google_col && isset( $row->{$google_col} ) ) ? (bool) $row->{$google_col} : null;
                        $js_run      = ( $jsrun_col && isset( $row->{$jsrun_col} ) ) ? (bool) $row->{$jsrun_col} : null;

                        $recent[] = array(
                            'time'       => ( $time_col && isset( $row->{$time_col} ) ) ? self::normalize_timestamp( $row->{$time_col} ) : null,
                            'ip'         => ( $ip_col && isset( $row->{$ip_col} ) ) ? self::maybe_decode_ip( $row->{$ip_col} ) : null,
                            'url'        => ( $url_col && isset( $row->{$url_col} ) ) ? (string) $row->{$url_col} : null,
                            'action'     => $action_text,
                            'status'     => $status,
                            'user_agent' => ( $agent_col && isset( $row->{$agent_col} ) ) ? (string) $row->{$agent_col} : null,
                            'is_google'  => $is_google,
                            'category'   => self::classify_traffic_hit( $js_run, $is_google, $status, $action_text ),
                            'location'   => null,
                        );
                    }

                    $locations = self::get_ip_locations( $wpdb, wp_list_pluck( $recent, 'ip' ) );
                    foreach ( $recent as &$hit ) {
                        if ( $hit['ip'] && isset( $locations[ $hit['ip'] ] ) ) {
                            $hit['location'] = $locations[ $hit['ip'] ];
                        }
                    }
                    unset( $hit );
                }

                return array(
                    'available'    => true,
                    'total_logged' => $total,
                    'recent'       => $recent,
                );
            } catch ( \Throwable $e ) {
                return array( 'available' => false );
            }
        }

        /**
         * Looks up city/country for a set of IPs from Wordfence's own
         * geolocation cache (wfLocs) — populated as Wordfence sees traffic
         * from each address, so a very new or rarely-seen IP may have no
         * entry yet (returns no data for it, not an error).
         *
         * Returns [decoded_ip => ['city'=>.., 'country_name'=>.., 'country_code'=>..]].
         */
        private static function get_ip_locations( $wpdb, array $ips ) {
            $ips = array_values( array_unique( array_filter( $ips ) ) );
            if ( empty( $ips ) ) {
                return array();
            }

            $table = self::resolve_table( $wpdb, $wpdb->prefix . 'wfLocs' );
            if ( ! $table ) {
                return array();
            }

            $columns     = self::columns( $wpdb, $table );
            $ip_col      = self::pick_column( $columns, array( 'IP', 'ip' ) );
            $city_col    = self::pick_column( $columns, array( 'city' ) );
            $country_col = self::pick_column( $columns, array( 'countryName' ) );
            $code_col    = self::pick_column( $columns, array( 'countryCode' ) );
            if ( ! $ip_col ) {
                return array();
            }

            // Wordfence's tables aren't consistent about how an IP is stored
            // — wfHits confirmed as a 16-byte IPv4-mapped-IPv6 packed value
            // (e.g. "::ffff:9.9.9.9"), but wfLocs could use a plain 4-byte
            // packed IPv4 value, or even a readable string — so every
            // candidate encoding is queried for and whichever one actually
            // matches wins. Cheap in practice: at most ~20 unique IPs here.
            $candidates = array();
            foreach ( $ips as $ip ) {
                $candidates[] = $ip;
                $v4 = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- an IP inet_pton can't parse is simply skipped, not fatal.
                if ( false !== $v4 ) {
                    $candidates[] = $v4;
                }
                $mapped = @inet_pton( '::ffff:' . $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- same as above.
                if ( false !== $mapped ) {
                    $candidates[] = $mapped;
                }
            }
            if ( empty( $candidates ) ) {
                return array();
            }

            $placeholders = implode( ',', array_fill( 0, count( $candidates ), '%s' ) );
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table/column names fixed internally or drawn from an internal allowlist; values bound via prepare() below.
            $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE `{$ip_col}` IN ({$placeholders})", $candidates ) );

            $map = array();
            foreach ( (array) $rows as $row ) {
                $decoded = self::maybe_decode_ip( $row->{$ip_col} );
                if ( ! $decoded ) {
                    continue;
                }
                $map[ $decoded ] = array(
                    'city'         => ( $city_col && ! empty( $row->{$city_col} ) ) ? (string) $row->{$city_col} : null,
                    'country_name' => ( $country_col && ! empty( $row->{$country_col} ) ) ? (string) $row->{$country_col} : null,
                    'country_code' => ( $code_col && ! empty( $row->{$code_col} ) ) ? (string) $row->{$code_col} : null,
                );
            }
            return $map;
        }
    }

    // Registered unconditionally — this is a passive read of Wordfence's own
    // data, with no KW Security feature toggle of its own to gate on.
    add_action( 'rest_api_init', array( 'KW_Wordfence_Integration', 'init_dashboard_api' ) );
}
