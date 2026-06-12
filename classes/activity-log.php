<?php
/**
 * KW Security – Activity Log
 *
 * Records security-relevant WordPress events to a dedicated database table
 * and renders them in an admin list under Settings → Activity Log.
 *
 * Events tracked:
 *  - User    : login, logout, failed login, registration, deletion, profile update, password reset
 *  - Post    : create, update, trash, restore, delete (all non-system post types)
 *  - Media   : upload, delete
 *  - Plugin  : activate, deactivate, install, update
 *  - Theme   : switch/activate, install, update
 *  - Core    : WordPress core update
 *  - Settings: KW Security settings saved
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Activity_Log' ) ) {

    class KW_Activity_Log {

        const TABLE_SUFFIX   = 'kw_activity_log';
        const PAGE_SLUG      = 'kw-activity-log';
        const OPTION_RETAIN  = 'kw_activity_log_retain_days';
        const DEFAULT_RETAIN = 90;

        // ----------------------------------------------------------------
        // Bootstrap
        // ----------------------------------------------------------------

        public function __construct() {
            add_action( 'admin_menu', array( $this, 'register_page' ) );

            // Daily retention cleanup via WP-Cron.
            add_action( 'kw_activity_log_cleanup', array( $this, 'delete_old_logs' ) );
            if ( ! wp_next_scheduled( 'kw_activity_log_cleanup' ) ) {
                wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'kw_activity_log_cleanup' );
            }

            // ── User events ──────────────────────────────────────────────
            add_action( 'wp_login',             array( $this, 'on_login' ),          10, 2 );
            add_action( 'clear_auth_cookie',    array( $this, 'on_logout' ) );
            add_action( 'wp_login_failed',      array( $this, 'on_login_failed' ) );
            add_action( 'user_register',        array( $this, 'on_user_register' ) );
            add_action( 'delete_user',          array( $this, 'on_delete_user' ) );
            add_action( 'profile_update',       array( $this, 'on_profile_update' ), 10, 2 );
            add_action( 'after_password_reset', array( $this, 'on_password_reset' ) );

            // ── Post events ──────────────────────────────────────────────
            add_action( 'transition_post_status', array( $this, 'on_post_status_transition' ), 10, 3 );
            add_action( 'delete_post',            array( $this, 'on_delete_post' ) );

            // ── Media events ─────────────────────────────────────────────
            add_action( 'add_attachment',    array( $this, 'on_attachment_added' ) );
            add_action( 'delete_attachment', array( $this, 'on_attachment_deleted' ) );

            // ── Plugin events ────────────────────────────────────────────
            add_action( 'activated_plugin',          array( $this, 'on_plugin_activated' ) );
            add_action( 'deactivated_plugin',        array( $this, 'on_plugin_deactivated' ) );
            add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_complete' ), 10, 2 );

            // ── Theme events ─────────────────────────────────────────────
            add_action( 'switch_theme', array( $this, 'on_theme_switched' ), 10, 3 );

            // ── WordPress core update ─────────────────────────────────────
            add_action( '_core_updated_successfully', array( $this, 'on_core_updated' ) );

            // ── KW Security settings ─────────────────────────────────────
            add_action( 'update_option_' . KW_Security_Settings::OPTION_NAME, array( $this, 'on_kw_settings_saved' ), 10, 2 );
        }

        // ----------------------------------------------------------------
        // Database
        // ----------------------------------------------------------------

        /**
         * Create the activity log table. Called on plugin activation.
         */
        public static function create_table() {
            global $wpdb;
            $table           = $wpdb->prefix . self::TABLE_SUFFIX;
            $charset_collate = $wpdb->get_charset_collate();

            $sql = "CREATE TABLE {$table} (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
                user_caps VARCHAR(70) NOT NULL DEFAULT '',
                action VARCHAR(100) NOT NULL DEFAULT '',
                object_type VARCHAR(100) NOT NULL DEFAULT '',
                object_subtype VARCHAR(100) NOT NULL DEFAULT '',
                object_name VARCHAR(255) NOT NULL DEFAULT '',
                object_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
                ip VARCHAR(55) NOT NULL DEFAULT '',
                created_at INT(11) UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY  (id),
                KEY user_id (user_id),
                KEY action (action),
                KEY object_type (object_type),
                KEY created_at (created_at)
            ) {$charset_collate};";

            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta( $sql );
        }

        // ----------------------------------------------------------------
        // Log insertion
        // ----------------------------------------------------------------

        /**
         * Insert a log entry.
         *
         * @param array $args {
         *     @type string $action         Required. Short verb: 'Logged In', 'Activated', etc.
         *     @type string $object_type    Required. Category: 'User', 'Post', 'Plugin', etc.
         *     @type string $object_subtype Optional sub-label (post type, plugin slug, etc.).
         *     @type string $object_name    Human-readable name of the affected object.
         *     @type int    $object_id      Optional ID of the affected object.
         *     @type int    $user_id        Optional; defaults to current user.
         *     @type string $user_caps      Optional; defaults to current user's primary role.
         *     @type string $ip             Optional; defaults to client IP.
         * }
         */
        public static function insert( array $args ) {
            global $wpdb;

            $user_id   = isset( $args['user_id'] ) ? (int) $args['user_id'] : get_current_user_id();
            $user_caps = isset( $args['user_caps'] ) ? $args['user_caps'] : self::get_user_caps( $user_id );

            $data = array(
                'user_id'        => $user_id,
                'user_caps'      => sanitize_text_field( $user_caps ),
                'action'         => sanitize_text_field( isset( $args['action'] )         ? $args['action']         : '' ),
                'object_type'    => sanitize_text_field( isset( $args['object_type'] )    ? $args['object_type']    : '' ),
                'object_subtype' => sanitize_text_field( isset( $args['object_subtype'] ) ? $args['object_subtype'] : '' ),
                'object_name'    => sanitize_text_field( isset( $args['object_name'] )    ? $args['object_name']    : '' ),
                'object_id'      => (int) ( isset( $args['object_id'] ) ? $args['object_id'] : 0 ),
                'ip'             => sanitize_text_field( isset( $args['ip'] )             ? $args['ip']             : self::get_ip() ),
                'created_at'     => time(),
            );

            $wpdb->insert(
                $wpdb->prefix . self::TABLE_SUFFIX,
                $data,
                array( '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
            );
        }

        // ----------------------------------------------------------------
        // Helpers
        // ----------------------------------------------------------------

        /**
         * Return the primary role for a user ID, or 'guest' for unauthenticated.
         */
        private static function get_user_caps( $user_id ) {
            if ( ! $user_id ) {
                return 'guest';
            }
            $user = get_userdata( $user_id );
            if ( ! $user || empty( $user->roles ) ) {
                return 'none';
            }
            return $user->roles[0];
        }

        /**
         * Return the validated client IP from REMOTE_ADDR.
         */
        private static function get_ip() {
            $ip = isset( $_SERVER['REMOTE_ADDR'] )
                ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
                : '';
            return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
        }

        // ----------------------------------------------------------------
        // Hook handlers — User
        // ----------------------------------------------------------------

        public function on_login( $user_login, $user ) {
            self::insert( array(
                'action'      => 'Logged In',
                'object_type' => 'User',
                'object_name' => $user_login,
                'object_id'   => $user->ID,
                'user_id'     => $user->ID,
                'user_caps'   => self::get_user_caps( $user->ID ),
            ) );
        }

        public function on_logout() {
            $user = wp_get_current_user();
            if ( ! $user->exists() ) {
                return;
            }
            self::insert( array(
                'action'      => 'Logged Out',
                'object_type' => 'User',
                'object_name' => $user->user_login,
                'object_id'   => $user->ID,
            ) );
        }

        public function on_login_failed( $username ) {
            self::insert( array(
                'action'      => 'Failed Login',
                'object_type' => 'User',
                'object_name' => sanitize_user( $username ),
                'user_id'     => 0,
                'user_caps'   => 'guest',
            ) );
        }

        public function on_user_register( $user_id ) {
            $user = get_userdata( $user_id );
            self::insert( array(
                'action'      => 'Registered',
                'object_type' => 'User',
                'object_name' => $user ? $user->user_login : '',
                'object_id'   => $user_id,
            ) );
        }

        public function on_delete_user( $user_id ) {
            $user = get_userdata( $user_id );
            self::insert( array(
                'action'      => 'Deleted',
                'object_type' => 'User',
                'object_name' => $user ? $user->user_login : (string) $user_id,
                'object_id'   => $user_id,
            ) );
        }

        public function on_profile_update( $user_id, $old_data ) {
            $user = get_userdata( $user_id );
            self::insert( array(
                'action'      => 'Updated',
                'object_type' => 'User',
                'object_name' => $user ? $user->user_login : (string) $user_id,
                'object_id'   => $user_id,
            ) );
        }

        public function on_password_reset( $user ) {
            self::insert( array(
                'action'      => 'Password Reset',
                'object_type' => 'User',
                'object_name' => $user->user_login,
                'object_id'   => $user->ID,
                'user_id'     => $user->ID,
                'user_caps'   => self::get_user_caps( $user->ID ),
            ) );
        }

        // ----------------------------------------------------------------
        // Hook handlers — Post
        // ----------------------------------------------------------------

        /** Post types to skip entirely. */
        private static $skip_post_types = array( 'revision', 'nav_menu_item', 'attachment', 'custom_css', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_block', 'wp_template', 'wp_template_part', 'wp_global_styles', 'wp_navigation' );

        public function on_post_status_transition( $new_status, $old_status, $post ) {
            if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
                return;
            }
            if ( in_array( $post->post_type, self::$skip_post_types, true ) ) {
                return;
            }
            if ( 'auto-draft' === $new_status || 'inherit' === $new_status ) {
                return;
            }
            if ( $new_status === $old_status ) {
                return;
            }

            if ( in_array( $old_status, array( 'new', 'auto-draft' ), true ) ) {
                $action = 'Created';
            } elseif ( 'trash' === $new_status ) {
                $action = 'Trashed';
            } elseif ( 'trash' === $old_status ) {
                $action = 'Restored';
            } else {
                $action = 'Updated';
            }

            self::insert( array(
                'action'         => $action,
                'object_type'    => 'Post',
                'object_subtype' => $post->post_type,
                'object_name'    => $post->post_title !== '' ? $post->post_title : __( '(no title)', 'kw-security' ),
                'object_id'      => $post->ID,
            ) );
        }

        public function on_delete_post( $post_id ) {
            $post = get_post( $post_id );
            if ( ! $post || in_array( $post->post_type, self::$skip_post_types, true ) ) {
                return;
            }
            self::insert( array(
                'action'         => 'Deleted',
                'object_type'    => 'Post',
                'object_subtype' => $post->post_type,
                'object_name'    => $post->post_title !== '' ? $post->post_title : __( '(no title)', 'kw-security' ),
                'object_id'      => $post_id,
            ) );
        }

        // ----------------------------------------------------------------
        // Hook handlers — Media
        // ----------------------------------------------------------------

        public function on_attachment_added( $attachment_id ) {
            $post = get_post( $attachment_id );
            self::insert( array(
                'action'      => 'Uploaded',
                'object_type' => 'Media',
                'object_name' => $post ? $post->post_title : (string) $attachment_id,
                'object_id'   => $attachment_id,
            ) );
        }

        public function on_attachment_deleted( $attachment_id ) {
            $post = get_post( $attachment_id );
            self::insert( array(
                'action'      => 'Deleted',
                'object_type' => 'Media',
                'object_name' => $post ? $post->post_title : (string) $attachment_id,
                'object_id'   => $attachment_id,
            ) );
        }

        // ----------------------------------------------------------------
        // Hook handlers — Plugins
        // ----------------------------------------------------------------

        public function on_plugin_activated( $plugin ) {
            if ( ! function_exists( 'get_plugin_data' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
            self::insert( array(
                'action'         => 'Activated',
                'object_type'    => 'Plugin',
                'object_subtype' => $plugin,
                'object_name'    => ! empty( $data['Name'] ) ? $data['Name'] : $plugin,
            ) );
        }

        public function on_plugin_deactivated( $plugin ) {
            if ( ! function_exists( 'get_plugin_data' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
            self::insert( array(
                'action'         => 'Deactivated',
                'object_type'    => 'Plugin',
                'object_subtype' => $plugin,
                'object_name'    => ! empty( $data['Name'] ) ? $data['Name'] : $plugin,
            ) );
        }

        public function on_upgrader_complete( $upgrader, $hook_extra ) {
            $type   = isset( $hook_extra['type'] )   ? $hook_extra['type']   : '';
            $action = isset( $hook_extra['action'] ) ? $hook_extra['action'] : '';

            if ( 'plugin' === $type ) {
                if ( ! function_exists( 'get_plugin_data' ) ) {
                    require_once ABSPATH . 'wp-admin/includes/plugin.php';
                }
                $slugs = isset( $hook_extra['plugins'] ) ? (array) $hook_extra['plugins'] : array();
                if ( ! empty( $hook_extra['plugin'] ) ) {
                    $slugs[] = $hook_extra['plugin'];
                }
                foreach ( array_unique( array_filter( $slugs ) ) as $plugin ) {
                    $data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
                    self::insert( array(
                        'action'         => 'install' === $action ? 'Installed' : 'Updated',
                        'object_type'    => 'Plugin',
                        'object_subtype' => $plugin,
                        'object_name'    => ! empty( $data['Name'] ) ? $data['Name'] : $plugin,
                    ) );
                }
            } elseif ( 'theme' === $type ) {
                $slugs = isset( $hook_extra['themes'] ) ? (array) $hook_extra['themes'] : array();
                if ( ! empty( $hook_extra['theme'] ) ) {
                    $slugs[] = $hook_extra['theme'];
                }
                foreach ( array_unique( array_filter( $slugs ) ) as $slug ) {
                    $theme = wp_get_theme( $slug );
                    self::insert( array(
                        'action'         => 'install' === $action ? 'Installed' : 'Updated',
                        'object_type'    => 'Theme',
                        'object_subtype' => $slug,
                        'object_name'    => $theme->get( 'Name' ) ? $theme->get( 'Name' ) : $slug,
                    ) );
                }
            }
        }

        // ----------------------------------------------------------------
        // Hook handlers — Theme
        // ----------------------------------------------------------------

        public function on_theme_switched( $new_name, $new_theme, $old_theme ) {
            self::insert( array(
                'action'         => 'Activated',
                'object_type'    => 'Theme',
                'object_subtype' => $new_theme->get_stylesheet(),
                'object_name'    => $new_name,
            ) );
        }

        // ----------------------------------------------------------------
        // Hook handlers — Core
        // ----------------------------------------------------------------

        public function on_core_updated( $wp_version ) {
            self::insert( array(
                'action'      => 'Updated',
                'object_type' => 'WordPress',
                'object_name' => 'WordPress ' . $wp_version,
                'user_id'     => 0,
                'user_caps'   => 'system',
            ) );
        }

        // ----------------------------------------------------------------
        // Hook handlers — Settings
        // ----------------------------------------------------------------

        public function on_kw_settings_saved( $old_value, $new_value ) {
            self::insert( array(
                'action'      => 'Updated',
                'object_type' => 'Settings',
                'object_name' => 'KW Security',
            ) );
        }

        // ----------------------------------------------------------------
        // Log retention
        // ----------------------------------------------------------------

        public function delete_old_logs() {
            global $wpdb;
            $days   = (int) get_option( self::OPTION_RETAIN, self::DEFAULT_RETAIN );
            $table  = $wpdb->prefix . self::TABLE_SUFFIX;
            $cutoff = time() - ( $days * DAY_IN_SECONDS );
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is a fixed internal string.
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %d", $cutoff ) );
        }

        // ----------------------------------------------------------------
        // Admin page
        // ----------------------------------------------------------------

        public function register_page() {
            add_submenu_page(
                'options-general.php',
                __( 'Activity Log', 'kw-security' ),
                __( 'Activity Log', 'kw-security' ),
                'manage_options',
                self::PAGE_SLUG,
                array( $this, 'render_page' )
            );
        }

        public function render_page() {
            if ( ! current_user_can( 'manage_options' ) ) {
                return;
            }

            // Handle clear-all action.
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified below via check_admin_referer.
            if ( isset( $_POST['kw_log_action'] ) && 'clear_all' === $_POST['kw_log_action'] ) {
                check_admin_referer( 'kw_activity_log_clear' );
                global $wpdb;
                // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- TRUNCATE does not support placeholders; table name is a fixed internal string.
                $wpdb->query( 'TRUNCATE TABLE ' . $wpdb->prefix . self::TABLE_SUFFIX ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.DirectQuery
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Activity log cleared.', 'kw-security' ) . '</p></div>';
            }

            if ( ! class_exists( 'WP_List_Table' ) ) {
                require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
            }

            $list_table = new KW_Activity_Log_List_Table();
            $list_table->prepare_items();
            ?>
            <div class="wrap">
                <h1><?php esc_html_e( 'KW Security — Activity Log', 'kw-security' ); ?></h1>

                <form method="post" style="display:inline-block;margin-bottom:12px;">
                    <?php wp_nonce_field( 'kw_activity_log_clear' ); ?>
                    <input type="hidden" name="kw_log_action" value="clear_all" />
                    <?php submit_button(
                        __( 'Clear All Logs', 'kw-security' ),
                        'secondary small',
                        'clear_logs',
                        false,
                        array( 'onclick' => 'return confirm(\'' . esc_js( __( 'Delete all activity log entries? This cannot be undone.', 'kw-security' ) ) . '\');' )
                    ); ?>
                </form>

                <form method="get">
                    <input type="hidden" name="page" value="<?php echo esc_attr( self::PAGE_SLUG ); ?>" />
                    <?php $list_table->search_box( __( 'Search Logs', 'kw-security' ), 'kw-log-search' ); ?>
                    <?php $list_table->display(); ?>
                </form>
            </div>
            <?php
        }

        // ----------------------------------------------------------------
        // Conflict detection
        // ----------------------------------------------------------------

        /**
         * Whether the Activity Log plugin by Aryo (aryo-activity-log) is
         * active. Running both loggers would duplicate every event, so
         * this feature stays dormant until the other plugin is deactivated.
         */
        public static function is_conflicting() {
            return class_exists( 'AAL_Main' ) || defined( 'ACTIVITY_LOG__FILE__' );
        }

        /**
         * Bootstrap at plugins_loaded so the conflict check sees every
         * other plugin regardless of load order.
         */
        public static function maybe_init() {
            if ( self::is_conflicting() ) {
                add_action( 'admin_notices', array( __CLASS__, 'conflict_notice' ) );
                return;
            }
            new self();
        }

        /**
         * Admin notice shown when the feature is enabled but blocked by
         * the Aryo Activity Log plugin.
         */
        public static function conflict_notice() {
            echo '<div class="notice notice-error is-dismissible"><p>'
                . esc_html__( 'KW Security — the Activity Log feature has been disabled because the "Activity Log" plugin (aryo-activity-log) is currently active. Please deactivate that plugin first to use the KW Security activity log.', 'kw-security' )
                . '</p></div>';
        }

        // ----------------------------------------------------------------
        // Activation / Deactivation
        // ----------------------------------------------------------------

        public static function activation() {
            self::create_table();
        }

        public static function deactivation() {
            wp_clear_scheduled_hook( 'kw_activity_log_cleanup' );
        }
    }

    // ----------------------------------------------------------------
    // List Table
    // ----------------------------------------------------------------

    if ( is_admin() ) {

        if ( ! class_exists( 'WP_List_Table' ) ) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
        }

        if ( ! class_exists( 'KW_Activity_Log_List_Table' ) ) {

            class KW_Activity_Log_List_Table extends WP_List_Table {

                public function __construct() {
                    parent::__construct( array(
                        'singular' => 'log_entry',
                        'plural'   => 'log_entries',
                        'ajax'     => false,
                    ) );
                }

                public function get_columns() {
                    return array(
                        'created_at'  => __( 'Date / Time', 'kw-security' ),
                        'user'        => __( 'User', 'kw-security' ),
                        'ip'          => __( 'IP Address', 'kw-security' ),
                        'object_type' => __( 'Event Type', 'kw-security' ),
                        'object_name' => __( 'Object', 'kw-security' ),
                        'action'      => __( 'Action', 'kw-security' ),
                    );
                }

                protected function get_sortable_columns() {
                    return array(
                        'created_at'  => array( 'created_at', true ),
                        'object_type' => array( 'object_type', false ),
                        'action'      => array( 'action', false ),
                    );
                }

                public function prepare_items() {
                    global $wpdb;
                    $table    = $wpdb->prefix . KW_Activity_Log::TABLE_SUFFIX;
                    $per_page = 50;
                    $current  = $this->get_pagenum();

                    $where  = array( '1=1' );
                    $values = array();

                    // Search
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter.
                    if ( ! empty( $_REQUEST['s'] ) ) {
                        $term     = '%' . $wpdb->esc_like( sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) ) . '%';
                        $where[]  = '(object_name LIKE %s OR object_subtype LIKE %s OR action LIKE %s)';
                        $values[] = $term;
                        $values[] = $term;
                        $values[] = $term;
                    }

                    // Filter: event type
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    if ( ! empty( $_REQUEST['kw_type'] ) ) {
                        $where[]  = 'object_type = %s';
                        $values[] = sanitize_text_field( wp_unslash( $_REQUEST['kw_type'] ) );
                    }

                    // Filter: action
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    if ( ! empty( $_REQUEST['kw_action'] ) ) {
                        $where[]  = 'action = %s';
                        $values[] = sanitize_text_field( wp_unslash( $_REQUEST['kw_action'] ) );
                    }

                    // Filter: user
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    if ( isset( $_REQUEST['kw_user'] ) && '' !== $_REQUEST['kw_user'] ) {
                        $where[]  = 'user_id = %d';
                        $values[] = (int) $_REQUEST['kw_user'];
                    }

                    // Sorting
                    $allowed_orderby = array( 'created_at', 'object_type', 'action' );
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    $orderby = ( isset( $_REQUEST['orderby'] ) && in_array( sanitize_key( $_REQUEST['orderby'] ), $allowed_orderby, true ) )
                        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                        ? sanitize_key( $_REQUEST['orderby'] )
                        : 'created_at';
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
                    $order = ( isset( $_REQUEST['order'] ) && 'asc' === strtolower( sanitize_key( $_REQUEST['order'] ) ) ) ? 'ASC' : 'DESC';

                    $where_sql = implode( ' AND ', $where );
                    $offset    = ( $current - 1 ) * $per_page;

                    if ( $values ) {
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name and where clauses are safe.
                        $total       = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}", $values ) );
                        $query_args  = array_merge( $values, array( $per_page, $offset ) );
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                        $this->items = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d", $query_args ) );
                    } else {
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                        $total       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}" );
                        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                        $this->items = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d", $per_page, $offset ) );
                    }

                    $this->set_pagination_args( array(
                        'total_items' => $total,
                        'per_page'    => $per_page,
                        'total_pages' => (int) ceil( $total / $per_page ),
                    ) );

                    $this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns() );
                }

                public function column_default( $item, $column_name ) {
                    return esc_html( $item->$column_name );
                }

                public function column_created_at( $item ) {
                    $ts    = (int) $item->created_at;
                    $date  = get_date_from_gmt( gmdate( 'Y-m-d H:i:s', $ts ), get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
                    $diff  = human_time_diff( $ts, time() );
                    return esc_html( $date )
                        . '<br><small style="color:#999;">'
                        . esc_html( $diff ) . ' ' . esc_html__( 'ago', 'kw-security' )
                        . '</small>';
                }

                public function column_user( $item ) {
                    if ( ! (int) $item->user_id ) {
                        return '<em>' . esc_html__( 'Guest', 'kw-security' ) . '</em>';
                    }
                    $user = get_userdata( (int) $item->user_id );
                    if ( ! $user ) {
                        return esc_html__( 'Deleted User', 'kw-security' ) . ' #' . (int) $item->user_id;
                    }
                    return '<a href="' . esc_url( get_edit_user_link( $user->ID ) ) . '">' . esc_html( $user->display_name ) . '</a>'
                        . '<br><small style="color:#999;">' . esc_html( $item->user_caps ) . '</small>';
                }

                public function column_ip( $item ) {
                    return $item->ip
                        ? esc_html( $item->ip )
                        : '<em style="color:#999;">' . esc_html__( 'n/a', 'kw-security' ) . '</em>';
                }

                public function column_object_type( $item ) {
                    $url = add_query_arg( array(
                        'page'    => KW_Activity_Log::PAGE_SLUG,
                        'kw_type' => rawurlencode( $item->object_type ),
                    ), admin_url( 'options-general.php' ) );
                    return '<a href="' . esc_url( $url ) . '">' . esc_html( $item->object_type ) . '</a>';
                }

                public function column_object_name( $item ) {
                    $out = esc_html( $item->object_name );
                    if ( $item->object_subtype ) {
                        $out .= '<br><small style="color:#999;">' . esc_html( $item->object_subtype ) . '</small>';
                    }
                    return $out;
                }

                public function column_action( $item ) {
                    $url = add_query_arg( array(
                        'page'      => KW_Activity_Log::PAGE_SLUG,
                        'kw_action' => rawurlencode( $item->action ),
                    ), admin_url( 'options-general.php' ) );
                    return '<a href="' . esc_url( $url ) . '">' . esc_html( $item->action ) . '</a>';
                }

                protected function extra_tablenav( $which ) {
                    if ( 'top' !== $which ) {
                        return;
                    }
                    ?>
                    <div class="alignleft actions">
                        <?php
                        $this->render_filter_dropdown( 'kw_type',   __( 'All Types', 'kw-security' ),   $this->distinct_values( 'object_type' ) );
                        $this->render_filter_dropdown( 'kw_action', __( 'All Actions', 'kw-security' ), $this->distinct_values( 'action' ) );
                        submit_button( __( 'Filter', 'kw-security' ), 'button', 'filter_action', false );
                        ?>
                    </div>
                    <?php
                }

                private function render_filter_dropdown( $param, $default_label, $options ) {
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter.
                    $current = isset( $_REQUEST[ $param ] ) ? sanitize_text_field( wp_unslash( $_REQUEST[ $param ] ) ) : '';
                    echo '<select name="' . esc_attr( $param ) . '" style="margin-right:4px;">';
                    echo '<option value="">' . esc_html( $default_label ) . '</option>';
                    foreach ( $options as $val ) {
                        printf(
                            '<option value="%s"%s>%s</option>',
                            esc_attr( $val ),
                            selected( $current, $val, false ),
                            esc_html( $val )
                        );
                    }
                    echo '</select>';
                }

                private function distinct_values( $column ) {
                    global $wpdb;
                    $allowed = array( 'object_type', 'action', 'user_caps' );
                    if ( ! in_array( $column, $allowed, true ) ) {
                        return array();
                    }
                    $table = $wpdb->prefix . KW_Activity_Log::TABLE_SUFFIX;
                    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Column validated against allowlist; table name is fixed.
                    return $wpdb->get_col( "SELECT DISTINCT {$column} FROM {$table} ORDER BY {$column} ASC" ) ?: array();
                }

                public function no_items() {
                    esc_html_e( 'No activity log entries found.', 'kw-security' );
                }
            }
        }
    }

    if ( KW_Security_Settings::is_enabled( 'activity_log' ) ) {
        // Deferred to plugins_loaded so the aryo-activity-log conflict check
        // works regardless of plugin load order.
        add_action( 'plugins_loaded', array( 'KW_Activity_Log', 'maybe_init' ), 1 );
    }
}
