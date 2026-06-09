<?php
if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('KW_Security')) {

    class KW_Security {

        public function __construct() {
            $this->init_hooks();
        }

        /**
         * Initializes WordPress hooks for security features.
         *
         * Each feature group is gated by a Settings → KW Security toggle so
         * sites can disable individual features (e.g. enable comments) without
         * forking the plugin.
         */
        private function init_hooks() {
            // Controlled auto-updates
            if (KW_Security_Settings::is_enabled('update_management')) {
                add_filter('allow_minor_auto_core_updates', '__return_true');
                add_filter('allow_major_auto_core_updates', '__return_false');
                add_filter('auto_update_plugin', array($this, 'allow_security_updates_only'), 10, 2);
                add_filter('auto_update_theme', '__return_false');
                add_filter('pre_site_transient_update_core', array($this, 'filter_core_updates'));
                add_filter('pre_site_transient_update_themes', array($this, 'remove_theme_updates'));
            }

            // XML-RPC pingback hardening
            if (KW_Security_Settings::is_enabled('xmlrpc_pingback')) {
                add_filter('xmlrpc_enabled', '__return_false');
                // Defense-in-depth: strip pingback methods even if XML-RPC gets re-enabled.
                add_filter('xmlrpc_methods', array($this, 'disable_xmlrpc_pingback_methods'));
            }

            // File upload restrictions and editor disable
            if (KW_Security_Settings::is_enabled('file_security')) {
                add_action('init', array($this, 'disable_file_editing'));
                add_filter('upload_mimes', array($this, 'restrict_file_uploads'));
                add_filter('wp_handle_upload_prefilter', array($this, 'block_dangerous_uploads'));

                // On Nginx the .htaccess written at activation has no effect — show a
                // persistent admin notice with the equivalent Nginx location block instead.
                if ('nginx' === self::detect_server()) {
                    add_action('admin_notices', array($this, 'nginx_upload_notice'));
                }
                add_action('admin_post_kw_nginx_notice_dismiss', array($this, 'handle_nginx_notice_dismiss'));
            }

            // Comment system disable
            if (KW_Security_Settings::is_enabled('comments')) {
                add_action('admin_init', array($this, 'disable_comments_admin'));
                add_action('wp_dashboard_setup', array($this, 'remove_dashboard_comments_widget'));
                add_action('admin_menu', array($this, 'disable_comments_admin_menu'));
                add_action('init', array($this, 'disable_comments_admin_bar'));
                add_action('wp_enqueue_scripts', array($this, 'disable_comments_reply_script'), 100);
                add_filter('rest_endpoints', array($this, 'disable_comments_rest_api'));
                add_filter('comments_open', '__return_false', 20, 2);
                add_filter('pings_open', '__return_false', 20, 2);
                add_filter('comments_array', '__return_empty_array', 10, 2);
            }
        }

        /**
         * Plugin activation hook.
         *
         * Seeds default feature toggles (only on first activation — uses
         * add_option so reactivation does not reset user preferences) and
         * runs feature-specific setup that respects those toggles.
         */
        public static function plugin_activation() {
            // Seed defaults on first activation — does nothing if option exists.
            if (class_exists('KW_Security_Settings')) {
                add_option(KW_Security_Settings::OPTION_NAME, KW_Security_Settings::get_defaults());
            }

            // Set up upload PHP-execution protection — method is server-aware.
            if (KW_Security_Settings::is_enabled('file_security')) {
                $instance = new self();
                $instance->setup_upload_protection();
            }
        }

        /**
         * Plugin deactivation hook — clean up scheduled cron jobs so they
         * do not continue firing after the plugin is disabled.
         */
        public static function plugin_deactivation() {
            if (class_exists('KW_File_Integrity')) {
                KW_File_Integrity::deactivation();
            }
        }

        /**
         * Strip pingback methods from the XML-RPC server.
         *
         * Defense-in-depth: even with `xmlrpc_enabled` filtered to false,
         * unsetting these methods removes a common DDoS / port-scan amplifier
         * if XML-RPC is re-enabled by another plugin or a custom filter.
         */
        public function disable_xmlrpc_pingback_methods($methods) {
            unset($methods['pingback.ping']);
            unset($methods['pingback.extensions.getPingbacks']);
            return $methods;
        }

        /**
         * Allow security updates only for plugins
         */
        public function allow_security_updates_only($update, $item = null) {
            // Allow updates for plugins that have security fixes
            if (isset($item->plugin) && $this->is_security_update($item)) {
                return true;
            }
            return false;
        }

        /**
         * Check if update contains security fixes.
         *
         * Allows updates where the major and minor version stay the same
         * (e.g. 1.2.3 -> 1.2.4, or 1.2 -> 1.2.1). Versions with fewer than
         * three numeric parts are zero-padded so 2-part schemes still get
         * patch updates instead of being silently blocked.
         *
         * Note: this only governs *automatic* background updates. Admins
         * can still update any plugin manually from the Plugins screen.
         */
        private function is_security_update($item) {
            if (!isset($item->new_version) || !isset($item->Version)) {
                return false;
            }

            $current_parts = $this->normalize_version_parts((string) $item->Version);
            $new_parts     = $this->normalize_version_parts((string) $item->new_version);

            // Same major and minor = patch update (allowed for auto-update).
            return ($current_parts[0] === $new_parts[0] && $current_parts[1] === $new_parts[1]);
        }

        /**
         * Normalize a version string into [major, minor, patch] integers.
         * Strips suffixes like "-beta" and pads short versions with zeros.
         */
        private function normalize_version_parts($version) {
            $clean = preg_replace('/[^0-9.]/', '', $version);
            $parts = array_map('intval', explode('.', $clean));
            return array_pad($parts, 3, 0);
        }

        /**
         * Filter core updates to allow only security patches
         */
        public function filter_core_updates($transient) {
            if (empty($transient->updates)) {
                return $transient;
            }
            
            // Filter out major updates, keep security patches
            $filtered_updates = array();
            foreach ($transient->updates as $update) {
                if (isset($update->version)) {
                    $current_parts = explode('.', get_bloginfo('version'));
                    $update_parts = explode('.', $update->version);
                    
                    // Keep if it's a patch version (same major.minor)
                    if (count($current_parts) >= 2 && count($update_parts) >= 2) {
                        if ($current_parts[0] === $update_parts[0] && $current_parts[1] === $update_parts[1]) {
                            $filtered_updates[] = $update;
                        }
                    }
                }
            }
            
            if (empty($filtered_updates)) {
                return $this->remove_core_updates();
            }
            
            $transient->updates = $filtered_updates;
            return $transient;
        }

        /**
         * Remove core update notifications
         */
        private function remove_core_updates() {
            global $wp_version;
            return (object) array(
                'last_checked' => time(),
                'version_checked' => $wp_version,
            );
        }

        /**
         * Remove theme update notifications
         */
        public function remove_theme_updates() {
            return $this->remove_core_updates();
        }

        /**
         * Disable WordPress file editing in admin
         */
        public function disable_file_editing() {
            // Disable file editing in WordPress admin
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        /**
         * Restrict file upload types to safe extensions only
         */
        public function restrict_file_uploads($mimes) {
            // Remove dangerous file types
            $dangerous_types = array(
                'exe', 'com', 'bat', 'cmd', 'scr', 'pif', 'msi', 'dll',
                'php', 'php3', 'php4', 'php5', 'phtml', 'phps',
                'js', 'vbs', 'jar', 'class',
                'sh', 'cgi', 'pl', 'py',
                'asp', 'aspx', 'jsp',
                'sql', 'db'
            );

            foreach ($dangerous_types as $type) {
                if (isset($mimes[$type])) {
                    unset($mimes[$type]);
                }
            }

            // Also remove some that might be in different formats
            unset($mimes['php|php3|php4|php5']);
            unset($mimes['js']);
            
            return $mimes;
        }

        /**
         * Block dangerous file uploads with additional checks
         */
        public function block_dangerous_uploads($file) {
            $filename = $file['name'];
            $filetype = wp_check_filetype($filename);
            
            // List of dangerous extensions (comprehensive)
            $dangerous_extensions = array(
                'php', 'php3', 'php4', 'php5', 'phtml', 'phps', 'phar',
                'exe', 'com', 'bat', 'cmd', 'scr', 'pif', 'msi', 'dll',
                'js', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'wsc',
                'jar', 'class', 'war', 'ear',
                'sh', 'bash', 'csh', 'ksh', 'fish',
                'cgi', 'pl', 'py', 'rb', 'go',
                'asp', 'aspx', 'jsp', 'cfm', 'cfc',
                'sql', 'db', 'sqlite', 'mdb',
                'htaccess', 'htpasswd', 'ini', 'conf', 'config',
                'log', 'bak', 'backup', 'old', 'orig', 'save', 'swp', 'tmp'
            );

            // Get file extension
            $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            
            // Block if extension is dangerous
            if (in_array($file_extension, $dangerous_extensions)) {
                $file['error'] = 'File type not allowed for security reasons.';
                return $file;
            }

            // Additional check for files without extensions
            if (empty($file_extension)) {
                $file['error'] = 'Files without extensions are not allowed.';
                return $file;
            }

            // Check for double extensions (e.g., file.php.jpg)
            $filename_parts = explode('.', $filename);
            if (count($filename_parts) > 2) {
                foreach ($filename_parts as $part) {
                    if (in_array(strtolower($part), $dangerous_extensions)) {
                        $file['error'] = 'Files with multiple extensions are not allowed.';
                        return $file;
                    }
                }
            }

            return $file;
        }

        /**
         * Detect the web server type from SERVER_SOFTWARE.
         *
         * Returns 'nginx' for Nginx / OpenResty. Returns 'apache' for everything
         * else (Apache, LiteSpeed, unknown) — all of which honour .htaccess files.
         *
         * @return string 'nginx' | 'apache'
         */
        private static function detect_server() {
            $sw = isset( $_SERVER['SERVER_SOFTWARE'] )
                ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) )
                : '';
            if ( strpos( $sw, 'nginx' ) !== false || strpos( $sw, 'openresty' ) !== false ) {
                return 'nginx';
            }
            return 'apache';
        }

        /**
         * Route upload PHP-execution protection to the right method for the
         * current web server.
         *
         * Apache / LiteSpeed: write the .htaccess (existing behaviour).
         * Nginx / OpenResty:  skip the file — Nginx ignores .htaccess entirely.
         *                     An admin notice (nginx_upload_notice) surfaces the
         *                     equivalent location block to add server-side.
         */
        public function setup_upload_protection() {
            if ( 'nginx' === self::detect_server() ) {
                return;
            }
            $this->create_upload_htaccess();
        }

        /**
         * Admin notice shown on Nginx servers when file_security is enabled.
         *
         * Shown on all admin pages (dismissible per-user) and always shown on
         * the KW Security settings page regardless of dismissal so the config
         * requirement is never silently forgotten.
         */
        public function nginx_upload_notice() {
            if ( ! current_user_can( 'manage_options' ) ) {
                return;
            }

            // Determine whether we are on the KW Security settings page.
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only page check, no state change.
            $on_settings_page = isset( $_GET['page'] ) && sanitize_key( $_GET['page'] ) === KW_Security_Settings::PAGE_SLUG;

            // Outside the settings page, respect per-user dismissal.
            if ( ! $on_settings_page && get_user_meta( get_current_user_id(), 'kw_security_nginx_notice_dismissed', true ) ) {
                return;
            }

            // Build the uploads URL path for the Nginx location directive.
            $upload_info  = wp_upload_dir();
            $uploads_path = rtrim( wp_parse_url( $upload_info['baseurl'], PHP_URL_PATH ), '/' );

            $dismiss_url = wp_nonce_url(
                admin_url( 'admin-post.php?action=kw_nginx_notice_dismiss' ),
                'kw_nginx_notice_dismiss'
            );

            $snippet = 'location ~* ' . esc_html( $uploads_path ) . '/.*\\.(php|php3|php4|php5|phtml|phps|phar|exe|com|bat|cmd|scr|cgi|pl|sh)$ {' . "\n"
                     . '    deny all;' . "\n"
                     . '}';

            ?>
            <div class="notice notice-warning <?php echo $on_settings_page ? '' : 'is-dismissible'; ?>">
                <p>
                    <strong><?php esc_html_e( 'KW Security — Action required on Nginx: uploads directory is not protected.', 'kw-security' ); ?></strong>
                </p>
                <p>
                    <?php esc_html_e( 'This site runs on Nginx (or OpenResty). Nginx ignores .htaccess files, so the uploads PHP-execution block written by KW Security has no effect. Add the following block inside your server {} configuration and reload Nginx:', 'kw-security' ); ?>
                </p>
                <pre style="background:#f6f7f7;border:1px solid #ddd;padding:10px 14px;overflow:auto;font-size:12px;line-height:1.6;"><?php echo esc_html( $snippet ); ?></pre>
                <p style="color:#666;font-size:12px;">
                    <?php esc_html_e( 'On Servebolt: paste this into the Nginx configuration panel for this site and click Save, then Activate.', 'kw-security' ); ?>
                </p>
                <?php if ( ! $on_settings_page ) : ?>
                <p>
                    <a href="<?php echo esc_url( $dismiss_url ); ?>" class="button button-secondary">
                        <?php esc_html_e( 'Dismiss', 'kw-security' ); ?>
                    </a>
                </p>
                <?php endif; ?>
            </div>
            <?php
        }

        /**
         * Handle the "Dismiss" GET request from the Nginx admin notice.
         * Stores the dismissal in per-user meta so other users still see the notice.
         */
        public function handle_nginx_notice_dismiss() {
            check_admin_referer( 'kw_nginx_notice_dismiss' );
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }
            update_user_meta( get_current_user_id(), 'kw_security_nginx_notice_dismissed', 1 );
            wp_safe_redirect( wp_get_referer() ?: admin_url() );
            exit;
        }

        /**
         * Create .htaccess file in uploads directory to prevent PHP execution
         */
        public function create_upload_htaccess() {
            $upload_dir = wp_upload_dir();
            $htaccess_file = $upload_dir['basedir'] . '/.htaccess';
            
            // .htaccess content to prevent PHP execution
            $htaccess_content = "# KW Security - Prevent PHP execution in uploads directory\n";
            $htaccess_content .= "<Files *.php>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php3>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php4>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.php5>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.phtml>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.phps>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n";
            $htaccess_content .= "<Files *.phar>\n";
            $htaccess_content .= "deny from all\n";
            $htaccess_content .= "</Files>\n\n";
            $htaccess_content .= "# Prevent access to any files with these extensions\n";
            $htaccess_content .= "<FilesMatch \"\\.(php|php3|php4|php5|phtml|phps|phar|exe|com|bat|cmd|scr|cgi|pl|sh)$\">\n";
            $htaccess_content .= "Order allow,deny\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "</FilesMatch>\n";

            // Only create if it doesn't exist or if it doesn't contain our rules.
            // Local filesystem ops are intentional here: writing .htaccess into the uploads
            // directory at plugin activation. wp_remote_get is for HTTP; WP_Filesystem requires
            // FTP credentials prompts during activation which would break unattended setups.
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if (!file_exists($htaccess_file) || strpos(file_get_contents($htaccess_file), 'KW Security') === false) {
                // If file exists, append our rules
                if (file_exists($htaccess_file)) {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                    $existing_content = file_get_contents($htaccess_file);
                    $htaccess_content = $existing_content . "\n\n" . $htaccess_content;
                }

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
                file_put_contents($htaccess_file, $htaccess_content);
            }
        }

        /**
         * Disable comments in WordPress admin
         */
        public function disable_comments_admin() {
            // Redirect any user trying to access comments page
            global $pagenow;

            if ($pagenow === 'edit-comments.php') {
                wp_safe_redirect(admin_url());
                exit;
            }

            // Disable support for comments and trackbacks in post types
            foreach (get_post_types() as $post_type) {
                if (post_type_supports($post_type, 'comments')) {
                    remove_post_type_support($post_type, 'comments');
                    remove_post_type_support($post_type, 'trackbacks');
                }
            }
        }

        /**
         * Remove the "Recent Comments" dashboard widget. Hooked on
         * wp_dashboard_setup so it runs after the meta box is registered.
         */
        public function remove_dashboard_comments_widget() {
            remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');
        }

        /**
         * Remove comments from admin menu
         */
        public function disable_comments_admin_menu() {
            remove_menu_page('edit-comments.php');
        }

        /**
         * Remove comments from admin bar
         */
        public function disable_comments_admin_bar() {
            if (is_admin_bar_showing()) {
                remove_action('admin_bar_menu', 'wp_admin_bar_comments_menu', 60);
            }
        }

        /**
         * Disable comment reply script
         */
        public function disable_comments_reply_script() {
            if (is_admin()) {
                return;
            }
            
            wp_deregister_script('comment-reply');
        }

        /**
         * Remove comment endpoints from REST API
         */
        public function disable_comments_rest_api($endpoints) {
            if (isset($endpoints['/wp/v2/comments'])) {
                unset($endpoints['/wp/v2/comments']);
            }
            if (isset($endpoints['/wp/v2/comments/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/comments/(?P<id>[\d]+)']);
            }
            return $endpoints;
        }
    }

    new KW_Security();
}