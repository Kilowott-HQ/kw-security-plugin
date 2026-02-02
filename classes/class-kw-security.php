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
         * Initializes WordPress hooks for security features
         */
        private function init_hooks() {
            // Security update controls
            add_filter('allow_minor_auto_core_updates', '__return_true');
            add_filter('allow_major_auto_core_updates', '__return_false');
            add_filter('auto_update_plugin', array($this, 'allow_security_updates_only'));
            add_filter('auto_update_theme', '__return_false');
            
            // Security enhancements
            add_filter('xmlrpc_enabled', '__return_false');
            
            // Comment security - disable comments completely
            add_action('admin_init', array($this, 'disable_comments_admin'));
            add_action('init', array($this, 'disable_comments_frontend'));
            add_filter('comments_open', '__return_false', 20, 2);
            add_filter('pings_open', '__return_false', 20, 2);
            add_filter('comments_array', '__return_empty_array', 10, 2);
            
            // Update notification filtering
            add_filter('pre_site_transient_update_core', array($this, 'filter_core_updates'));
            add_filter('pre_site_transient_update_themes', array($this, 'remove_theme_updates'));
        }

        /**
         * Plugin activation hook
         */
        public static function plugin_activation() {
            // Plugin activated successfully
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
         * Check if update contains security fixes
         */
        private function is_security_update($item) {
            if (isset($item->new_version) && isset($item->Version)) {
                // Allow patch versions (x.x.X) which are typically security fixes
                $current_parts = explode('.', $item->Version);
                $new_parts = explode('.', $item->new_version);
                
                if (count($current_parts) >= 3 && count($new_parts) >= 3) {
                    // Same major and minor version = likely security patch
                    return ($current_parts[0] === $new_parts[0] && $current_parts[1] === $new_parts[1]);
                }
            }
            return false;
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
         * Disable comments in WordPress admin
         */
        public function disable_comments_admin() {
            // Redirect any user trying to access comments page
            global $pagenow;
            
            if ($pagenow === 'edit-comments.php') {
                wp_redirect(admin_url());
                exit;
            }
            
            // Remove comments metabox from dashboard
            remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');
            
            // Disable support for comments and trackbacks in post types
            foreach (get_post_types() as $post_type) {
                if (post_type_supports($post_type, 'comments')) {
                    remove_post_type_support($post_type, 'comments');
                    remove_post_type_support($post_type, 'trackbacks');
                }
            }
        }

        /**
         * Disable comments on frontend
         */
        public function disable_comments_frontend() {
            // Close comments on the frontend
            add_filter('comments_open', '__return_false', 20, 2);
            add_filter('pings_open', '__return_false', 20, 2);
            
            // Hide existing comments
            add_filter('comments_array', '__return_empty_array', 10, 2);
            
            // Remove comments page in admin menu
            add_action('admin_menu', array($this, 'disable_comments_admin_menu'));
            
            // Remove comments links from admin bar
            add_action('init', array($this, 'disable_comments_admin_bar'));
            
            // Remove comment-reply script for themes that include it
            add_action('wp_enqueue_scripts', array($this, 'disable_comments_reply_script'), 100);
            
            // Remove REST API comment endpoints
            add_filter('rest_endpoints', array($this, 'disable_comments_rest_api'));
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