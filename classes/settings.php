<?php
/**
 * KW Security – Settings Manager
 *
 * Provides a single Settings → KW Security page with feature toggles and
 * configuration for every module shipped by the plugin.
 *
 * Each feature can be enabled or disabled independently. Disabled features
 * skip hook registration entirely (zero runtime cost), so a site that
 * needs WordPress comments enabled can simply turn the "Disable Comments"
 * toggle off — no plugin fork required.
 *
 * Default state: every security feature is ENABLED except "Hide Login URL"
 * (opt-in, because changing the login slug is disruptive on existing sites).
 *
 * Other modules check feature state via the static helper:
 *
 *   if ( KW_Security_Settings::is_enabled( 'security_headers' ) ) {
 *       new KW_Security_Headers();
 *   }
 *
 * Stored options are merged against defaults via wp_parse_args(), so a
 * future plugin update that adds a new toggle inherits its default on
 * existing sites automatically — no migration script needed.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Security_Settings' ) ) {

    class KW_Security_Settings {

        const OPTION_NAME = 'kw_security_features';
        const PAGE_SLUG   = 'kw-security';
        const SETTINGS_GROUP = 'kw_security_settings';

        public function __construct() {
            add_action( 'admin_menu', array( $this, 'register_page' ) );
            add_action( 'admin_init', array( $this, 'register_settings' ) );

            // "Settings" link on the Plugins screen for quick access.
            add_filter(
                'plugin_action_links_' . plugin_basename( KW_SECURITY_PLUGIN_FILE ),
                array( $this, 'plugin_action_links' )
            );
        }

        /**
         * Default feature state — every feature ON except Hide Login URL.
         *
         * @return array<string,bool>
         */
        public static function get_defaults() {
            return array(
                'comments'          => true,
                'file_security'     => true,
                'update_management' => true,
                'xmlrpc_pingback'   => true,
                'security_headers'  => true,
                'user_enumeration'  => true,
                'hide_login_url'    => false,
            );
        }

        /**
         * Whether a given feature is enabled on this site.
         *
         * Result is cached per-request to avoid repeated get_option calls
         * during hook registration.
         *
         * @param string $feature Feature key from get_defaults().
         * @return bool
         */
        public static function is_enabled( $feature ) {
            static $resolved = null;
            if ( null === $resolved ) {
                $stored = get_option( self::OPTION_NAME, array() );
                if ( ! is_array( $stored ) ) {
                    $stored = array();
                }
                $resolved = wp_parse_args( $stored, self::get_defaults() );
            }
            return ! empty( $resolved[ $feature ] );
        }

        /**
         * Human-readable metadata for each feature toggle.
         *
         * @return array<string,array{label:string,description:string}>
         */
        private function get_feature_metadata() {
            return array(
                'comments' => array(
                    'label'       => __( 'Disable Comments', 'kw-security' ),
                    'description' => __( 'Disables WordPress comments site-wide, removes comment admin pages, blocks comment REST endpoints, and disables pingbacks/trackbacks. Turn this OFF if the site genuinely needs comments.', 'kw-security' ),
                ),
                'file_security' => array(
                    'label'       => __( 'File Security', 'kw-security' ),
                    'description' => __( 'Restricts dangerous file uploads (.php, .exe, .js, etc.), blocks double-extension attacks, disables the WordPress file editor, and writes a .htaccess in /uploads/ to prevent PHP execution there.', 'kw-security' ),
                ),
                'update_management' => array(
                    'label'       => __( 'Controlled Auto-Updates', 'kw-security' ),
                    'description' => __( 'Allows security patch auto-updates only (e.g. 1.2.3 → 1.2.4) and blocks major/minor version updates for WordPress core, plugins, and themes. Manual updates from the admin remain unaffected.', 'kw-security' ),
                ),
                'xmlrpc_pingback' => array(
                    'label'       => __( 'Disable XML-RPC Pingbacks', 'kw-security' ),
                    'description' => __( 'Removes pingback methods from XML-RPC and disables XML-RPC entirely to prevent DDoS amplification attacks and brute-force login via xmlrpc.php.', 'kw-security' ),
                ),
                'security_headers' => array(
                    'label'       => __( 'HTTP Security Headers', 'kw-security' ),
                    'description' => __( 'Sends X-Frame-Options, Content-Security-Policy, HSTS (on HTTPS), Referrer-Policy, Permissions-Policy, and X-Content-Type-Options on every response.', 'kw-security' ),
                ),
                'user_enumeration' => array(
                    'label'       => __( 'Block User Enumeration', 'kw-security' ),
                    'description' => __( 'Returns 404 for /?author=N requests by anonymous visitors and requires authentication for the /wp/v2/users REST endpoint, preventing username discovery.', 'kw-security' ),
                ),
                'hide_login_url' => array(
                    'label'       => __( 'Hide Login URL', 'kw-security' ),
                    'description' => __( 'Replaces /wp-login.php and /wp-admin with a custom slug. <strong>Off by default</strong> — bookmark your custom URL before saving, or you may lock yourself out. Configure the slug below.', 'kw-security' ),
                ),
            );
        }

        /**
         * Register Settings → KW Security in the admin menu.
         */
        public function register_page() {
            add_options_page(
                __( 'KW Security', 'kw-security' ),
                __( 'KW Security', 'kw-security' ),
                'manage_options',
                self::PAGE_SLUG,
                array( $this, 'render_page' )
            );
        }

        /**
         * Add a Settings link next to the plugin in the Plugins list.
         *
         * @param array $links
         * @return array
         */
        public function plugin_action_links( $links ) {
            $url = admin_url( 'options-general.php?page=' . self::PAGE_SLUG );
            $settings_link = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'kw-security' ) . '</a>';
            array_unshift( $links, $settings_link );
            return $links;
        }

        /**
         * Register all settings fields and sections.
         */
        public function register_settings() {
            // Feature toggles — single array option.
            register_setting( self::SETTINGS_GROUP, self::OPTION_NAME, array(
                'type'              => 'array',
                'sanitize_callback' => array( $this, 'sanitize_features' ),
                'default'           => self::get_defaults(),
            ) );

            // Hide Login URL configuration — kept as separate options for
            // backward compatibility with sites that already have these set.
            register_setting( self::SETTINGS_GROUP, 'whl_page',           'sanitize_title_with_dashes' );
            register_setting( self::SETTINGS_GROUP, 'whl_redirect_admin', 'sanitize_title_with_dashes' );

            // ---- Section 1: Feature toggles ----------------------------
            add_settings_section(
                'kw_security_features_section',
                __( 'Feature Toggles', 'kw-security' ),
                array( $this, 'features_section_desc' ),
                self::PAGE_SLUG
            );

            foreach ( $this->get_feature_metadata() as $key => $meta ) {
                add_settings_field(
                    'kw_security_feature_' . $key,
                    esc_html( $meta['label'] ),
                    array( $this, 'render_feature_toggle' ),
                    self::PAGE_SLUG,
                    'kw_security_features_section',
                    array(
                        'key'         => $key,
                        'label'       => $meta['label'],
                        'description' => $meta['description'],
                    )
                );
            }

            // ---- Section 2: Hide Login URL configuration ---------------
            add_settings_section(
                'kw_security_hide_login_section',
                __( 'Hide Login URL Configuration', 'kw-security' ),
                array( $this, 'hide_login_section_desc' ),
                self::PAGE_SLUG
            );

            add_settings_field(
                'whl_page',
                '<label for="whl_page">' . esc_html__( 'Login URL', 'kw-security' ) . '</label>',
                array( $this, 'render_whl_page' ),
                self::PAGE_SLUG,
                'kw_security_hide_login_section'
            );

            add_settings_field(
                'whl_redirect_admin',
                '<label for="whl_redirect_admin">' . esc_html__( 'Redirection URL', 'kw-security' ) . '</label>',
                array( $this, 'render_whl_redirect' ),
                self::PAGE_SLUG,
                'kw_security_hide_login_section'
            );
        }

        /**
         * Sanitize feature toggle submission. Anything missing from input
         * is treated as unchecked (false).
         *
         * @param mixed $input
         * @return array<string,bool>
         */
        public function sanitize_features( $input ) {
            $defaults = self::get_defaults();
            $clean    = array();
            foreach ( $defaults as $key => $default ) {
                $clean[ $key ] = ! empty( $input[ $key ] );
            }
            return $clean;
        }

        // ----------------------------------------------------------------
        // Section descriptions
        // ----------------------------------------------------------------

        public function features_section_desc() {
            echo '<p>'
                . esc_html__( 'Enable or disable individual security features. Disabled features have zero runtime cost — their hooks are not registered at all.', 'kw-security' )
                . '</p>';
        }

        public function hide_login_section_desc() {
            echo '<p>';
            if ( self::is_enabled( 'hide_login_url' ) ) {
                $current_url = home_url( '/' . $this->current_login_slug() . '/' );
                echo wp_kses_post( sprintf(
                    /* translators: %s: current login URL */
                    __( 'Hide Login URL is currently <strong>active</strong>. Your custom login URL is: <a href="%1$s"><code>%1$s</code></a> &mdash; bookmark this!', 'kw-security' ),
                    esc_url( $current_url )
                ) );
            } else {
                esc_html_e( 'These fields configure the custom login slug used by the "Hide Login URL" feature above. They take effect once the feature toggle is enabled.', 'kw-security' );
            }
            echo '</p>';
        }

        // ----------------------------------------------------------------
        // Field renderers
        // ----------------------------------------------------------------

        /**
         * @param array{key:string,label:string,description:string} $args
         */
        public function render_feature_toggle( $args ) {
            $key      = $args['key'];
            $enabled  = self::is_enabled( $key );
            $name     = self::OPTION_NAME . '[' . $key . ']';
            ?>
            <label>
                <input type="checkbox"
                       name="<?php echo esc_attr( $name ); ?>"
                       value="1"
                       <?php checked( $enabled ); ?> />
                <?php echo esc_html__( 'Enabled', 'kw-security' ); ?>
            </label>
            <p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
            <?php
        }

        public function render_whl_page() {
            $value = $this->current_login_slug();
            if ( get_option( 'permalink_structure' ) ) {
                $trailing = ( '/' === substr( get_option( 'permalink_structure' ), -1, 1 ) ) ? ' <code>/</code>' : '';
                printf(
                    '<code>%s</code> <input id="whl_page" type="text" name="whl_page" value="%s" class="regular-text">%s',
                    esc_html( trailingslashit( home_url() ) ),
                    esc_attr( $value ),
                    $trailing // already-escaped fragment
                );
            } else {
                printf(
                    '<code>%s?</code> <input id="whl_page" type="text" name="whl_page" value="%s" class="regular-text">',
                    esc_html( trailingslashit( home_url() ) ),
                    esc_attr( $value )
                );
            }
            echo '<p class="description">'
                . esc_html__( 'Slug for the custom login page. Avoid "login", "admin", or "wp-login".', 'kw-security' )
                . '</p>';
        }

        public function render_whl_redirect() {
            $value = $this->current_redirect_slug();
            if ( get_option( 'permalink_structure' ) ) {
                $trailing = ( '/' === substr( get_option( 'permalink_structure' ), -1, 1 ) ) ? ' <code>/</code>' : '';
                printf(
                    '<code>%s</code> <input id="whl_redirect_admin" type="text" name="whl_redirect_admin" value="%s" class="regular-text">%s',
                    esc_html( trailingslashit( home_url() ) ),
                    esc_attr( $value ),
                    $trailing
                );
            } else {
                printf(
                    '<code>%s?</code> <input id="whl_redirect_admin" type="text" name="whl_redirect_admin" value="%s" class="regular-text">',
                    esc_html( trailingslashit( home_url() ) ),
                    esc_attr( $value )
                );
            }
            echo '<p class="description">'
                . esc_html__( 'Where unauthorized visitors are redirected when they hit /wp-login.php or /wp-admin. Use "404" to show a not-found page.', 'kw-security' )
                . '</p>';
        }

        // ----------------------------------------------------------------
        // Helpers
        // ----------------------------------------------------------------

        private function current_login_slug() {
            $slug = get_option( 'whl_page' );
            return $slug ? $slug : 'login';
        }

        private function current_redirect_slug() {
            $slug = get_option( 'whl_redirect_admin' );
            return $slug ? $slug : '404';
        }

        // ----------------------------------------------------------------
        // Page renderer
        // ----------------------------------------------------------------

        public function render_page() {
            if ( ! current_user_can( 'manage_options' ) ) {
                return;
            }
            ?>
            <div class="wrap">
                <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

                <?php settings_errors(); ?>

                <?php if ( isset( $_GET['settings-updated'] ) && self::is_enabled( 'hide_login_url' ) ) :
                    $current_url = home_url( '/' . $this->current_login_slug() . '/' ); ?>
                    <div class="notice notice-success is-dismissible">
                        <p>
                            <?php echo wp_kses_post( sprintf(
                                /* translators: %s: custom login URL */
                                __( 'Settings saved. Your login page is now at: <strong><a href="%1$s">%1$s</a></strong> — bookmark this!', 'kw-security' ),
                                esc_url( $current_url )
                            ) ); ?>
                        </p>
                    </div>
                <?php endif; ?>

                <form method="post" action="options.php">
                    <?php
                    settings_fields( self::SETTINGS_GROUP );
                    do_settings_sections( self::PAGE_SLUG );
                    submit_button();
                    ?>
                </form>
            </div>
            <?php
        }
    }

    new KW_Security_Settings();
}
