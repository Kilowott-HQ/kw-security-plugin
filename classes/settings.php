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
                'activity_log'      => true,
                'comments'          => true,
                'file_security'     => true,
                'update_management' => true,
                'xmlrpc_pingback'   => true,
                'security_headers'  => true,
                'user_enumeration'  => true,
                'login_rate_limit'  => true,
                'file_integrity'    => true,
                'password_policy'   => true,
                'disable_author_url' => true,
                'hide_login_url'    => false,
                'maintenance_api'   => true,
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
                'activity_log' => array(
                    'label'       => __( 'Activity Log', 'kw-security' ),
                    'description' => __( 'Records security-relevant events (logins, logouts, failed logins, plugin/theme changes, post edits, file uploads, and settings saves) to a database log. View the log at <a href="options-general.php?page=kw-activity-log">Settings → Activity Log</a>.', 'kw-security' ),
                ),
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
                    'description' => __( 'Redirects /?author=N requests by anonymous visitors to the homepage and requires authentication for the /wp/v2/users REST endpoint, preventing username discovery.', 'kw-security' ),
                ),
                'disable_author_url' => array(
                    'label'       => __( 'Disable Author URLs', 'kw-security' ),
                    'description' => __( 'Redirects /author/username archive pages to the homepage for all visitors, preventing username exposure via author slugs.', 'kw-security' ),
                ),
                'login_rate_limit' => array(
                    'label'       => __( 'Login Rate Limiting', 'kw-security' ),
                    'description' => __( 'Locks out an IP address for 1 hour after 5 failed login attempts within 15 minutes. Replaces "Invalid username/password" errors with a generic message so attackers cannot enumerate valid usernames.', 'kw-security' ),
                ),
                'file_integrity' => array(
                    'label'       => __( 'File Integrity Monitoring', 'kw-security' ),
                    'description' => __( 'Daily WP-Cron scan of the WordPress root directory. Emails the site admin when unknown PHP files appear or when index.php / wp-config.php are modified.', 'kw-security' ),
                ),
                'password_policy' => array(
                    'label'       => __( 'Strong Password Policy (Admins)', 'kw-security' ),
                    'description' => __( 'Requires administrator passwords to be at least 12 characters and include an uppercase letter, a lowercase letter, a number, and a special character. Enforced when admins are created, when passwords are changed, and during password reset. Other roles are unaffected.', 'kw-security' ),
                ),
                'hide_login_url' => array(
                    'label'       => __( 'Hide Login URL', 'kw-security' ),
                    'description' => __( 'Replaces /wp-login.php and /wp-admin with a custom slug. <strong>Off by default</strong> — bookmark your custom URL before saving, or you may lock yourself out. Configure the slug below.', 'kw-security' ),
                ),
                'maintenance_api' => array(
                    'label'       => __( 'Maintenance API', 'kw-security' ),
                    'description' => __( 'Exposes a read-only REST endpoint (<code>/wp-json/kw-security/v1/site-status</code>) used by the Kilowott maintenance agent to fetch WordPress version, PHP version, and plugin update status. Enabled by default — the endpoint requires a Bearer key and is rate-limited to 20 req/hour.', 'kw-security' ),
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

            // Maintenance API key — stored as a plain string.
            register_setting( self::SETTINGS_GROUP, KW_Maintenance_API::OPTION_KEY, array(
                'type'              => 'string',
                'sanitize_callback' => 'sanitize_text_field',
                'default'           => '',
            ) );

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
            // (File Integrity status is rendered OUTSIDE the main settings
            // form by render_file_integrity_panel() — its action buttons
            // post to admin-post.php as separate forms, and HTML does not
            // allow nested forms.)
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

            // ---- Section 3: Maintenance API ----------------------------
            add_settings_section(
                'kw_security_maintenance_section',
                __( 'Maintenance API', 'kw-security' ),
                array( $this, 'maintenance_section_desc' ),
                self::PAGE_SLUG
            );

            add_settings_field(
                KW_Maintenance_API::OPTION_KEY,
                '<label for="kw_maintenance_key">' . esc_html__( 'API Key', 'kw-security' ) . '</label>',
                array( $this, 'render_maintenance_key' ),
                self::PAGE_SLUG,
                'kw_security_maintenance_section'
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

        /**
         * Render the File Integrity panel. Rendered OUTSIDE the main
         * settings form because its action buttons are their own forms
         * (HTML does not allow nested forms — nesting silently breaks
         * the outer "Save Changes" button).
         */
        public function render_file_integrity_panel() {
            ?>
            <h2><?php esc_html_e( 'File Integrity Status', 'kw-security' ); ?></h2>
            <?php

            if ( ! self::is_enabled( 'file_integrity' ) ) {
                echo '<p>' . esc_html__( 'Enable the "File Integrity Monitoring" feature toggle above and save settings to activate daily scans.', 'kw-security' ) . '</p>';
                return;
            }

            $last_scan  = (int) get_option( 'kw_security_file_last_scan', 0 );
            $last_label = $last_scan
                ? sprintf(
                    /* translators: %s: human-readable time difference */
                    esc_html__( '%s ago', 'kw-security' ),
                    human_time_diff( $last_scan, time() )
                )
                : esc_html__( 'never (cron will run within 24 hours)', 'kw-security' );

            $admin_email = esc_html( get_option( 'admin_email' ) );
            ?>
            <p>
                <?php
                /* translators: %1$s: last scan time, %2$s: admin email */
                echo wp_kses_post( sprintf(
                    __( 'Last scan: <strong>%1$s</strong>. Alerts are emailed to <code>%2$s</code>.', 'kw-security' ),
                    esc_html( $last_label ),
                    $admin_email
                ) );
                ?>
            </p>
            <p>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px;">
                    <input type="hidden" name="action" value="kw_security_run_scan" />
                    <?php wp_nonce_field( 'kw_security_run_scan' ); ?>
                    <?php submit_button( __( 'Run Scan Now', 'kw-security' ), 'secondary', 'submit', false ); ?>
                </form>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;" onsubmit="return confirm('<?php echo esc_js( __( 'Reset baseline? Current root files will become the new known-good state. Use only after verifying the site is clean.', 'kw-security' ) ); ?>');">
                    <input type="hidden" name="action" value="kw_security_reset_baseline" />
                    <?php wp_nonce_field( 'kw_security_reset_baseline' ); ?>
                    <?php submit_button( __( 'Reset Baseline', 'kw-security' ), 'secondary', 'submit', false ); ?>
                </form>
            </p>
            <?php
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
            $status   = $enabled ? __( 'Enabled', 'kw-security' ) : __( 'Disabled', 'kw-security' );
            ?>
            <label>
                <input type="checkbox"
                       class="kw-feature-toggle"
                       name="<?php echo esc_attr( $name ); ?>"
                       value="1"
                       <?php checked( $enabled ); ?> />
                <span class="kw-toggle-status"><?php echo esc_html( $status ); ?></span>
            </label>
            <p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
            <?php
        }

        public function maintenance_section_desc() {
            if ( ! self::is_enabled( 'maintenance_api' ) ) {
                echo '<p><em>'
                    . esc_html__( 'The Maintenance API is currently disabled. Enable the toggle above and save to activate the endpoint.', 'kw-security' )
                    . '</em></p>';
                return;
            }
            $endpoint = home_url( '/wp-json/kw-security/v1/site-status' );
            echo '<p>'
                . esc_html__( 'Endpoint is active. The key is sent via the Authorization: Bearer header — never in the URL.', 'kw-security' )
                . '</p>';
            echo '<p>'
                . esc_html__( 'Endpoint: ', 'kw-security' )
                . '<code>' . esc_html( $endpoint ) . '</code>'
                . '</p>';
        }

        public function render_maintenance_key() {
            $key = get_option( KW_Maintenance_API::OPTION_KEY, '' );
            ?>
            <input
                type="text"
                id="kw_maintenance_key"
                name="<?php echo esc_attr( KW_Maintenance_API::OPTION_KEY ); ?>"
                value="<?php echo esc_attr( $key ); ?>"
                class="regular-text"
                autocomplete="off"
                spellcheck="false"
            />
            <button
                type="button"
                class="button"
                style="margin-left:6px"
                onclick="document.getElementById('kw_maintenance_key').value = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2,'0')).join('')"
            ><?php esc_html_e( 'Generate Key', 'kw-security' ); ?></button>
            <p class="description">
                <?php esc_html_e( 'Set this same value as KW_MAINTENANCE_KEY in the maintenance-agent .env file. Click Generate Key, then Save Changes to activate. Regenerating invalidates the old key immediately.', 'kw-security' ); ?>
            </p>
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
                    wp_kses( $trailing, array( 'code' => array() ) )
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
                    wp_kses( $trailing, array( 'code' => array() ) )
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

                <?php // WordPress core's options-head.php already calls settings_errors() for pages under Settings menu — calling it here would duplicate the "Settings saved." notice. ?>

                <?php
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect-back display set by admin-post handler; the underlying handler is nonce-protected via check_admin_referer().
                if ( ! empty( $_GET['kw_scan'] ) ) : ?>
                    <div class="notice notice-info is-dismissible">
                        <p><?php echo esc_html( sanitize_text_field( wp_unslash( $_GET['kw_scan'] ) ) ); ?></p>
                    </div>
                <?php endif; ?>

                <?php
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of the standard "settings-updated" flag set by WP core's options.php after its own nonce verification.
                if ( isset( $_GET['settings-updated'] ) && self::is_enabled( 'hide_login_url' ) ) :
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

                <?php $this->render_file_integrity_panel(); ?>
            </div>
            <script>
            ( function () {
                document.querySelectorAll( '.kw-feature-toggle' ).forEach( function ( checkbox ) {
                    checkbox.addEventListener( 'change', function () {
                        var span = this.parentNode.querySelector( '.kw-toggle-status' );
                        if ( span ) {
                            span.textContent = this.checked ? '<?php echo esc_js( __( 'Enabled', 'kw-security' ) ); ?>' : '<?php echo esc_js( __( 'Disabled', 'kw-security' ) ); ?>';
                        }
                    } );
                } );
            } )();
            </script>
            <?php
        }
    }

    new KW_Security_Settings();
}
