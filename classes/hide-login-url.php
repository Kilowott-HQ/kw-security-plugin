<?php
/**
 * KW Security – Hide Login URL
 *
 * Protects the site by changing the login URL and preventing direct access
 * to wp-login.php and wp-admin while not logged in.
 *
 * Core logic is ported from WPS Hide Login (GPL v2) by WPServeur / NicolasKulka.
 * Adapted as a standalone class for the KW Security plugin (no namespace / composer).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'KW_Hide_Login' ) ) {

	class KW_Hide_Login {

		/**
		 * Whether the current request was originally for wp-login.php
		 * (before we rewrote REQUEST_URI).
		 *
		 * @var bool
		 */
		private $wp_login_php = false;

		// ----------------------------------------------------------------
		// Bootstrap
		// ----------------------------------------------------------------

		public function __construct() {
			// One-time migration from the old option structure.
			$this->maybe_migrate_options();

			// Conflict detection. Hooked early to see if WPS Hide Login is active.
			add_action( 'plugins_loaded', array( $this, 'init_or_conflict' ), 1 );
		}

		/**
		 * Checks if the original WPS Hide Login plugin is active.
		 * If conflicted, stops initialization and shows a warning.
		 */
		public function init_or_conflict() {
			// Check if WPS Hide Login is running
			if ( class_exists( 'WPS\WPS_Hide_Login\Plugin' ) || defined( 'WPS_HIDE_LOGIN_VERSION' ) ) {
				add_action( 'admin_notices', array( $this, 'conflict_notice' ) );
				return;
			}

			// Filters that must run very early.
			add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ), 9999 );
			add_action( 'wp_loaded',      array( $this, 'wp_loaded' ) );
			add_action( 'setup_theme',    array( $this, 'setup_theme' ), 1 );
			add_action( 'init',           array( $this, 'init_block_access' ) );

			// URL filters — rewrite every internal wp-login.php reference.
			add_filter( 'site_url',         array( $this, 'site_url' ),         10, 4 );
			add_filter( 'network_site_url', array( $this, 'network_site_url' ), 10, 3 );
			add_filter( 'wp_redirect',      array( $this, 'wp_redirect' ),       10, 2 );
			add_filter( 'login_url',        array( $this, 'login_url' ),         10, 3 );

			// Welcome-email link fix.
			add_filter( 'site_option_welcome_email', array( $this, 'welcome_email' ) );

			// Remove the default admin-location redirect so we can handle it ourselves.
			remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

			// Privacy / GDPR data-export confirmation link fix.
			add_filter( 'user_request_action_email_content',
				array( $this, 'user_request_action_email_content' ), 999, 2 );
		}

		/**
		 * Admin notice shown if a conflict with WPS Hide Login is detected.
		 */
		public function conflict_notice() {
			echo '<div class="notice notice-error is-dismissible"><p>'
				. esc_html__( 'KW Security — Hide Login URL functionality has been disabled because the WPS Hide Login plugin is currently active. Please deactivate WPS Hide Login to prevent conflicts.', 'kw-security' )
				. '</p></div>';
		}

		// ----------------------------------------------------------------
		// Option helpers
		// ----------------------------------------------------------------

		/**
		 * One-time migration: if the old array option exists, copy values
		 * into the new flat options and delete the old one.
		 */
		private function maybe_migrate_options() {
			$old = get_option( 'custom_hide_login_options' );
			if ( $old && is_array( $old ) ) {
				if ( ! get_option( 'whl_page' ) && ! empty( $old['login_slug'] ) ) {
					update_option( 'whl_page', sanitize_title_with_dashes( $old['login_slug'] ) );
				}
				if ( ! get_option( 'whl_redirect_admin' ) && ! empty( $old['redirect_slug'] ) ) {
					update_option( 'whl_redirect_admin', sanitize_title_with_dashes( $old['redirect_slug'] ) );
				}
				delete_option( 'custom_hide_login_options' );
			}
		}

		/**
		 * Custom login slug (e.g. "my-login"). Falls back to "login".
		 *
		 * @param string|int $blog_id  Optional blog ID for multisite.
		 * @return string
		 */
		private function new_login_slug( $blog_id = '' ) {
			if ( $blog_id ) {
				if ( $slug = get_blog_option( $blog_id, 'whl_page' ) ) {
					return $slug;
				}
			} else {
				if ( $slug = get_option( 'whl_page' ) ) {
					return $slug;
				}
			}
			return 'login';
		}

		/**
		 * Redirect slug when blocking unauthorized access (e.g. "404"). Falls back to "404".
		 *
		 * @return string
		 */
		private function new_redirect_slug() {
			if ( $slug = get_option( 'whl_redirect_admin' ) ) {
				return $slug;
			}
			return '404';
		}

		/**
		 * Whether the active permalink structure uses trailing slashes.
		 *
		 * @return bool
		 */
		private function use_trailing_slashes() {
			return ( '/' === substr( get_option( 'permalink_structure' ), -1, 1 ) );
		}

		/**
		 * Apply (or strip) trailing slash according to permalink settings.
		 *
		 * @param string $string
		 * @return string
		 */
		private function user_trailingslashit( $string ) {
			return $this->use_trailing_slashes()
				? trailingslashit( $string )
				: untrailingslashit( $string );
		}

		/**
		 * Full URL of the custom login page.
		 *
		 * @param string|null $scheme
		 * @return string
		 */
		public function new_login_url( $scheme = null ) {
			$url = home_url( '/', $scheme );

			if ( get_option( 'permalink_structure' ) ) {
				return $this->user_trailingslashit( $url . $this->new_login_slug() );
			}

			return $url . '?' . $this->new_login_slug();
		}

		/**
		 * Full URL to redirect blocked visitors to.
		 *
		 * @param string|null $scheme
		 * @return string
		 */
		public function new_redirect_url( $scheme = null ) {
			if ( get_option( 'permalink_structure' ) ) {
				return $this->user_trailingslashit( home_url( '/', $scheme ) . $this->new_redirect_slug() );
			}

			return home_url( '/', $scheme ) . '?' . $this->new_redirect_slug();
		}

		// ----------------------------------------------------------------
		// Core interception — runs at plugins_loaded:9999
		// ----------------------------------------------------------------

		/**
		 * Intercept requests for wp-login.php / the custom login slug.
		 * Rewrites $pagenow and REQUEST_URI so the rest of WordPress treats
		 * the request correctly.
		 */
		public function plugins_loaded() {
			global $pagenow;

			$request = parse_url( rawurldecode( $_SERVER['REQUEST_URI'] ) );

			// --- Request is for the real wp-login.php (must be hidden) ----
			if (
				( strpos( rawurldecode( $_SERVER['REQUEST_URI'] ), 'wp-login.php' ) !== false
					|| ( isset( $request['path'] )
						&& untrailingslashit( $request['path'] ) === site_url( 'wp-login', 'relative' ) ) )
				&& ! is_admin()
			) {
				$this->wp_login_php        = true;
				$_SERVER['REQUEST_URI']    = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
				$pagenow                   = 'index.php';

			// --- Request is for the custom login slug ----------------------
			} elseif (
				( isset( $request['path'] )
					&& untrailingslashit( $request['path'] ) === home_url( $this->new_login_slug(), 'relative' ) )
				|| ( ! get_option( 'permalink_structure' )
					&& isset( $_GET[ $this->new_login_slug() ] )
					&& '' === $_GET[ $this->new_login_slug() ] )
			) {
				$_SERVER['SCRIPT_NAME'] = $this->new_login_slug();
				$pagenow                = 'wp-login.php';

			// --- Request is for wp-register.php (also hidden) --------------
			} elseif (
				( strpos( rawurldecode( $_SERVER['REQUEST_URI'] ), 'wp-register.php' ) !== false
					|| ( isset( $request['path'] )
						&& untrailingslashit( $request['path'] ) === site_url( 'wp-register', 'relative' ) ) )
				&& ! is_admin()
			) {
				$this->wp_login_php        = true;
				$_SERVER['REQUEST_URI']    = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
				$pagenow                   = 'index.php';
			}
		}

		// ----------------------------------------------------------------
		// Redirect / page-serve — runs at wp_loaded
		// ----------------------------------------------------------------

		/**
		 * After WordPress has fully loaded, either:
		 *  - redirect blocked access to the redirect URL, or
		 *  - serve the actual login page for the custom slug.
		 */
		public function wp_loaded() {
			global $pagenow;

			$request = parse_url( rawurldecode( $_SERVER['REQUEST_URI'] ) );

			// Allow password-protected post form submissions through.
			if ( isset( $_GET['action'] ) && 'postpass' === $_GET['action'] && isset( $_POST['post_password'] ) ) {
				return;
			}

			// --- Block wp-admin for non-logged-in users --------------------
			if (
				is_admin()
				&& ! is_user_logged_in()
				&& ! defined( 'WP_CLI' )
				&& ! defined( 'DOING_AJAX' )
				&& ! defined( 'DOING_CRON' )
				&& $pagenow !== 'admin-post.php'
				&& ( ! isset( $request['path'] ) || $request['path'] !== '/wp-admin/options.php' )
			) {
				wp_safe_redirect( $this->new_redirect_url() );
				die();
			}

			// WooCommerce profile edge-case.
			if ( ! is_user_logged_in() && isset( $_GET['wc-ajax'] ) && 'profile.php' === $pagenow ) {
				wp_safe_redirect( $this->new_redirect_url() );
				die();
			}

			// /wp-admin/options.php without login.
			if (
				! is_user_logged_in()
				&& isset( $request['path'] )
				&& '/wp-admin/options.php' === $request['path']
			) {
				header( 'Location: ' . $this->new_redirect_url() );
				die;
			}

			// Trailing-slash redirect for custom login URL.
			if (
				'wp-login.php' === $pagenow
				&& isset( $request['path'] )
				&& $request['path'] !== $this->user_trailingslashit( $request['path'] )
				&& get_option( 'permalink_structure' )
			) {
				wp_safe_redirect(
					$this->user_trailingslashit( $this->new_login_url() )
					. ( ! empty( $_SERVER['QUERY_STRING'] ) ? '?' . $_SERVER['QUERY_STRING'] : '' )
				);
				die;

			// --- Someone hit the real wp-login.php → serve 404 theme ------
			} elseif ( $this->wp_login_php ) {

				// Special case: wp-activate.php referer with a valid key.
				if (
					( $referer = wp_get_referer() )
					&& false !== strpos( $referer, 'wp-activate.php' )
					&& ( $referer = parse_url( $referer ) )
					&& ! empty( $referer['query'] )
				) {
					parse_str( $referer['query'], $referer );

					@require_once WPINC . '/ms-functions.php';

					if (
						! empty( $referer['key'] )
						&& ( $result = wpmu_activate_signup( $referer['key'] ) )
						&& is_wp_error( $result )
						&& ( 'already_active' === $result->get_error_code()
							|| 'blog_taken' === $result->get_error_code() )
					) {
						wp_safe_redirect(
							$this->new_login_url()
							. ( ! empty( $_SERVER['QUERY_STRING'] ) ? '?' . $_SERVER['QUERY_STRING'] : '' )
						);
						die;
					}
				}

				// Serve the WordPress 404/theme template instead.
				$this->wp_template_loader();

			// --- Custom login slug → serve wp-login.php --------------------
			} elseif ( 'wp-login.php' === $pagenow ) {

				global $error, $interim_login, $action, $user_login;

				$redirect_to           = admin_url();
				$requested_redirect_to = isset( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '';

				if ( is_user_logged_in() ) {
					$user = wp_get_current_user();
					if ( ! isset( $_REQUEST['action'] ) ) {
						$logged_in_redirect = apply_filters(
							'whl_logged_in_redirect',
							$redirect_to,
							$requested_redirect_to,
							$user
						);
						wp_safe_redirect( $logged_in_redirect );
						die();
					}
				}

				@require_once ABSPATH . 'wp-login.php';

				die;
			}
		}

		// ----------------------------------------------------------------
		// URL filters
		// ----------------------------------------------------------------

		/** @param string $url  @param string $path  @param string $scheme  @param int $blog_id */
		public function site_url( $url, $path, $scheme, $blog_id ) {
			return $this->filter_wp_login_php( $url, $scheme );
		}

		/** @param string $url  @param string $path  @param string $scheme */
		public function network_site_url( $url, $path, $scheme ) {
			return $this->filter_wp_login_php( $url, $scheme );
		}

		/** @param string $location  @param int $status */
		public function wp_redirect( $location, $status ) {
			// Never rewrite Jetpack / WP.com login URLs.
			if ( false !== strpos( $location, 'https://wordpress.com/wp-login.php' ) ) {
				return $location;
			}
			return $this->filter_wp_login_php( $location );
		}

		/**
		 * Replace wp-login.php in any URL with the custom login slug.
		 *
		 * @param string      $url
		 * @param string|null $scheme
		 * @return string
		 */
		public function filter_wp_login_php( $url, $scheme = null ) {
			global $pagenow;

			$origin_url = $url;

			// Never touch postpass URLs.
			if ( false !== strpos( $url, 'wp-login.php?action=postpass' ) ) {
				return $url;
			}

			// During multisite install.
			if ( is_multisite() && 'install.php' === $pagenow ) {
				return $url;
			}

			if (
				false !== strpos( $url, 'wp-login.php' )
				&& false === strpos( (string) wp_get_referer(), 'wp-login.php' )
			) {
				if ( is_ssl() ) {
					$scheme = 'https';
				}

				$args = explode( '?', $url );

				if ( isset( $args[1] ) ) {
					parse_str( $args[1], $args );

					if ( isset( $args['login'] ) ) {
						$args['login'] = rawurlencode( $args['login'] );
					}

					$url = add_query_arg( $args, $this->new_login_url( $scheme ) );
				} else {
					$url = $this->new_login_url( $scheme );
				}
			}

			// Gravity Forms compatibility.
			if ( isset( $_POST['post_password'] ) ) {
				global $current_user;
				if (
					! is_user_logged_in()
					&& is_wp_error(
						wp_authenticate_username_password( null, $current_user->user_login, $_POST['post_password'] )
					)
				) {
					return $origin_url;
				}
			}

			if ( ! is_user_logged_in() ) {
				if (
					file_exists( WP_CONTENT_DIR . '/plugins/gravityforms/gravityforms.php' )
					&& isset( $_GET['gf_page'] )
				) {
					return $origin_url;
				}
			}

			return $url;
		}

		/**
		 * Fix `login_url` filter for the options.php redirect edge-case.
		 *
		 * @param string $login_url
		 * @param string $redirect
		 * @param bool   $force_reauth
		 * @return string
		 */
		public function login_url( $login_url, $redirect, $force_reauth ) {
			if ( is_404() ) {
				return '#';
			}

			if ( false === $force_reauth ) {
				return $login_url;
			}

			if ( empty( $redirect ) ) {
				return $login_url;
			}

			$redirect = explode( '?', $redirect );

			if ( $redirect[0] === admin_url( 'options.php' ) ) {
				$login_url = admin_url();
			}

			return $login_url;
		}

		// ----------------------------------------------------------------
		// Block access to wp-signup / wp-activate / customize
		// ----------------------------------------------------------------

		/**
		 * Block wp-signup.php and wp-activate.php on non-multisite installs.
		 */
		public function init_block_access() {
			if (
				! is_multisite()
				&& (
					false !== strpos( rawurldecode( $_SERVER['REQUEST_URI'] ), 'wp-signup' )
					|| false !== strpos( rawurldecode( $_SERVER['REQUEST_URI'] ), 'wp-activate' )
				)
			) {
				wp_die( esc_html__( 'This feature is not enabled.', 'kw-security' ) );
			}
		}

		/**
		 * Block non-logged-in users from the Customizer.
		 */
		public function setup_theme() {
			global $pagenow;

			if ( ! is_user_logged_in() && 'customize.php' === $pagenow ) {
				wp_die( esc_html__( 'This has been disabled.', 'kw-security' ), 403 );
			}
		}

		// ----------------------------------------------------------------
		// Email / misc filters
		// ----------------------------------------------------------------

		/**
		 * Replace wp-login.php in the WordPress welcome email.
		 *
		 * @param string $value
		 * @return string
		 */
		public function welcome_email( $value ) {
			return str_replace(
				'wp-login.php',
				trailingslashit( $this->new_login_slug() ),
				$value
			);
		}

		/**
		 * Fix GDPR data-export confirmation URL in emails.
		 *
		 * @param string $email_text
		 * @param array  $email_data
		 * @return string
		 */
		public function user_request_action_email_content( $email_text, $email_data ) {
			$email_text = str_replace(
				'###CONFIRM_URL###',
				esc_url_raw(
					str_replace(
						$this->new_login_slug() . '/',
						'wp-login.php',
						$email_data['confirm_url']
					)
				),
				$email_text
			);
			return $email_text;
		}

		// ----------------------------------------------------------------
		// Internal helpers
		// ----------------------------------------------------------------

		/**
		 * Load the WordPress theme template (renders the site's 404 page)
		 * instead of responding to a direct wp-login.php request.
		 */
		private function wp_template_loader() {
			global $pagenow;

			$pagenow = 'index.php';

			if ( ! defined( 'WP_USE_THEMES' ) ) {
				define( 'WP_USE_THEMES', true );
			}

			wp();

			require_once ABSPATH . WPINC . '/template-loader.php';

			die;
		}

	} // end class KW_Hide_Login

	if ( KW_Security_Settings::is_enabled( 'hide_login_url' ) ) {
		new KW_Hide_Login();
	}

} // end if class_exists