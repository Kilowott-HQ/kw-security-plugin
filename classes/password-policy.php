<?php
/**
 * KW Security – Strong Password Policy
 *
 * Enforces a minimum password strength for administrator accounts at
 * the moments WordPress accepts a new password:
 *
 *   1. New user creation                    (Users → Add New)
 *   2. Profile / user edit password change  (Users → Edit / Profile)
 *   3. Password reset via "Lost Password"   (wp-login.php?action=resetpass)
 *
 * Policy (administrators only):
 *   - Minimum 12 characters
 *   - At least one uppercase letter
 *   - At least one lowercase letter
 *   - At least one digit
 *   - At least one non-alphanumeric character
 *
 * Roles enforced can be overridden via the kw_security_password_policy_roles
 * filter to extend coverage to editors, etc.:
 *
 *   add_filter( 'kw_security_password_policy_roles', function () {
 *       return array( 'administrator', 'editor' );
 *   } );
 *
 * Note: WP-CLI (`wp user create`) and direct REST API user creation
 * bypass these hooks. Admin-level CLI access already has full control;
 * REST API user-create flows are rarely used for routine account
 * management. Both are out of scope for this enforcement.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'KW_Password_Policy' ) ) {

    class KW_Password_Policy {

        const MIN_LENGTH = 12;

        public function __construct() {
            // Fires on new-user creation AND existing-user profile/password edits.
            add_action( 'user_profile_update_errors', array( $this, 'on_profile_update' ), 10, 3 );

            // Fires on the lost-password reset flow.
            add_action( 'validate_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
        }

        /**
         * Roles for which the policy is enforced.
         *
         * @return string[]
         */
        public static function enforced_roles() {
            return apply_filters( 'kw_security_password_policy_roles', array( 'administrator' ) );
        }

        /**
         * Whether the policy applies to a given user object/ID.
         *
         * @param WP_User|object|int|null $user
         * @return bool
         */
        private static function should_enforce( $user ) {
            $roles_to_enforce = self::enforced_roles();

            // Existing WP_User instance — read role list directly.
            if ( $user instanceof WP_User ) {
                return (bool) array_intersect( $roles_to_enforce, (array) $user->roles );
            }

            // User ID — load and check.
            if ( is_numeric( $user ) && (int) $user > 0 ) {
                $loaded = get_user_by( 'id', (int) $user );
                if ( $loaded ) {
                    return (bool) array_intersect( $roles_to_enforce, (array) $loaded->roles );
                }
            }

            // Raw form-data object passed during new-user creation. The role
            // being assigned is on $user->role.
            if ( is_object( $user ) && isset( $user->role ) && '' !== $user->role ) {
                return in_array( $user->role, $roles_to_enforce, true );
            }

            // Unknown context — enforce by default rather than silently allow.
            return true;
        }

        /**
         * Find every policy violation in the given password.
         *
         * @param string $password
         * @return string[] Empty array = password is acceptable.
         */
        private static function find_violations( $password ) {
            $errors = array();

            if ( strlen( $password ) < self::MIN_LENGTH ) {
                $errors[] = sprintf(
                    /* translators: %d: minimum password length */
                    esc_html__( 'must be at least %d characters', 'kw-security' ),
                    self::MIN_LENGTH
                );
            }
            if ( ! preg_match( '/[A-Z]/', $password ) ) {
                $errors[] = esc_html__( 'must include an uppercase letter', 'kw-security' );
            }
            if ( ! preg_match( '/[a-z]/', $password ) ) {
                $errors[] = esc_html__( 'must include a lowercase letter', 'kw-security' );
            }
            if ( ! preg_match( '/[0-9]/', $password ) ) {
                $errors[] = esc_html__( 'must include a number', 'kw-security' );
            }
            if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
                $errors[] = esc_html__( 'must include a special character', 'kw-security' );
            }

            return $errors;
        }

        /**
         * Add a friendly error to the WP_Error bag if the password is weak.
         *
         * @param WP_Error $errors
         * @param string   $password
         */
        private static function add_error_if_weak( $errors, $password ) {
            $violations = self::find_violations( $password );
            if ( empty( $violations ) ) {
                return;
            }

            $message = sprintf(
                /* translators: %s: comma-separated list of policy violations */
                esc_html__( 'Password does not meet administrator policy: %s.', 'kw-security' ),
                implode( ', ', $violations )
            );
            $errors->add( 'kw_weak_password', $message );
        }

        /**
         * Hook callback for user_profile_update_errors.
         *
         * @param WP_Error      $errors
         * @param bool          $update  True if updating existing user, false on creation.
         * @param stdClass      $user    Raw user form data (NOT WP_User).
         */
        public function on_profile_update( $errors, $update, $user ) {
            $password = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
            if ( '' === $password ) {
                // Profile saved without changing password.
                return;
            }

            // For updates: load actual WP_User to check current role list.
            // For creations: pass the form-data object so should_enforce reads $user->role.
            $check_target = $update && isset( $user->ID ) && $user->ID
                ? get_user_by( 'id', $user->ID )
                : $user;

            if ( ! self::should_enforce( $check_target ) ) {
                return;
            }

            self::add_error_if_weak( $errors, $password );
        }

        /**
         * Hook callback for validate_password_reset.
         *
         * @param WP_Error $errors
         * @param WP_User  $user
         */
        public function on_password_reset( $errors, $user ) {
            $password = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
            if ( '' === $password ) {
                return;
            }

            if ( ! self::should_enforce( $user ) ) {
                return;
            }

            self::add_error_if_weak( $errors, $password );
        }
    }

    if ( KW_Security_Settings::is_enabled( 'password_policy' ) ) {
        new KW_Password_Policy();
    }
}
