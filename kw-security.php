<?php
/*
  Plugin Name: KW Security
  Description: WordPress security enhancements and controlled updates.
  Plugin URI: https://kilowott.com/
  Version: 1.0.0
  Author: KW Development
  Author URI: https://kilowott.com/
 */

// Make sure we don't expose any info if called directly
if (!function_exists('add_action') || !defined('ABSPATH')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

define('KW_SECURITY_NAME', 'KW Security');
define('KW_SECURITY_VERSION', '1.0.0');
define('KW_SECURITY_SLUG', 'kw-security');
define('KW_SECURITY_MINIMUM_WP_VERSION', '5.0');
define('KW_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KW_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('KW_SECURITY_PLUGIN_FILE', __FILE__);

register_activation_hook(__FILE__, array('KW_Security', 'plugin_activation'));

require_once(KW_SECURITY_PLUGIN_DIR . 'classes/class-kw-security.php');



?>