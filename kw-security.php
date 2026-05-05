<?php
/*
  Plugin Name: KW Security
  Description: WordPress security enhancements and controlled updates.
  Plugin URI: https://kilowott.com/
  Version: 26.05.08
  Author: KW Development
  Author URI: https://kilowott.com/
 */

// Make sure we don't expose any info if called directly
if (!function_exists('add_action') || !defined('ABSPATH')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

define('KW_SECURITY_NAME', 'KW Security');
define('KW_SECURITY_VERSION', '26.05.08');
define('KW_SECURITY_SLUG', 'kw-security');
define('KW_SECURITY_MINIMUM_WP_VERSION', '5.0');
define('KW_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KW_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('KW_SECURITY_PLUGIN_FILE', __FILE__);

register_activation_hook(__FILE__, array('KW_Security', 'plugin_activation'));
register_deactivation_hook(__FILE__, array('KW_Security', 'plugin_deactivation'));

// Settings manager loads first so feature classes can call
// KW_Security_Settings::is_enabled() at instantiation time.
require_once KW_SECURITY_PLUGIN_DIR . 'classes/settings.php';

// Load remaining class files. require_once protects against double-include
// of settings.php that the glob will also match.
foreach (glob(KW_SECURITY_PLUGIN_DIR . 'classes/*.php') as $file) {
    require_once $file;
}



?>