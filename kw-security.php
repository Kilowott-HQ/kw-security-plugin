<?php
/*
  Plugin Name: KW Security
  Description: WordPress security enhancements and controlled updates.
  Plugin URI: https://kilowott.com/
  Version: 26.05.10
  Author: KW Development
  Author URI: https://kilowott.com/
 */

// Make sure we don't expose any info if called directly
if (!function_exists('add_action') || !defined('ABSPATH')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

define('KW_SECURITY_NAME', 'KW Security');
define('KW_SECURITY_VERSION', '26.05.10');
define('KW_SECURITY_SLUG', 'kw-security');
define('KW_SECURITY_MINIMUM_WP_VERSION', '5.0');
define('KW_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KW_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('KW_SECURITY_PLUGIN_FILE', __FILE__);

// Phase 6-WP: auto-registration.
// KW_DISCOVERY_URL points to the Kilowott registration endpoint discovery doc.
// Returns { register_url, version } so the endpoint can move without a plugin update.
define('KW_DISCOVERY_URL', 'https://raw.githubusercontent.com/Kilowott-HQ/kw-plugin-config/main/kw-registration.json');

// RSA-2048 public key used to verify key-delivery requests from the Kilowott scanner.
// The scanner signs with the corresponding private key (never distributed).
// Safe to publish: a public key can verify signatures but cannot forge them.
define('KW_DELIVERY_PUBLIC_KEY', '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA03r6DkadKTfshfw5Evfv
zdUE4318hMnmd+d8XMxBLC5hhqV8m9hNoqnrpBMY8Fzo6OpTSVGbZ5LDFT89Bq7e
MyeaDFZhJdTRMM2RsuFPZJCnZS6zlI2OKwkP3tWjzDxCwY8M7ZQHSE5ndgM4rBm3
8LTYnzQKIzYMVYbxmJfz5oqr4p5g43u44EQZCEtmDWmw+EtlLTrirosbAF3UFxi8
Wbs9Tai2j60IgQp+G6Q8ZYL5fsMXioCR10tjInltI9qRYvwBV+5bDKHcpD7ix/Xm
cQo6ScfVo5YV81giSkyfhiMaFLGOEP2NQ0DQo11BkKuyA0O3piLQcrPyTYxNXMbl
nQIDAQAB
-----END PUBLIC KEY-----');

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