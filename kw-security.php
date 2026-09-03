<?php
/*
  Plugin Name: KW Security
  Description: WordPress security enhancements and controlled updates.
  Plugin URI: https://kilowott.com/
  Version: 26.09.06
  Author: KW Development
  Author URI: https://kilowott.com/
  Requires at least: 5.0
  Tested up to: 7.1
 */

// Make sure we don't expose any info if called directly
if (!function_exists('add_action') || !defined('ABSPATH')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

define('KW_SECURITY_NAME', 'KW Security');
define('KW_SECURITY_VERSION', '26.09.06');
define('KW_SECURITY_SLUG', 'kw-security');
define('KW_SECURITY_MINIMUM_WP_VERSION', '5.0');
define('KW_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KW_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('KW_SECURITY_PLUGIN_FILE', __FILE__);

// Update server. The plugin repository is private, so releases are served as
// static files from Kilowott infrastructure instead of the GitHub Releases
// API: info.json is the update metadata document PUC reads, kw-security.zip
// is the artifact it downloads.
//
// Both are overridable from wp-config.php, so a staging site can be pointed
// at a different endpoint without editing the plugin. Anything reading these
// must tolerate the endpoint being unreachable — an update check that fails
// is an inconvenience, but a fatal here would take the site down.
if (!defined('KW_UPDATE_SERVER')) {
    define('KW_UPDATE_SERVER', 'https://updates.kwrk.in/kw-security');
}
if (!defined('KW_UPDATE_METADATA_URL')) {
    define('KW_UPDATE_METADATA_URL', KW_UPDATE_SERVER . '/info.json');
}

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

// Sent as a bearer token on first registration with the Security Dashboard
// (classes/telemetry.php's register()). This repository is public, so this
// is not a secret in the usual sense — anyone can read it here — its job
// is only to stop the registration endpoint being blindly scannable by
// something that hasn't at least gone to the trouble of reading the
// plugin source. Actual protection against a captured value is on the
// dashboard's side: registration only ever creates a new installation
// row and never overwrites an existing one's site_url or API key, so
// knowing this value plus an existing installation_id still isn't enough
// to take over that site's registration.
if (!defined('KW_REGISTER_SHARED_SECRET')) {
    define('KW_REGISTER_SHARED_SECRET', 'a1f9c3e7-8b2d-4f6a-9c1e-5d7b3a8f2c4e');
}

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