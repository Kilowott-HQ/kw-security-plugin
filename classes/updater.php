<?php
/**
 * KW Security – Plugin Update Checker
 *
 * Hooks into WordPress's update system to surface new releases from the
 * plugin's GitHub repository on the Dashboard > Updates and Plugins screens.
 *
 * Release workflow:
 *   1. Bump Version in kw-security.php (both plugin header and KW_SECURITY_VERSION).
 *      Also bump the "Tested up to" header when a new WP major/minor ships —
 *      PUC reads it from the tagged copy of this file and WP uses it for the
 *      "Compatibility with WordPress x.y.z" line on Dashboard > Updates.
 *   2. Create a GitHub release tagged with that exact version string (e.g. 26.05.05).
 *   3. Attach a zip whose root folder is named "kw-security" — WP uses this
 *      as the plugin directory name when installing the update.
 *
 * The update notice will appear on Plugins > Installed Plugins and
 * Dashboard > Updates just like any WordPress.org plugin.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once KW_SECURITY_PLUGIN_DIR . 'vendor/plugin-update-checker/load-v5p6.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

PucFactory::buildUpdateChecker(
    'https://github.com/Kilowott-HQ/kw-security-plugin/',
    KW_SECURITY_PLUGIN_FILE,
    'kw-security'
);
