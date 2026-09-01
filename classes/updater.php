<?php
/**
 * KW Security – Plugin Update Checker
 *
 * Hooks into WordPress's update system to surface new releases on the
 * Dashboard > Updates and Plugins screens.
 *
 * Updates are served as static files from the Kilowott update server
 * (KW_UPDATE_SERVER, see kw-security.php), not from GitHub. The plugin
 * repository is private, and the alternative — shipping a GitHub token to
 * every install so it could read the Releases API — would put a credential
 * that reads our source code on every client site. The update server holds
 * two files and no credentials:
 *
 *   info.json        PUC metadata: version, download_url, sections, notes
 *   kw-security.zip  the release artifact, root folder named "kw-security"
 *
 * Passing a non-VCS URL is what selects PUC's self-hosted mode; hand
 * buildUpdateChecker() a github.com URL and it silently switches back to the
 * GitHub API instead, so the endpoint must stay a plain HTTPS URL.
 *
 * Release workflow (all of it automated by .github/workflows/release.yml):
 *   1. Bump Version in kw-security.php (header and KW_SECURITY_VERSION).
 *      Also bump "Tested up to" when a new WP major/minor ships — it is
 *      copied into info.json and WP uses it for the "Compatibility with
 *      WordPress x.y.z" line on Dashboard > Updates.
 *   2. Write the CHANGELOG.md entry — the release job fails without one.
 *   3. Run the Release workflow. It builds the zip, generates info.json,
 *      uploads both to the update server, tags, and publishes.
 *
 * The zip is uploaded before info.json, deliberately: info.json is what
 * advertises the new version, so publishing it first would point sites at a
 * download that does not exist yet.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

require_once KW_SECURITY_PLUGIN_DIR . 'vendor/plugin-update-checker/load-v5p6.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

PucFactory::buildUpdateChecker(
    KW_UPDATE_METADATA_URL,
    KW_SECURITY_PLUGIN_FILE,
    'kw-security'
);
