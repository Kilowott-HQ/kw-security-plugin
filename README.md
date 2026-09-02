# KW Security - WordPress Plugin

A lightweight WordPress security plugin that provides controlled updates and essential security enhancements for WordPress installations.

## Features

- 🔒 **Controlled Updates**: Allows security patches while blocking major updates
- 🛡️ **HTTP Security Headers**: X-Frame-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy
- 🚪 **Hide Login URL**: Replace `/wp-login.php` with a custom slug
- 👤 **User Enumeration Protection**: Redirect `?author=N` requests to homepage and gate `/wp/v2/users` REST endpoint
- 👤 **Disable Author URLs**: Redirects `/author/username` archive pages to the homepage, preventing username exposure via author slugs
- 🔐 **Login Rate Limiting**: Lock out IPs after repeated failed login attempts
- 🔍 **File Integrity Monitoring**: Daily scan of WP root for unknown PHP files and modifications to `index.php` / `wp-config.php`
- 🔑 **Strong Password Policy**: Enforce 12+ char passwords with mixed case, digits, and symbols for administrator accounts
- 💬 **Comment Security**: Disables comments, pingbacks, and trackbacks
- 📁 **File Security**: Prevents dangerous file uploads and disables file editing
- 📋 **Activity Log**: Records logins, failed logins, plugin/theme changes, post edits, media uploads, and settings changes to a searchable, filterable log at **Settings → Activity Log**
- 🔁 **Update Notifications**: Surfaces new releases on the WordPress Updates screen, served from Kilowott's own update server rather than the GitHub Releases API
- 🔧 **Maintenance API**: Read-only REST endpoint for the Kilowott maintenance agent to query site health (WP/PHP version, plugin update status), gated by a Bearer key
- 🌐 **Nginx Upload Protection**: Server-aware file security — skips the ineffective `.htaccess` on Nginx/OpenResty and shows an admin notice with the equivalent Nginx location block
- 🔌 **Remote Plugin Control**: Install (from wordpress.org), activate, deactivate, or update any installed plugin — not just this one — from the KW Security Dashboard, without logging into the site
- 🔒 **Plugin Lockout**: Blocks activating, deactivating, updating, or deleting KW Security, KW Performance, and Wordfence specifically from wp-admin — every other already-installed plugin is unaffected — and blocks installing any new plugin from wp-admin outright (new plugins can still be added remotely from the KW Security Dashboard's Add Plugin page). Turning it off is temporary: it automatically re-enables after 8 hours if left off
- 👥 **Remote User Management**: Add a new WordPress user, or edit an existing admin's email/name/role, from the KW Security Dashboard, without logging into the site
- 🔒 **User Lockout**: Blocks adding, editing, or deleting WordPress users from wp-admin or the REST API entirely — even for a logged-in Administrator. The only way to manage users while it's on is through the dashboard
- 🔑 **One-Click Admin Login**: The dashboard can log an admin straight into wp-admin via a single-use, 60-second token for a dedicated "KW Security Dashboard" account — no password needed, recorded in the Activity Log, and capped at an 8-hour session regardless of how long the tab stays open
- ✉️ **Dashboard-Triggered Password Reset**: Send the standard reset-link email, or set a new password directly, for any admin account — from the dashboard
- 🕵️ **Dashboard Actor Attribution**: Plugin/Wordfence activation, deactivation, updates, and user creation/edits triggered from the dashboard are attributed to the responsible dashboard role in the Activity Log (e.g. "SuperAdmin (KW SECURITY DASH)") instead of showing as "Guest"
- ⚙️ **Feature Toggles**: Every feature can be enabled or disabled per site from **Settings → KW Security**

## Installation

1. Download the plugin zip file ([kw-security.zip](https://github.com/Kilowott-HQ/kw-security-plugin/releases/latest/download/kw-security.zip))
2. Go to **WordPress Admin → Plugins → Add New**
3. Click **Upload Plugin** and select the zip file
4. Click **Install Now**
5. Click **Activate Plugin**
6. Configure feature toggles at **Settings → KW Security**

## Feature Toggles

Every security feature can be turned on or off per site from **Settings → KW Security**.
Defaults: all features enabled, except **Hide Login URL** (opt-in, off by default).

| Toggle | Default | What it controls |
|---|---|---|
| Disable Comments | ON | Comments site-wide, dashboard widget, REST endpoints, pingbacks |
| File Security | ON | Dangerous upload blocking, file editor disable, `/uploads/.htaccess` |
| Controlled Auto-Updates | ON | Security-only auto-updates for core/plugins/themes |
| Disable XML-RPC Pingbacks | ON | XML-RPC disable + pingback method removal |
| HTTP Security Headers | ON | X-Frame-Options, CSP, HSTS, Referrer-Policy, Permissions-Policy |
| Block User Enumeration | ON | `/?author=N` redirects to homepage, auth required for `/wp/v2/users` |
| Disable Author URLs | ON | Redirects `/author/username` archive pages to homepage for all visitors |
| Login Rate Limiting | ON | 5 failed attempts / 15 min → 1-hour IP lockout; generic "Invalid login credentials" error |
| File Integrity Monitoring | ON | Daily WP-Cron scan; emails admin on unknown PHP in root or modified `index.php` / `wp-config.php` |
| Strong Password Policy (Admins) | ON | Requires 12+ chars with upper, lower, digit, and symbol when creating/updating administrator passwords |
| Hide Login URL | **OFF** | Custom login slug; replaces `/wp-login.php` and `/wp-admin` |
| User Lockout | **OFF** | Blocks adding, editing, or deleting WordPress users — even for logged-in Administrators, via wp-admin or the REST API. Removes the Edit, Delete, Send password reset, View, and Login Security row actions on the Users screen. The only way to manage users while this is on is through the KW Security Dashboard |
| Plugin Lockout | **OFF** | Blocks activating, deactivating, updating, or deleting KW Security, KW Performance, and Wordfence specifically — even for logged-in Administrators — and blocks installing any new plugin from wp-admin outright. Every other already-installed plugin is unaffected; new plugins can still be added remotely from the dashboard. Turning this off is temporary: it automatically switches back on after 8 hours if left off |
| Maintenance API | ON | Read-only REST endpoint (`/wp-json/kw-security/v1/site-status`) used by the Kilowott maintenance agent; gated by `Authorization: Bearer <key>`, rate-limited to 20 req/hour |
| Activity Log | ON | Records security-relevant events (logins, failed logins, plugin/theme/core changes, post edits, media uploads, settings saves) to a database log viewable at Settings → Activity Log; 90-day retention with daily cleanup |
| Slack Security Alerts | ON | Forwards **critical security events** (brute-force lockouts, admin privilege changes, blocked malicious uploads, file-integrity anomalies, disabled defenses) to a Slack channel via an Incoming Webhook. Also reports **updates available for KW Security or Wordfence** — with the release notes, so the team can see what the update contains — and **activation/deactivation of either plugin**. Per-site, queued and flushed on shutdown, de-duplicated. Inert until a webhook URL is set — via Settings → KW Security or the `KW_SLACK_WEBHOOK_URL` constant/environment variable. The channel is identified by a Channel ID (from the channel's Slack details panel → Copy channel ID), used to build the "View Channel" link. Both the webhook and Channel ID can also be set remotely from the Security Dashboard. Choose which categories to send per site |

> **About "Hide Login URL":** Disabled by default because changing the login URL is a disruptive change that requires bookmarking a custom URL. Enable only when ready, and configure the slug in the same Settings → KW Security page before saving.

When a feature is disabled, **none of its hooks are registered** — there is zero runtime cost.

## What This Plugin Does

### Update Management
- ✅ **Allows minor WordPress core updates** (security patches: 6.1.1 → 6.1.2)
- ❌ **Blocks major WordPress core updates** (feature releases: 6.1.x → 6.2.x)
- ✅ **Allows plugin security updates** (patch versions only)
- ❌ **Blocks regular plugin updates** (feature releases)
- ❌ **Blocks all theme updates**

### Security Enhancements
- ❌ **Disables XML-RPC** for improved security
- 🔒 **Controlled automatic updates** to prevent breaking changes
- 🛡️ **Security-first update policy**

### Comment Security
- ❌ **Disables all comments** site-wide
- ❌ **Disables pingbacks and trackbacks**
- 🚫 **Removes comment admin pages** and menu items
- 🔒 **Blocks comment REST API endpoints**
- 🧹 **Hides existing comments** from frontend

### File Security
- ❌ **Disables WordPress file editor** in admin area
- 🚫 **Blocks dangerous file uploads** (.php, .exe, .bat, .js, etc.)
- 🔒 **Prevents PHP execution** in uploads directory
- 🛡️ **Blocks double extensions** (e.g., file.php.jpg)
- 📁 **Creates .htaccess protection** in uploads folder

## Technical Details

### Requirements
- **WordPress**: 5.0 or higher
- **PHP**: 7.4 or higher

### File Structure
```
kw-security/
├── kw-security.php                       # Main plugin file & autoloader
├── classes/
│   ├── class-kw-security.php             # Core security class (gated by toggles)
│   ├── settings.php                      # Feature toggle UI + is_enabled() helper; Plugin Lockout's 8-hour auto-relock cron
│   │                                      # Site-facing hardening features:
│   ├── security-headers.php              #   HTTP security headers
│   ├── hide-login-url.php                #   Custom login URL routing
│   ├── user-enumeration.php              #   Block user enumeration + author-URL redirects
│   ├── login-rate-limiter.php            #   Failed-login IP lockout
│   ├── file-integrity.php                #   Daily root-dir scan + email alerts
│   ├── password-policy.php               #   Strong password enforcement (admin role)
│   ├── user-lockout.php                  #   Blocks add/edit/delete of WordPress users from wp-admin/REST
│   ├── plugin-lockout.php                #   Blocks managing KW Security/KW Performance/Wordfence from wp-admin
│   │                                      # Activity logging & alerting:
│   ├── activity-log.php                  #   Activity log (event recording + admin list table)
│   ├── security-alerts.php               #   Slack alert categories, queueing, and delivery
│   ├── wordfence-integration.php         #   Parses Wordfence's own alert emails to avoid double-alerting
│   ├── telemetry.php                     #   Heartbeat ping to the Security Dashboard + update-info lookup
│   │                                      # Security Dashboard remote-action endpoints (signed, per-installation):
│   ├── toggle-feature.php                #   Enable/disable a feature toggle remotely
│   ├── plugin-toggle.php                 #   Activate/deactivate any installed plugin remotely
│   ├── plugin-file-update.php            #   Update any installed plugin remotely
│   ├── plugin-install.php                #   Install a plugin from wordpress.org and activate it
│   ├── update-trigger.php                #   Force-check + install a KW Security update remotely
│   ├── plugin-list.php                   #   Reports installed plugins + update status (read-only)
│   ├── refresh-heartbeat.php             #   On-demand heartbeat (bypasses WP-Cron)
│   ├── slack-webhook-set.php             #   Set this site's Slack webhook + Channel ID remotely
│   ├── admin-users.php                   #   Lists WP admins; dashboard-triggered edit/password reset/delete
│   ├── create-user.php                   #   Create a new WordPress user remotely
│   ├── dashboard-login.php               #   One-click WP admin login (single-use token, 8-hour session cap)
│   ├── dashboard-visibility.php          #   Backs the dashboard's "Remove"/resume toggle (telemetry opt-out)
│   │                                      # Update checking & maintenance:
│   ├── updater.php                       #   Update checker (PUC) reading Kilowott's own update server
│   ├── class-kw-maintenance-api.php      #   Read-only REST API for the Kilowott maintenance agent
│   └── mu-loader.php                     #   Deploys the mu-plugin below into wp-content/mu-plugins/
├── mu-plugins/
│   └── kw-security-activator.php         # Always-loaded (see mu-loader.php above): tracks which
│                                          # dashboard role triggered the current request, for Activity
│                                          # Log attribution, and consumes one-click login tokens
├── vendor/
│   └── plugin-update-checker/            # PUC v5.6 library (vendored)
└── README.md                             # This file
```

### Constants Defined
- `KW_SECURITY_NAME` - Plugin name
- `KW_SECURITY_VERSION` - Current version
- `KW_SECURITY_SLUG` - Plugin slug
- `KW_SECURITY_MINIMUM_WP_VERSION` - Minimum WordPress version
- `KW_SECURITY_PLUGIN_DIR` - Plugin directory path
- `KW_SECURITY_PLUGIN_URL` - Plugin URL
- `KW_SECURITY_PLUGIN_FILE` - Main plugin file path

## Security Features Explained

### Update Filtering Logic

#### Core Updates
- **Security patches**: Allowed (e.g., 6.1.1 → 6.1.2)
- **Major releases**: Blocked (e.g., 6.1.x → 6.2.x)
- **Minor releases**: Blocked (e.g., 6.1.x → 6.2.x)

#### Plugin Updates
- **Patch versions**: Allowed (e.g., 1.2.3 → 1.2.4)
- **Minor versions**: Blocked (e.g., 1.2.x → 1.3.x)
- **Major versions**: Blocked (e.g., 1.x.x → 2.x.x)

#### Theme Updates
- **All updates**: Blocked for stability

### XML-RPC Security
XML-RPC is disabled to prevent:
- Brute force attacks
- DDoS amplification attacks
- Unauthorized remote access

### Comment Security
Comments are completely disabled to prevent:
- **Comment spam** and automated spam bots
- **Security vulnerabilities** in comment processing
- **Database bloat** from spam comments
- **SEO penalties** from spammy comment content
- **Performance issues** from comment queries

The plugin removes:
- Comment forms from all posts and pages
- Comment admin pages and menu items
- Comment-related database queries
- Comment REST API endpoints
- Admin bar comment notifications
- Dashboard comment widgets

### File Security
File uploads are secured to prevent:
- **Malicious file uploads** that could compromise the server
- **PHP backdoors** being uploaded and executed
- **Script execution** in the uploads directory
- **Double extension attacks** (file.php.jpg)

The plugin blocks these dangerous file types:
- **Executable files**: .exe, .com, .bat, .cmd, .scr, .msi, .dll
- **Script files**: .php, .js, .vbs, .py, .pl, .sh, .cgi
- **Web scripts**: .asp, .aspx, .jsp, .cfm
- **Database files**: .sql, .db, .sqlite, .mdb
- **Config files**: .htaccess, .ini, .conf, .config
- **Backup files**: .bak, .backup, .old, .tmp

Additionally, it:
- Creates .htaccess rules in uploads directory
- Prevents execution of any PHP files in uploads
- Disables the WordPress file editor completely

## Hooks & Filters

### Actions Added
- `admin_init` - Disables comment admin functionality
- `init` - Disables comment frontend functionality and file editing
- `admin_menu` - Removes comment admin menu
- `wp_enqueue_scripts` - Removes comment reply scripts

### Filters Added
- `allow_minor_auto_core_updates` - Enables security updates
- `allow_major_auto_core_updates` - Disables major updates
- `auto_update_plugin` - Controls plugin updates
- `auto_update_theme` - Disables theme updates
- `pre_site_transient_update_core` - Filters core updates
- `pre_site_transient_update_themes` - Hides theme updates
- `xmlrpc_enabled` - Disables XML-RPC
- `comments_open` - Disables comments
- `pings_open` - Disables pingbacks/trackbacks
- `comments_array` - Hides existing comments
- `rest_endpoints` - Removes comment REST API endpoints
- `upload_mimes` - Restricts allowed file upload types
- `wp_handle_upload_prefilter` - Blocks dangerous file uploads

## Customization for Developers

### Changing Update Policy
Modify the `is_security_update()` method to adjust what constitutes a security update:
```php
private function is_security_update($item) {
    // Your custom logic here
}
```

### Adding More Security Features
Extend the `init_hooks()` method to add additional security measures.

## Releasing a New Version

Releases run from the **Release** workflow (Actions tab → Release → *Run workflow*).
It lints every PHP file, bumps the version in `kw-security.php`, builds the zip with
the correct `kw-security/` root folder, generates `info.json` (the update metadata
PUC reads), deploys both to Kilowott's own update server over SSH and verifies the
live checksum matches what was just uploaded, tags, publishes the GitHub release,
and announces it in Slack. There is nothing to build or upload by hand.

Updates are served from that update server, not the GitHub Releases API — see
`classes/updater.php`'s own docblock for why. `KW_UPDATE_SERVER` (default
`https://updates.kwrk.in/kw-security`, overridable from `wp-config.php` for staging)
is where a site actually checks; the GitHub release/tag is still created for the
changelog and Slack announcement, but a site never talks to GitHub to update.

### Step 1 — Write the changelog entry

Add a section for the version you are about to release to
[`CHANGELOG.md`](CHANGELOG.md), following the format documented at the top of that
file (`### What's new` / `### Why it matters` / `### Changed` / `### New`).

The first two are the plain-language sections the team reads in Slack; the last two are
the technical record, collapsed under a **Technical detail** toggle on the release.

**This is required.** The workflow uses that section as the GitHub release body and
the Slack announcement, and fails the release if it is missing — before anything is
pushed or tagged. Commit it on the branch that carries the change, so the notes land
with the work they describe.

Version format is `YY.MM.NN` (e.g. `26.08.04` = year 2026, August, release 4). The
workflow computes the next `NN` for the current month on its own, so you only need
to know it in order to write the heading.

### Step 2 — Run the workflow

Actions → **Release** → *Run workflow*, with:

| Input | Purpose |
| --- | --- |
| `version` | Override the auto-computed `YY.MM.NN`. Leave blank normally. |
| `dry_run` | Lint, extract notes, and build the zip without pushing, tagging, releasing, or announcing. Use this first when in doubt. |
| `skip_changelog_check` | Release without a `CHANGELOG.md` section. Emergencies only — the release body falls back to auto-generated commit notes. |
| `skip_announcement` | Don't post to Slack. For small fixes that don't warrant a channel update. The release still publishes with full notes; only the channel post is suppressed. |
| `slack_webhook_override` | Post the announcement to a different channel for this run. Also enables the announcement during a dry run, which is how you test the message without publishing. |

The workflow pushes the version bump commit to `main` itself, so there is no manual
bump step.

### Step 3 — Verify on a site

Visit this URL while logged in as admin on any site running the plugin:

```
https://example.com/wp-admin/plugins.php?force-check=1
```

The update notice should appear under KW Security on the Plugins screen within a few
seconds.

> **Note:** Without `?force-check=1`, WordPress checks for updates every 12 hours.
> The force-check bypasses the cache immediately.

### What the announcement looks like

The release body and the Slack message both lead with two plain-language sections
written for non-technical readers:

- **What's new** — what is actually different, in terms someone can see or click.
- **Why it matters** — a descriptive explanation of the problem the release solves.

**You write both sections by hand**, as `### What's new` and `### Why it matters` in the
`CHANGELOG.md` entry for the version. Nothing is generated: what the channel reads is
exactly what somebody wrote and a reviewer approved in the pull request.

They live in the changelog rather than in a *Run workflow* input box because
`workflow_dispatch` inputs are single-line text fields — GitHub has no multiline input
type — so bullets and paragraphs cannot survive one. In the changelog you get a normal
editor, real bullets, and version history.

The GitHub release body keeps the technical changelog underneath, in a collapsed
**Technical detail** block — `### Changed` and `### New` only. What's new and Why it
matters are dropped from it because they are rendered directly above, and `### Problem`
because Why it matters now says the same thing in the voice that block's readers are not
here for.

If the entry has no What's new / Why it matters, the release still succeeds: the
announcement falls back to the technical text, labelled as such, and the run logs a
warning.

The Slack post tags `@channel`, so the whole channel is notified. To see the message
before it goes out, do a dry run with `slack_webhook_override` pointed at a test channel.

For a small fix that doesn't warrant a channel update, tick **`skip_announcement`**. The
release still publishes with its full notes — only the Slack post is suppressed, and the
run log says so.

> Note that `skip_announcement` silences the *release* channel only. Sites running KW
> Security have their own per-site Slack alerts, and one of those fires when an update
> becomes available (see the **Update available for KW Security or Wordfence** alert
> category). A quiet release is not an invisible one; to silence that too, turn the
> category off per site under **Settings → KW Security**.

### Configuring the Slack announcement channel

The webhook is resolved in this order, first match wins:

1. the `slack_webhook_override` workflow input (one-off, this run only),
2. the `RELEASE_SLACK_WEBHOOK_URL` **Actions secret**,
3. a `RELEASE_SLACK_WEBHOOK_URL` **Actions variable** (handy for a test channel).

Set the secret under repo → Settings → Secrets and variables → Actions, or with
`gh secret set RELEASE_SLACK_WEBHOOK_URL`. Setting it at the Kilowott-HQ **org**
level instead lets other repos share the same channel wiring.

To move announcements to another channel, create a new Incoming Webhook in Slack and
update the secret — no code change and no release needed.

> **This repository is public.** The webhook URL is a credential that lets its holder
> post to the channel, so it must live in a secret and must never be committed. If
> none of the three sources resolve, the release still succeeds and the announcement
> is skipped with a notice.

---

## Changelog

> **New entries go in [CHANGELOG.md](CHANGELOG.md), not here.** The release
> workflow reads that file to build the GitHub release body and the Slack
> announcement, and a release with no matching section there fails. The history
> below predates that change and is kept as-is.

### Version 26.06.05
- **Slack Security Alerts**: new toggle (enabled by default, inert until configured) that forwards *critical security events* to a Slack channel via an Incoming Webhook. The site posts events directly (per-site), mirroring the File Integrity email-alert approach — there is no central event pipeline
- Categories: administrator login from a new/unrecognized IP, administrator login (successful — opt-in), brute-force lockout, login attempt from an already locked-out IP, administrator password changed or reset (covers both the profile/edit-user screen and the lost-password email flow), administrator privilege granted (new admin or promotion), administrator account deleted, Application Password created, WooCommerce REST API key created, dangerous file upload blocked, file-integrity anomaly, a KW Security defense switched off, Wordfence plugin deactivated, plugin update available (security patch or major version), and malware detected (reserved for future use). Each category can be toggled per site under **Settings → KW Security → Slack Security Alerts**
- Plugin-update alerts fire when an available update is a security patch (per its upgrade notice) or a major version jump (e.g. 1.x → 2.0); a persistent per-version set prevents re-alerting the same standing update on each update-check. Watched-plugin deactivation defaults to Wordfence and is extendable via `kw_slack_alert_watch_plugins`
- Deliberately not an Activity Log mirror — routine events (page saves, media uploads) are never sent. Raw failed logins are ignored as background noise; the brute-force **lockout** is the high-signal event that fires instead. Successful admin logins are split into a low-noise **new-IP** alert (on by default — the "suspicious login" signal) and an every-login alert (off by default). New-IP detection records up to 20 known IP hashes per user and seeds silently on first sight
- Webhook URL resolves from the `KW_SLACK_WEBHOOK_URL` constant (wp-config.php) → `KW_SLACK_WEBHOOK_URL` environment variable → the Webhook URL field, so the secret never has to live in committed code or the database
- Producer modules fire lightweight actions (`kw_login_lockout`, `kw_login_blocked`, `kw_upload_blocked`, `kw_file_integrity_anomaly`, `kw_malware_detected`) at the point each condition is detected; successful logins, password resets, admin-role changes, and defense-disabled events are read from WordPress core hooks. The `kw_slack_alert_send` filter is the final say on any alert, and `kw_slack_alert_login_roles` extends which roles count as privileged
- Sends are queued during the request (capped at 50) and flushed on `shutdown` (after `fastcgi_finish_request()` where available, so there is no visitor-facing latency), then posted with `blocking => true` and the response checked with `is_wp_error()` / HTTP status. This is best-effort, in-process delivery — chosen over a fire-and-forget (`blocking => false`) post because most admin write-actions call `wp_redirect()` + `exit` immediately after the event hook, which would tear down the socket before it transmits; it does not survive a hard process kill. The de-dupe transient is written only **after** a successful send, so a failed delivery doesn't suppress the retry; burst-prone categories (lockout/block) de-dupe per-category so an IP-rotating attack can't flood the channel. The webhook host is validated as `hooks.slack.com` (SSRF guard); the entire payload is built with `wp_json_encode()` **and** Slack mrkdwn control chars (`&`/`<`/`>`) are escaped on interpolated data, so usernames, IPs, and file paths cannot break the JSON or inject Slack mentions/links
- Optional **Notify (mention)** field: comma-separated Slack member IDs (e.g. `U012ABCDEF`) — or `@here` / `@channel` — to @-mention on every alert, so the right person for that site/project is pinged. Resolves from the `KW_SLACK_MENTION` constant → environment variable → setting. Note: Slack only notifies by member ID, not by display name
- **Wordfence integration (avoids duplicate detection):** only Wordfence *scan* findings are relayed (malware, file changes, vulnerable/outdated plugins), parsed from Wordfence's alert **emails** via the `wp_mail` filter and routed into the `malware`, `file_changed`, and `plugin_update_critical` categories (anything else Wordfence emails falls through to `wordfence_alert`). Those three categories are listed in `KW_Security_Alerts::get_wordfence_sourced()`, where native detection short-circuits to prevent double-alerting — but only while Wordfence is active; if Wordfence is deactivated, native detection automatically resumes. Login, lockout, and IP-block detection is **always native** and version-independent — KW Security does not consume Wordfence's `wordfence_security_event` action, whose event names vary across Wordfence releases. Filterable via `kw_slack_wordfence_sourced`, `kw_slack_wordfence_email_routes`, `kw_slack_wordfence_email_skip`, and `kw_slack_is_wordfence_alert`. All other events (admin login/granted/deleted, password change, Application Password, WooCommerce REST key, defense disabled, Wordfence deactivated) are detected natively

### Version 26.06.04
- **Activity Log**: new feature (enabled by default) that records security-relevant events — user logins/logouts/failed logins/registrations/deletions/password resets, post create/update/trash/delete, media uploads/deletions, plugin activate/deactivate/install/update, theme switches/installs/updates, WordPress core updates, and KW Security settings changes
- Log viewable at **Settings → Activity Log** with search, sortable columns, type/action filter dropdowns, pagination, and a Clear All Logs action
- Entries stored in a dedicated `wp_kw_activity_log` table; 90-day retention enforced by a daily WP-Cron cleanup
- Settings toggle labels now switch between "Enabled"/"Disabled" to reflect the checkbox state

### Version 26.06.03
- **Disable Author URLs**: new independent toggle that redirects `/author/username` archive pages to the homepage for all visitors, preventing username exposure via author slugs
- **User Enumeration redirect**: `/?author=N` requests by anonymous visitors now redirect to the homepage (301) instead of returning a 404

### Version 26.06.01
- **Maintenance API**: new read-only REST endpoint (`/wp-json/kw-security/v1/site-status`) for the Kilowott maintenance agent — returns WP version, PHP version, and plugin update status; gated by `Authorization: Bearer <key>` (timing-safe comparison), HTTPS-enforced, rate-limited to 20 req/hour per IP
- **Auto-registration**: on plugin activation the site registers with the Kilowott maintenance scanner via a discovery document; the scanner delivers a per-site API key via the signed `/set-key` endpoint (RSA-2048/SHA-256); no manual key entry required on the client site
- **Nginx upload protection**: file-security `.htaccess` write is now server-aware — on Nginx/OpenResty (which ignores `.htaccess`) the write is skipped and a dismissible admin notice surfaces the equivalent Nginx location block to add to the server config; Apache/LiteSpeed behaviour unchanged
- **Maintenance API settings section**: new section in Settings → KW Security showing the active endpoint URL, API key field, and a Generate Key button; also adds the `Maintenance API` feature toggle (enabled by default)

### Version 26.05.10
- Bug fix: "Settings saved." notice was appearing twice on the KW Security settings page. WordPress core's `options-head.php` already calls `settings_errors()` for pages under the Settings menu, so the explicit call in our render method was duplicating the notice.

### Version 26.05.09
- Bug fix: clicking **Save Changes** on Settings → KW Security did nothing because the File Integrity scan/reset buttons were rendered as nested forms inside the main settings form. HTML disallows nested forms, so the browser silently closed the outer form and orphaned the Save button.
- File Integrity status panel now renders below the settings form instead of inside it.

### Version 26.05.08
- **Strong Password Policy**: enforces 12+ character passwords with uppercase, lowercase, digit, and special character requirements for administrator accounts. Applied at user creation, profile password changes, and password reset. Other roles are unaffected by default; the `kw_security_password_policy_roles` filter extends coverage if needed.

### Version 26.05.07
- **Login Rate Limiting**: locks out IPs for 1 hour after 5 failed attempts within 15 minutes; generic error message prevents username enumeration
- **File Integrity Monitoring**: daily WP-Cron scan of WP root directory; emails admin when unknown PHP files appear or `index.php`/`wp-config.php` are modified. Manual scan + baseline reset available from Settings → KW Security
- Auto-reset of integrity baseline after WordPress core updates (avoids false positives on legitimate `index.php` changes)
- Plugin deactivation now properly clears scheduled cron jobs
- Both new features address the Preikestolen Basecamp RCA (24 April 2026) findings on brute-force exposure and root-directory file injection

### Version 26.05.06
- **Feature toggle system**: every security feature can now be enabled or disabled from **Settings → KW Security**
- All features ON by default, except Hide Login URL which is opt-in
- Disabled features skip hook registration entirely (zero runtime cost)
- Hide Login URL slug/redirect configuration moved from Settings → General to the new KW Security settings page
- "Settings" link added to the plugin row on the Plugins screen for quick access

### Version 26.05.04
- HTTP security headers (X-Frame-Options, Content-Security-Policy, HSTS, Referrer-Policy, Permissions-Policy, X-Content-Type-Options)
- Block user enumeration via `?author=N` for anonymous visitors
- Restrict `/wp/v2/users` REST endpoint to authenticated users only
- Disable XML-RPC pingback methods
- GitHub-based plugin update notifications via plugin-update-checker v5.6
- Fixed: `allow_security_updates_only` was silently blocking all plugin auto-updates (missing second filter argument)
- Fixed: duplicate hooks in comment disabling frontend logic
- Fixed: dashboard Recent Comments widget removal now fires at correct hook timing

### Version 26.04.07
- Initial release
- Controlled update management
- XML-RPC security disable
- Complete comment system disable
- Pingback and trackback blocking
- Comment REST API endpoint removal
- WordPress file editor disable
- Dangerous file upload blocking
- PHP execution prevention in uploads
- .htaccess upload directory protection
- Core, plugin, and theme update filtering
- **New Feature:** Added Custom Login URL rendering to completely hide the default `wp-login.php` and `wp-admin` workflows.

## License

This plugin is developed by KW Development.

---

**Developed by KW Development**