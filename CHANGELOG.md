# Changelog

Release notes for KW Security, newest first.

**This file is required to release.** The release workflow
(`.github/workflows/release.yml`) extracts the section matching the version being
released and uses it as both the GitHub release body and the Slack announcement.
A release with no matching `## <version>` section fails before anything is pushed,
tagged, or published.

## Format

Every entry uses this shape:

```markdown
## YY.MM.NN

### What's new
- What is actually different now, in terms a non-developer can see or act on.
  Short bullets. If a change shows up in the WordPress admin or as a Slack
  message, say where.

### Why it matters
- Why each change matters for the client sites and the team: what the risk, the
  manual work, or the blind spot was before. Short bullets, one point each.

### Changed
- What changed in behaviour, and anything an operator needs to know or do.

### New
- New capabilities. Omit the section if there are none.
```

**What's new** and **Why it matters** are what the team reads: they lead the GitHub
release body and are the whole of the Slack announcement. Write them for account
managers and support staff, not developers — no file names, class names, hook names,
or git vocabulary.

**Changed** and **New** are the technical record. They sit under a collapsed
*Technical detail* toggle on the release and never reach Slack.

Nothing here is generated. What the channel reads is exactly what you write, so it is
worth the five minutes. If the first two sections are missing the release still
succeeds — the announcement falls back to the technical text, labelled as such.

At least one subsection must have content. Keep bullets short: they are read in Slack,
not just on GitHub.

Versions are `YY.MM.NN`. The workflow computes the next `NN` for the current month
automatically, so add the heading for the version you are about to release.

---

## 26.08.08

### What's new
- Admin Users has a Reset Password action — send the standard WordPress
  reset-link email, or set a new password directly, both from the dashboard

### Why it matters
- Resetting an admin's password used to mean logging into that site first

### New
- `POST /wp-json/kw-security/v1/send-password-reset` — emails the standard
  WordPress reset link via `retrieve_password()`, the same thing "Lost your
  password?" on wp-login.php sends.
- `POST /wp-json/kw-security/v1/set-password` — sets a new password
  directly via `wp_set_password()` (which already invalidates that user's
  other sessions on its own). Logged to the Activity Log, attributed to
  the dashboard role behind the request, since `after_password_reset` only
  fires from the wp-login.php form flow, not from calling
  `wp_set_password()` directly.

## 26.08.07

### What's new
- The dashboard's "WP admin" button now logs straight into wp-admin with
  one click, the same way a hosting platform's own "Log in to WordPress"
  button works — no more typing a password
- Activating or deactivating a plugin from the dashboard now shows who
  actually did it in the Activity Log (e.g. "SuperAdmin (KW SECURITY
  DASH)") instead of "Guest"

### Why it matters
- Getting into wp-admin to check something used to mean finding or
  resetting a password first
- "Guest" gave no way to tell a real anonymous visitor apart from a
  legitimate dashboard action

### New
- `POST /wp-json/kw-security/v1/request-login` — issues a single-use,
  60-second login token for a dedicated "KW Security Dashboard"
  administrator account (created on first use, visible in the site's own
  Users list like any other admin — never a hidden backdoor). A follow-up
  request to `home_url('/?kw_security_login=...')` consumes the token and
  establishes a real logged-in session, then redirects to wp-admin. The
  resulting login is recorded in the Activity Log.
- `KW_Security_Dashboard_Actor` (in `mu-plugins/kw-security-activator.php`,
  always loaded) records which dashboard role is behind the current
  activate/deactivate request, so `on_plugin_activated()`/
  `on_plugin_deactivated()` in `classes/activity-log.php` can attribute the
  resulting entry instead of defaulting to "Guest". Threaded through
  `plugin-toggle.php` and the mu-plugin's own activate-plugin/
  activate-wordfence routes.

## 26.08.06

### What's new
- The Slack channel field is now a Channel ID instead of a pasted link —
  find it in Slack via the channel's details panel → Copy channel ID
- The dashboard can ask a site to check in right now instead of waiting for
  its next scheduled heartbeat — useful when a site has gone quiet and shows
  as Inactive even though the plugin is fine
- Any installed plugin can now be updated from the dashboard's Installed
  Plugins list, not just KW Security itself

### Why it matters
- A Channel ID is what Slack's own UI surfaces directly, rather than
  requiring you to already know how to construct or find a full link
- A site can go stale on the dashboard when its own WP-Cron has stalled (no
  traffic, a broken cron setup) — this gives a way to unstick it without
  waiting or logging into wp-admin
- Updating an out-of-date plugin previously meant logging into that site

### Changed
- `kw_slack_channel_link` is superseded by `kw_slack_channel_id`. The
  dashboard now builds the "View Channel" link itself, combining this ID
  with the Team ID already embedded in the webhook URL, instead of
  requiring a full link to be pasted in. The settings-page field and its
  sanitizer (`sanitize_slack_channel_id`) were updated to match — plain
  text, not a URL. `classes/slack-webhook-set.php`'s dashboard-write
  endpoint takes `channel_id` instead of `channel_link` in its signed
  request.

### New
- `POST /wp-json/kw-security/v1/refresh-heartbeat` — triggered by a REST
  request rather than WP-Cron, so it works even when the site's own cron
  has stalled. Calls `KW_Security_Telemetry::send_ping('heartbeat')`
  directly.
- `POST /wp-json/kw-security/v1/update-plugin-file` — updates any installed
  plugin by file path, validated against `get_plugins()` first (the same
  local-file-inclusion safeguard `plugin-toggle.php` already uses). Forces
  WordPress's own generic update check (`wp_update_plugins()`) rather than
  KW Security's specific GitHub-backed one (see `update-trigger.php`),
  since an arbitrary plugin's update source varies. Applies the same
  stuck-Inactive safety net as `update-trigger.php` when the plugin being
  updated happens to be KW Security itself.

## 26.08.05

### What's new
- KW Security update availability on the dashboard now refreshes within about
  an hour of a new release, instead of sometimes taking up to half a day
- The dashboard shows a site's configured login URL even while Hide Login
  URL is switched off, so it can be previewed before turning the feature on
- The Slack webhook and channel-link fields on the dashboard can now be set
  or changed directly from there, instead of requiring a login to this
  site's own Settings → KW Security page

### Why it matters
- A just-released update could sit invisible on the dashboard for hours even
  though installing it already worked fine if you tried — this closes that gap
- There was previously no way to see the configured login address unless the
  feature was already on
- Setting up Slack alerts for a new site meant logging into that site first

### Changed
- `KW_Security_Telemetry::get_update_info()` now forces a fresh check against
  the plugin's GitHub releases (via PUC's `checkForUpdates()`) before reading
  WordPress's `update_plugins` transient, instead of only reading whatever
  that transient already has cached. PUC's own schedule only refreshes it
  every ~12 hours; `classes/update-trigger.php`'s Update button already
  forced this same check before upgrading, so this brings the passive
  dashboard-facing read in line with that. Runs once per hourly heartbeat per
  site — one extra GitHub call per site per hour, well inside GitHub's
  per-IP rate limit.
- The heartbeat now reports `login_url` unconditionally —
  `KW_Security_Settings::get_login_url()` is a pure function of the
  configured slug, not of whether Hide Login URL is on, so there was no
  reason to withhold it while the feature is off.

### New
- `POST /wp-json/kw-security/v1/set-slack-webhook` — lets the dashboard set
  this site's own Slack webhook URL and channel-link bookmark remotely, same
  signed-request model as `toggle-feature.php`, validated the same way the
  settings page's own sanitizer already validates them. Refuses with a clear
  message if the site's webhook is set via a constant or environment
  variable, since a stored option would silently have no effect in that case.

## 26.08.04

### What's new
- Alert when a site has a KW Security or Wordfence update pending
- Alert when either security plugin is switched on or off
- Activate or deactivate plugins on any site from the KW Security dashboard, without
  logging into that site
- Every site reports its custom login URL (when hide-login is on) and which Slack
  channel its alerts go to

### Why it matters
- Deactivation was only alerting for Wordfence before
- Activation was not alerting on either Wordfence or this plugin before
- Unpatched security plugins were a blind spot
- A security plugin being switched off was invisible

### Changed
- `wordfence_deactivated` now covers KW Security as well as Wordfence and is relabelled
  accordingly. The option key is unchanged, so no site loses its saved preference.
- Wordfence and KW Security are excluded from `plugin_update_critical`, so a Wordfence
  security release produces one alert rather than two. Every other plugin is unaffected.
- The heartbeat reports the resolved Slack webhook URL and, when `hide_login_url` is on,
  the site's login URL. `KW_Security_Settings::get_login_url()` was extracted from
  `toggle-feature.php` so the heartbeat and the toggle response return the same value.
- The post-update handler re-arms the heartbeat cron and sends a fresh activation ping
  once it confirms the plugin ended up active, instead of relying on `activate_plugin()`
  firing the activation hook — which it does not when WordPress, or a stale
  `active_plugins` read from a persistent object cache, already believed the plugin was
  active. That left the heartbeat cron cleared and the site stuck Inactive.
- `primary_role()` and the activity log read the first role with `reset()` rather than
  `[0]`. Before WP 6.9, `get_role_caps()` built the roles list with `array_filter()`,
  which preserves keys, so a capability stored ahead of the role produced
  `array( 1 => 'administrator' )` — an "Undefined array key 0" warning on PHP 8 and a
  blank Role field on the alert. Affects WP 5.0–6.8.
- Release notes come from `CHANGELOG.md` rather than `gh release --generate-notes`, and
  the release body leads with the hand-written `### What's new` / `### Why it matters`
  with `### Changed` and `### New` collapsed underneath. Release announcements post to
  Slack and tag `@channel`.

### New
- `watched_plugin_update` alert category: fires on any available update to KW Security
  or Wordfence, whatever the size of the version jump, carrying an excerpt of the
  release notes. KW Security's notes come from its GitHub release body; Wordfence's from
  the wordpress.org changelog, narrowed to the entry for the new version. Cached for 12
  hours per version.
- `security_plugin_activated` alert category, and deactivation alerts extended to KW
  Security. Both default on.
- `classes/plugin-toggle.php` registers `POST /wp-json/kw-security/v1/toggle-plugin`,
  letting the dashboard activate or deactivate any installed plugin remotely, including
  this one. Same signed-request model as `toggle-feature.php` and `update-trigger.php`;
  `plugin_file` is validated against `get_plugins()` before `activate_plugin()` or
  `deactivate_plugins()` is called, since both `include()` the target file.
- `kw_slack_channel_link` option (Alerts & Integrations → Slack Security Alerts →
  Channel Link). A Slack Incoming Webhook URL does not itself encode which channel it
  posts to, so this is a manually pasted bookmark, reported alongside the resolved
  webhook on every heartbeat.
- Release announcements posted to Slack, with a `slack_webhook_override` input, a
  "don't post to Slack" checkbox, and a webhook resolved from input → secret → variable.
- The release workflow warns when the changelog carries sections for versions that were
  never tagged, so unreleased notes cannot pile up unnoticed.
