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

## 26.09.04

### What's new
- The "Update available for KW Security or Wordfence" Slack alert is
  switched off fleet-wide.

### Why it matters
- With every site's own Slack webhook now typically pointed at the same
  shared channel, one KW Security release meant one of these alerts per
  registered site landing in that channel at once. The setting to turn it
  off is per-site, so it couldn't be silenced fleet-wide from the settings
  screen alone.

### Changed
- `check_watched_plugin_updates()` is now a no-op regardless of the stored
  per-site setting. The checkbox is left in place (so no site's saved
  preferences are reset) but now has no effect; its label says so.

## 26.09.03

### What's new
- Slack alerts for plugin activation/deactivation, an admin account being
  granted or deleted, a defense being switched off, and similar no longer
  say "Activated by: system/guest" when nobody was logged in at the time.
  They now say **System**, **WP-CLI**, or **Scheduled Task (WP-Cron)**,
  whichever actually applies.

### Why it matters
- None of these actions can be performed by a real anonymous site visitor —
  they all require a WordPress capability no guest holds — so "guest" was
  never accurate. It read as "an unknown visitor did this," which is a very
  different, more alarming claim than what actually happened: the site's
  own automation (a scheduled update, a `wp` command, a plugin restored via
  FTP or a host's file manager) re-triggered the action outside any admin
  session.

### Changed
- `KW_Activity_Log::attribute_system_actor()` (new) supplies this
  attribution for `on_plugin_activated`, `on_plugin_deactivated`, and the
  plugin branch of `on_upgrader_complete` — checking the dashboard's own
  signed actions first, then WP-CLI, then WP-Cron, before falling back to
  "System". Left unchanged: `on_user_register` and `on_profile_update`,
  where an unauthenticated request can legitimately be a real visitor
  (self-registration), and `security-alerts.php`'s password-reset and
  blocked-upload alerts, which can too (a self-service reset, a public-form
  upload attempt).
- `KW_Activity_Log::system_actor_label()` (new) exposes the same logic as a
  plain string for `security-alerts.php`'s Slack notifications, replacing
  its own `current_user_label()` on exactly the alerts above that can never
  legitimately be anonymous (plugin activate/deactivate, admin granted/
  deleted, Super Admin granted/revoked, a defense disabled, a WooCommerce
  REST key created).

## 26.09.02

### What's new
- Creating a user from the dashboard's Add User page no longer asks for a
  password up front.
- First-time registration with the Security Dashboard now identifies itself
  with a shared key, matching a change already live on the dashboard's side.

### Why it matters
- The new-user account still emails the person a link to set their own
  password before they can sign in, so asking someone to type one into the
  dashboard first was an extra step for a value that got thrown away as soon
  as that link was used. Removing it also means no password ever has to
  travel from the dashboard to the site at all.
- The dashboard's registration endpoint now requires this key on every
  request. Without this update, a site activating KW Security for the first
  time cannot complete registration at all — this closes that gap. Sites
  that registered before this change are unaffected; registration only
  happens once per site.

### Changed
- `create-user`'s signed request no longer carries a password. The account's
  actual password is generated on the site itself and is never returned or
  logged anywhere.
- The Add User page's "Send this user login details by email" checkbox is
  now labelled "Email this user a link to set their password", matching what
  it actually sends.
- Registration now sends an `Authorization: Bearer` header alongside its
  existing signed payload.

## 26.09.01

### What's new
- Plugin updates now come from Kilowott's own update server instead of GitHub.
- Nothing changes for site owners: updates still appear on the WordPress
  Updates screen and install exactly as before.

### Why it matters
- The plugin's source can now be kept private without any site losing the
  ability to receive updates or security fixes.
- One fewer outside service sits between us and a site getting patched.

### Changed
- Update checks, the dashboard's update action, and the Slack update alert now
  read from the update server rather than the GitHub Releases API.
- The update endpoint can be overridden per site, for staging.
- The release process uploads the build to the update server and verifies the
  live endpoint — version, checksum, and lockdown rules — before finishing.

### New
- The distribution directory serves only the update metadata and the plugin
  package. Nothing else in it is reachable or executable.

## 26.08.12

### What's new
- Plugin Lockout now only locks down **KW Security, KW Performance, and
  Wordfence** — every other plugin can be installed, activated,
  deactivated, updated, or deleted completely normally while it's on. It
  previously blocked every plugin on the site.
- Turning Plugin Lockout off is now temporary: if left off, it
  automatically switches back on after 8 hours

### Why it matters
- Locking down the site's own security tooling shouldn't mean losing the
  ability to manage anything else installed on the site
- A protection that gets switched off "just for a minute" and then
  forgotten about isn't protection — an automatic 8-hour limit means it
  can't be left off indefinitely by accident

### Changed
- `classes/plugin-lockout.php` no longer strips any WordPress capability
  (`install_plugins`/`update_plugins`/`delete_plugins`/`edit_plugins`/
  `activate_plugins` are all whole-site, not per-plugin, so revoking one
  blocked every plugin, not just the three intended). It now blocks
  specific requests instead, checking which plugin a request actually
  names against the three-item locked list, on `plugins.php`,
  `update.php`, and `plugin-editor.php`. The Add Plugins screen and the
  Plugin File Editor — both fully inaccessible before — now work
  normally for anything other than the three locked plugins.
- `classes/settings.php`'s `sanitize_features()` now detects a
  Plugin Lockout on→off transition (from either the settings page or a
  remote dashboard toggle) and schedules a one-off WP-Cron event 8 hours
  out that turns it back on; turning it back on manually clears the
  pending event. The resulting Activity Log entry is attributed to
  "System".

## 26.08.11

### What's new
- Plugin Lockout now leaves the Installed Plugins list visible in
  wp-admin — only installing, activating, deactivating, updating, and
  deleting a plugin from there is blocked. It previously hid the whole
  Plugins screen instead.
- The one-click "WP admin" login now correctly attributes the very first
  sign-in on a site (which also creates the dashboard's own account
  there) to the acting dashboard role in the Activity Log, instead of
  "Guest"

### Why it matters
- Site owners still need to see what's installed even while locked down
  — only the ability to change anything needed to be blocked
- "Guest" gave no way to tell that first sign-in apart from a real
  anonymous visitor

### Changed
- WordPress ties viewing wp-admin's Plugins screen to the same
  permission as activating/deactivating a plugin — there's no way to
  grant one without the other. Activate/deactivate are now blocked by
  rejecting the request itself (and hiding the Activate/Deactivate/Delete
  links) rather than by revoking that permission outright, the way
  Install/Update/Delete/Edit still are. See `classes/plugin-lockout.php`.
- `classes/dashboard-login.php` now records the acting dashboard role
  before creating the site's "KW Security Dashboard" account, not after
  — that account is only ever created once, on a site's very first
  one-click login, and the old order meant that one specific event could
  never be attributed correctly.

## 26.08.10

### What's new
- New **Plugin Lockout** toggle (Settings → KW Security → Hardening, or
  from the dashboard) — once on, plugins on this site can only be
  installed, activated, deactivated, or updated through the KW Security
  Dashboard, not even by an existing Administrator
- Installed Plugins on the dashboard has an **Add Plugin** page
  (SuperAdmin only) — install a real plugin from wordpress.org's own
  "most used" list, or search for one by name, without logging into the
  site
- Dashboard-triggered plugin updates now show who actually did it in the
  Activity Log instead of "Guest"

### Why it matters
- If an admin login is ever compromised, Plugin Lockout stops the
  intruder from installing a malicious plugin or disabling security
  plugins from wp-admin
- Adding a plugin previously meant logging into that site's wp-admin
- "Guest" gave no way to tell a real anonymous event apart from a
  legitimate dashboard action

### Changed
- The Installed Plugins list stays visible in wp-admin while Plugin
  Lockout is on — only installing, activating, deactivating, updating,
  and deleting are blocked. WordPress ties viewing the list to the same
  permission as activating/deactivating a plugin, so that specific pair
  is enforced by rejecting the request itself (and hiding the
  Activate/Deactivate links) rather than by a capability alone; install,
  update, and delete each have their own separate capability and are
  blocked the same way User Lockout blocks things — by revoking it
  outright. Deleting a plugin isn't available from the dashboard yet
  either, so deactivate instead while this is on.
- `on_upgrader_complete()` in `classes/activity-log.php` now attributes a
  dashboard-triggered plugin install/update to the acting dashboard role,
  same as plugin activate/deactivate already does. `classes/update-trigger.php`
  and `classes/plugin-file-update.php` now pass that role through.

### New
- `plugin_lockout` feature key. `classes/plugin-lockout.php` strips
  `install_plugins`, `update_plugins`, `delete_plugins`, and
  `edit_plugins` via `map_meta_cap()`. Activate/deactivate are blocked
  separately: an `admin_init` hook rejects any plugins.php request other
  than a plain page view before plugins.php's own handler runs, and the
  Activate/Deactivate/Delete row links and the bulk-actions dropdown
  entries are hidden so there's nothing clickable that would hit it.
- `POST /wp-json/kw-security/v1/install-plugin` (`classes/plugin-install.php`)
  — resolves the download link itself from wordpress.org via the plugin
  slug (never trusts a URL from the dashboard), installs via
  `Plugin_Upgrader`, and activates it — the same sequence wp-admin's own
  Add Plugins screen uses.

## 26.08.09

### What's new
- The dashboard's one-click "WP admin" login now automatically signs out
  after 8 hours, instead of staying signed in for up to two weeks
- New **User Lockout** toggle (Settings → KW Security → Login & Access, or
  from the dashboard) — once on, WordPress users on this site can only be
  added, edited, or removed through the KW Security Dashboard, not even by
  an existing Administrator in wp-admin
- Admin Users on the dashboard has an **Edit** action (email, name, role)
  and an **Add User** page — manage a site's WordPress users, with a role,
  without logging into it

### Why it matters
- A one-click login left that account signed in for up to two weeks even
  after the person who requested it closed the tab — an 8-hour cap limits
  how long that access window stays open
- If an admin login is ever compromised, User Lockout stops the intruder
  from renaming, deleting, resetting the password on, or managing 2FA for
  any account, or planting a new one, as a durable backdoor
- Adding or editing a user previously meant logging into that site's
  wp-admin

### Changed
- `wp_set_auth_cookie( $user_id, true )` for the "KW Security Dashboard"
  account (`classes/dashboard-login.php`) previously meant WordPress's
  normal 14-day "remember me" session length. An `auth_cookie_expiration`
  filter now caps that account's session at 8 hours regardless — every
  other user is unaffected, and no cron or scheduled event is involved:
  WordPress itself checks the stored expiration on every request.
- `on_user_register()` and `on_profile_update()` in `classes/activity-log.php`
  now attribute a dashboard-created or dashboard-edited user's log entry to
  the acting dashboard role (e.g. "SuperAdmin (KW SECURITY DASH)") instead
  of "Guest", the same way plugin activate/deactivate already does.

### New
- `user_lockout` feature key. `classes/user-lockout.php` strips the
  `create_users`, `edit_users`, and `delete_users` capabilities from every
  user via `map_meta_cap()` when enabled — one filter closes wp-admin's Add
  New User screen, the Edit/Delete/Send password reset row actions and
  bulk actions on the Users list, and the equivalent REST endpoints, since
  all of them gate on one of those three capabilities. (Editing your own
  profile is unaffected — WordPress never requires `edit_users` for that.)
  The Users list's "View" row action and any "Login Security" action a
  plugin like Wordfence adds to the same row aren't gated by a capability
  in core, so both are removed directly. Shows an info notice on the Users
  list screen explaining why.
- `POST /wp-json/kw-security/v1/update-admin-user` (`classes/admin-users.php`)
  — updates an existing administrator's email, name, and role via
  `wp_update_user()` directly, so it is unaffected by User Lockout. Same
  role whitelist and email-conflict check as user creation.
- `POST /wp-json/kw-security/v1/create-user` (`classes/create-user.php`) —
  creates a user via `wp_insert_user()` directly, so it is unaffected by
  User Lockout. Validates the role against a fixed whitelist (Administrator,
  Editor, Author, Contributor, Subscriber), rejects a password under 12
  characters, and checks `username_exists()` / `email_exists()` first for a
  clear conflict message instead of a generic failure. Optionally fires
  WordPress's own `wp_new_user_notification()` to email the new user a
  password-reset link.

## 26.08.08

### What's new
- Admin Users has a Reset Password action — send the standard WordPress
  reset-link email, or set a new password directly, both from the dashboard
- Slack announces an available plugin update once per version, instead of
  repeating the same update every hour or two until someone installed it

### Why it matters
- Resetting an admin's password used to mean logging into that site first
- The repeated update alerts were burying the alerts that need someone to act

### Changed
- The two update alerts (`watched_plugin_update`, `plugin_update_critical`)
  no longer forget that they already alerted. WordPress writes the
  `update_plugins` transient twice per check: first the value it just read
  (filtered, so it carries entries injected by bundled updaters such as this
  plugin's own PUC instance), then the wp.org response alone (which never
  carries them). The old cleanup dropped any `file@version` entry missing
  from the transient being written, so the second write erased what the first
  had just recorded and the next check re-announced the same version — every
  1-2 hours, per WordPress's own check throttle. Entries are now dropped only
  on positive evidence: the update was installed, the plugin is gone, or the
  entry has stood for 90 days (`UPDATE_ALERT_TTL`).
- Update alerts read the installed version from the plugin header when the
  transient carries no `checked` map, rather than reporting
  "Installed: unknown".
- The de-dupe sets are stored network-wide on multisite, since
  `update_plugins` is itself a network-wide transient and the hook fires on
  whichever site serves the request — one update no longer alerts once per
  subsite. The network option starts empty, so expect one final alert per
  pending update on multisite after this upgrade.

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
