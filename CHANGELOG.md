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

## 26.08.04

### What's new
- A Slack alert now fires when a site has an update waiting for KW Security or
  Wordfence, carrying an excerpt of what that update contains — so you can tell a
  security patch from a routine one without opening the site.
- A Slack alert now fires when either security plugin is switched on or off on a site.
  Deactivation previously only covered Wordfence; it now covers KW Security too, so
  neither plugin can be turned off quietly.
- A Wordfence security release now produces one alert per site instead of two.
- Plugins can be activated or deactivated on any site directly from the Security
  Dashboard, without logging into that site.
- Every site now reports its custom login URL (when the hide-login feature is on) and
  the Slack channel its alerts go to, so there is one place to confirm a site is
  actually wired up rather than silently sending nowhere.
- A new "Channel Link" setting under Alerts & Integrations, for bookmarking the Slack
  channel a site posts to. It is only used for the dashboard's "View Channel" link.
- Sites no longer get stuck showing "Inactive" on the dashboard after a remote update.
- Slack alerts now show who made a change on older WordPress versions, where the role
  field could come through blank.

### Why it matters
- A client site was compromised. Everything here shortens the gap between something
  changing on a site and somebody knowing about it.
- Unpatched security plugins were the largest blind spot. Sites sat on old versions
  until somebody happened to open that particular dashboard, so a published fix could
  go unapplied for weeks — which is the window an attacker needs.
- A security plugin being switched off was invisible. That is both a routine attacker
  move after gaining access and an easy accident during other work, and either way the
  site was left unprotected with nobody told.
- Both new alerts default to on for every site, so no site has to be configured before
  it starts reporting.
- Toggling a plugin remotely means responding without first hunting for that site's
  credentials — taking a compromised plugin offline, or restoring protection across
  several sites, in the minutes after a discovery rather than the hours.
- Reporting the login URL and Slack channel on every heartbeat closes a verification
  gap: a site whose alerts were never wired up looked exactly like a site with nothing
  to report. Now the difference is visible from the dashboard.
- The blank role field affected WordPress 5.0 through 6.8 — nearly the whole supported
  range — and removed the "who did this" line from alerts at exactly the moment it
  matters most.
- A site wrongly showing "Inactive" is indistinguishable from one genuinely
  unprotected. Fixing it means the dashboard can be trusted at a glance.

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
