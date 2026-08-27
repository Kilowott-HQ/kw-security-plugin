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
Two or three plain-English paragraphs on the problem this release solves and why
it matters for the client sites and the team — what the risk, the manual work, or
the blind spot was before. Prose, not bullets.

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
- Every KW Security release is now announced in this Slack channel, tagging the whole
  channel so it arrives as a notification rather than something you have to be
  scrolling to catch. The announcement says what changed and why, in plain English,
  written by the person who did the work.
- A new alert tells you when a client site has an update waiting for KW Security or
  Wordfence, and includes an excerpt of what that update contains — so you can judge
  whether it is urgent without opening the site.
- A new alert tells you when either security plugin is switched on or off on a site,
  whether that was deliberate or a mistake made during other work.
- A Wordfence security release now produces one alert per site instead of two.
- Releases too small to be worth a channel update can be published quietly, using a
  "don't post to Slack" checkbox on the release screen.

### Why it matters
Until now a release went out and nobody was told. The team had to watch the Releases
tab to notice a new version, and what they found there was a list of commit subjects —
"Icon changed", "Fixed Wordfence Integration" — that explained neither what had been
wrong nor what the release actually delivered. Most of the people who look after these
client sites are not developers, and there was nothing written for them.

The bigger gap was on the sites themselves. Nothing announced that a site had a
security update waiting, so sites sat on old versions until somebody happened to open
that particular dashboard, and a security patch could go unapplied for weeks. Nothing
announced that a security plugin had been switched off either — a site could lose its
protection entirely, by accident during other work or deliberately, and the first
anyone knew of it was the next time they looked. Both of those are now alerts that
arrive in Slack on their own.

What ties it together is that the plain-English explanation is written by hand, in the
changelog, alongside the code it describes. It is reviewed in the pull request like any
other change, so the words that reach the channel are words somebody chose and somebody
else approved.

### Changed
- Release notes come from `CHANGELOG.md` rather than `gh release --generate-notes`. A
  missing section fails the release early — before the version bump is pushed or the
  tag is created — rather than publishing an unexplained release.
- The release body leads with `### What's new` and `### Why it matters` read straight
  out of the changelog entry, and keeps `### Changed` and `### New` in a collapsed
  "Technical detail" block underneath. One page serves a client-facing reader and a
  developer. It is also structured enough to read back from the Releases API, which is
  how the update alert below gets its excerpt.
- The Slack announcement tags `@channel`. The mention sits in its own section block
  rather than the header, because a Slack header is plain text and would render the
  mention as literal characters instead of notifying anyone.
- The announcement uses a proper Slack header block, and hard-wrapped text is unwrapped
  before sending so Slack reflows it instead of breaking sentences mid-clause.
- Wordfence and KW Security are excluded from the existing `plugin_update_critical`
  category, so a Wordfence security release produces one alert rather than two. Every
  other plugin is unaffected.
- The `wordfence_deactivated` category now covers KW Security as well and is relabelled
  accordingly. The option key is unchanged, so no site loses its saved preference.

### New
- Release announcements posted to Slack, carrying the version, the two plain-language
  sections, a link to the release, and a compare link against the previous tag.
- The announcement webhook is configurable without a code change, resolved in order:
  the `slack_webhook_override` workflow input (one-off redirect), the
  `RELEASE_SLACK_WEBHOOK_URL` Actions secret, then a `RELEASE_SLACK_WEBHOOK_URL`
  Actions variable. With none set, the release still succeeds and the announcement is
  skipped.
- `watched_plugin_update` alert category: fires on any available update to KW Security
  or Wordfence, whatever the size of the version jump, carrying an excerpt of the
  release notes. KW Security's notes come from its GitHub release body; Wordfence's
  from the wordpress.org changelog, narrowed to the entry for the new version. Cached
  for 12 hours per version.
- `security_plugin_activated` alert category, and deactivation alerts extended to KW
  Security. Both default on.
- A "don't post to Slack" checkbox on the release workflow, for small fixes that don't
  warrant a channel update. The release still publishes with its full notes; only the
  channel post is suppressed, and the run log records why nothing posted.
- The release workflow warns when the changelog carries sections for versions that were
  never tagged, so unreleased notes cannot pile up unnoticed.
