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

## 26.08.06

### What's new
- Release announcements in Slack now tag the whole channel, so a release lands as a
  notification rather than something you have to be scrolling to catch.
- The "What's new" and "Why it matters" you are reading are now written by hand in the
  changelog, not produced by an AI service. What the channel reads is exactly what
  somebody wrote and a reviewer approved.
- The collapsed "Technical detail" section on a release now carries only the technical
  record, instead of repeating the plain-language explanation in developer language.

### Why it matters
Release notes were being written by an external AI service, and that turned out to be
both unreliable and wordy. On the previous release the service answered "currently
experiencing high demand" and the announcement fell back to raw developer notes — the
exact unreadable output the plain-language sections existed to replace. A release
announcement that only works when somebody else's free service is having a good day is
not something the team can rely on.

Writing the two sections by hand costs a few minutes per release and removes the
dependency entirely. It also removes a subtler problem: generated text was verbose and
nobody had approved the specific words that went out to the channel. Now the
announcement is reviewed in the pull request alongside the code it describes, and reads
the way the person who did the work would explain it.

The sections live in the changelog rather than in a box on the release screen because
that box is a single line — bullets and paragraphs cannot survive it. In the changelog
they are written in a normal editor and kept with the work they describe.

### Changed
- The plain-language sections are read from `### What's new` and `### Why it matters` in
  the CHANGELOG.md entry for the version. The Groq/Gemini summary step, the
  `release_context` workflow input, and `.github/release-summary-prompt.md` are gone,
  along with the `GROQ_API_KEY` and `GEMINI_API_KEY` secrets they needed.
- An entry missing those two sections logs a warning and falls back to the technical
  text, labelled as such. The release still publishes.
- The Slack announcement tags `@channel`. The mention sits in its own section block
  rather than the header, because a Slack header is plain text and would print the
  mention as literal characters instead of notifying anyone.
- The collapsed "Technical detail" block carries `### Changed` and `### New` only.
  `### Problem` is retired from the format — "Why it matters" now covers it.

## 26.08.05

### Problem
- The first Slack release announcement read like developer notes: it explained
  auto-generated release notes, Releases API readability, and workflow inputs,
  none of which mean anything to the non-technical half of the team. Its bullets
  also broke mid-sentence, because the source changelog is hard-wrapped at 80
  columns and Slack treats those newlines as hard breaks.
- Nothing told the team that a client site had an update waiting for KW Security
  or Wordfence. Sites sat on old versions until somebody happened to open that
  site's dashboard, so a security patch could go unapplied for weeks.
- Nothing told the team when either security plugin was switched on or off. A
  site could lose its protection entirely — by mistake during other work, or
  deliberately — and nothing announced it.

### Changed
- Release announcements are now two plain-language sections, "What's new" and
  "Why it matters", generated from the technical changelog plus a business-context
  paragraph supplied at release time. The GitHub release body leads with the same
  two sections and keeps the technical changelog in a collapsed block underneath.
- The announcement now uses a proper Slack header block, and hard-wrapped text is
  unwrapped before sending so Slack reflows it instead of breaking sentences.
- Wordfence and KW Security are excluded from the existing
  `plugin_update_critical` category, so a Wordfence security release produces one
  alert rather than two. Every other plugin is unaffected.
- The `wordfence_deactivated` category now covers KW Security as well and is
  relabelled accordingly. The option key is unchanged, so no site loses its saved
  preference.

### New
- `watched_plugin_update` alert category: fires on any available update to KW
  Security or Wordfence, whatever the size of the version jump, carrying an
  excerpt of the release notes. KW Security's notes come from its GitHub release
  body; Wordfence's from the wordpress.org changelog, narrowed to the entry for
  the new version. Cached for 12 hours per version.
- `security_plugin_activated` alert category, and deactivation alerts extended to
  KW Security. Both default on.
- The summary prompt lives in `.github/release-summary-prompt.md` so tone and
  emphasis can be tuned without touching the release workflow.
- A "don't post to Slack" checkbox on the release workflow, for small fixes that
  don't warrant a channel update. The release still publishes with its full notes;
  only the channel post is suppressed, and the run log records why nothing posted.
- Configurable via a `GEMINI_API_KEY` secret plus optional `GEMINI_MODEL` and
  `GEMINI_API_URL` variables. Without the key the release still succeeds and the
  announcement falls back to the changelog text, labelled as such.

## 26.08.04

### Problem
- Releases were announced nowhere. The team had to watch the Releases tab to
  notice a new version, and the auto-generated notes were a list of commit
  subjects ("Icon changed", "Fixed Wordfence Integration") that explained neither
  what had been wrong nor what the release actually delivered.

### Changed
- Release notes now come from this file instead of `gh release --generate-notes`,
  so every release states the problem, the change, and any new features in the
  team's own words. A missing changelog section fails the release early — before
  the version bump is pushed or the tag is created — rather than publishing an
  unexplained release.
- The GitHub release body is now the same structured text, which makes it readable
  back from the Releases API by anything that needs to know what a version
  contains.

### New
- Release announcements posted to Slack, carrying the version, the changelog
  narrative, a link to the release, and a compare link against the previous tag.
- The announcement webhook is configurable without a code change, resolved in
  order: the `slack_webhook_override` workflow input (one-off redirect), the
  `RELEASE_SLACK_WEBHOOK_URL` Actions secret, then a `RELEASE_SLACK_WEBHOOK_URL`
  Actions variable. With none set, the release still succeeds and the announcement
  is skipped.
