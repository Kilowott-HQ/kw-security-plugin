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

### Problem
- What was wrong, or what the team could not do before. Use `- n/a` for a pure
  feature release with no preceding defect.

### Changed
- What changed in behaviour, and anything an operator needs to know or do.

### New
- New capabilities. Omit the section if there are none.
```

At least one of the three subsections must have content. Keep the bullets short —
they are read in Slack, not just on GitHub.

Versions are `YY.MM.NN`. The workflow computes the next `NN` for the current month
automatically, so add the heading for the version you are about to release.

---

## 26.08.06

### Problem
- A release summary had one provider behind it and no retries: a single HTTP
  response was the whole attempt. Gemini answered `503 high demand` on the
  26.08.05 dry run — a transient spike that clears in seconds — and the
  announcement dropped straight to raw changelog text.
- The collapsed "Technical detail" block on a release repeated the whole
  changelog section, so "Problem" said in developer voice what "Why it matters"
  had just said in plain English two lines above it.

### Changed
- The summary now tries two providers in order, Groq first and Gemini second,
  each retried three times (about 2s, 6s, then 18s apart) on a rate limit, a
  timeout, or a 5xx. A bad key or an unknown model is not retried and hands over
  to the next provider immediately, as does a reply that comes back missing the
  What or the Why section. Only when both providers are exhausted does the
  release fall back to the changelog text.
- Either `GROQ_API_KEY` or `GEMINI_API_KEY` on its own is enough to produce a
  summary. Both free tiers; with neither key the release still succeeds.
- The run summary and the release log now name which provider and model actually
  wrote the text that went out.
- The collapsed "Technical detail" block carries `### Changed` and `### New`
  only. `### Problem` still appears when no plain-language summary was produced,
  where it is the only thing explaining why the release exists.

### New
- `GROQ_API_KEY` secret plus optional `GROQ_MODEL` and `GROQ_API_URL` variables,
  defaulting to `openai/gpt-oss-120b` on Groq's OpenAI-compatible endpoint.

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
