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
