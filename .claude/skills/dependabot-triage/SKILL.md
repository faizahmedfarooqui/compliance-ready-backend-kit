---
name: dependabot-triage
description: >
  Review, verify, land, or close open Dependabot pull requests. Separates
  failures the bump caused from failures it inherited, verifies every major
  and every security-relevant update against primary release notes, checks
  the combined result locally, and lands it as one reviewable change. Use
  when asked to handle, review, triage, merge, or clean up Dependabot or
  dependency-update PRs, or when a dependency advisory is failing CI.
triggers:
  - dependabot
  - dependabot PRs
  - dependency PRs
  - dependency updates
  - bump dependencies
  - dependency advisories failing
  - pnpm audit failing
  - npm audit failing
  - security advisory
  - GHSA
  - review dependency PRs
license: MIT
metadata:
  author: faizahmedfarooqui
  version: "1.0.0"
---

# Dependabot triage

Dependency currency is a named control here (HIPAA 164.308(a)(5)(ii)(B), PCI-DSS Req 6.3.x,
SOC 2 CC7.1), so these PRs are compliance evidence, not housekeeping. The output of this skill
is a decision per PR with a reason attached, never a batch of blind merges and never a stale
queue.

Two failure modes to avoid, in order of how often they happen:

1. **Merging on green without reading the major.** CI passing means the code compiles and the
   tests that exist still pass. It does not mean a changed default is safe.
2. **Assuming a red check is the PR's fault.** When every open Dependabot PR fails the same
   check, the branch did not break it. Check the base branch before touching a single PR.

## Step 1: inventory, and find the shared cause

```bash
unset GITHUB_TOKEN GH_TOKEN   # so gh uses the keyring credential
gh pr list --state open --limit 50 \
  --json number,title,author,headRefName,mergeable,mergeStateStatus \
  --jq '.[] | select(.author.login | test("dependabot")) |
        "\(.number)\t\(.headRefName)\t\(.mergeable)/\(.mergeStateStatus)\t\(.title)"'

for n in <numbers>; do
  echo "=== #$n ==="
  gh pr view $n --json mergeStateStatus,reviewDecision,statusCheckRollup \
    --jq '{state:.mergeStateStatus, review:.reviewDecision,
           checks:[.statusCheckRollup[]? | "\(.name // .context): \(.conclusion // .state)"]}'
done
```

If one check fails identically across all of them, check the base branch before anything else:

```bash
gh run list --workflow=security.yml --branch main --limit 3 \
  --json databaseId,conclusion,headSha --jq '.[] | "\(.databaseId) \(.conclusion) \(.headSha[0:8])"'
gh run view <id> --json jobs --jq '.jobs[] | "\(.conclusion)\t\(.name)\t\(.databaseId)"'
gh run view --job <job-id> --log \
  | grep -E "high|critical|Package|Vulnerable versions|vulnerabilities found"
```

A red base branch blocks every Dependabot PR on a problem none of them caused, and no amount
of rebasing clears it. Fix the base first, in the same change if it is small.

Note the second half of that trap: a Dependabot branch cut before a fix landed on main still
fails even though main is now green, because its head predates the fix. Judge a PR by what its
head contains, not by what main contains.

## Step 2: classify before investigating

Sort each update, because the cost of review is not uniform:

- **Dev-only, types-only, patch** (`@types/*`, formatters, test tooling): read the diff, move on.
- **Runtime minor**: skim release notes for behaviour changes, confirm the lockfile carries no
  surprise transitive majors.
- **Runtime major**: full treatment, step 3. Never merge on green alone.
- **Security-relevant regardless of semver** (anything under `packages/crypto`, auth, token
  handling, TLS, password hashing): read the changelog even for a patch. A patch here is often
  a hardening release that is the reason to upgrade, and occasionally a strictness change that
  rejects input previously accepted.
- **GitHub Actions**: see step 6.

Check `.github/dependabot.yml` for deliberate `ignore` entries before proposing anything. In
this repo `@types/node` and `typescript` majors are pinned on purpose, with the reason recorded
inline. A PR that contradicts an `ignore` rule means the rule needs revisiting, not bypassing.

## Step 3: verify a major against primary sources

Release notes from the API, not from recollection:

```bash
gh api repos/<owner>/<repo>/releases/tags/v<version> --jq '.body'
gh api repos/<owner>/<repo>/pulls/<n> --jq '.title, .body'   # for a specific linked change
```

Then answer, in writing:

1. **What does it now require?** Node floor, peer ranges, server or protocol version. Check
   each against `.nvmrc`, `engines`, `docker-compose.yml`, and the CI service images. A floor
   satisfied by this repo can still break a downstream consumer, which is worth a note in the
   commit message.
2. **What defaults changed?** These are the silent ones, because nothing fails to compile.
   Cross-check every changed default against options the code sets explicitly: a default the
   code overrides is a non-event, a default it relies on is a behaviour change.
3. **Which of our call sites can observe the change?** Grep for the library's API surface and
   walk each hit. Include serialization boundaries, not just function signatures.

That third question is where the real bugs hide. A worked example from this repo: ioredis 6
switched to RESP3 by default, and Redis converts a Lua script's return value according to the
client's protocol. The RESP3 rules add cases for Lua booleans, nils, and tables tagged `map`,
`set` or `double`. The limiter's scripts return indexed tables of plain numbers, so they
convert identically under both protocols and nothing broke. Had they returned Lua `true`/`false`,
RESP3 would deliver real booleans where RESP2 delivered `1` and `null`, and an `allowed === 1`
comparison would have silently started rejecting every request. Compiles clean, tests pass,
limiter inverted. Confirm the mechanism from the vendor's own docs rather than reasoning about
it, and record the conclusion where the next person will hit it.

## Step 4: never invent an advisory id

Every GHSA, CVE, version range, and affected path is a lookup, never a recollection:

```bash
pnpm audit --audit-level=high
pnpm why <package> -r                      # the real dependency path
gh api "/advisories?ecosystem=npm&affects=<package>&per_page=20" \
  --jq '.[] | "\(.ghsa_id) | \(.cve_id) | \(.summary) | \([.vulnerabilities[] |
        select(.package.name=="<package>") | .vulnerable_version_range] | join(" ; "))"'
```

Fixing an advisory with a transitive dependency:

- Prefer letting a lockfile refresh resolve it, when the dependent's range already admits the
  fixed version. Confirm by reading the lockfile diff, then add nothing.
- Otherwise add a `pnpm.overrides` entry, keyed by major (`"js-yaml@4": "^4.3.1"`), matching
  the file's existing style. Verify the fixed version actually exists (`pnpm view <pkg> versions`)
  and that it still satisfies the dependent's range.
- `auditConfig.ignoreGhsas` is a last resort and needs a written justification next to it.

**Never weaken the gate to make it pass.** Not the `--audit-level`, not the
`fail-on-severity`, not deleting the step. A dev-only path is a reason to say so in the commit
message, not a reason to stop failing: the gate is the evidence the control exists.

### An override takes that version out of Dependabot's hands

This is the trap that closes behind you a week later. An override range is not a floor that drifts
upward: once `"fastify@5": "^5.11.0"` exists, 5.11.0 satisfies it, so a Dependabot PR raising the
declaring package to `^5.11.3` changes the lockfile not at all. It looks merged and does nothing,
which is worse than failing, and CI cannot see it because everything still passes.

So for any package with an override, treat the override as the version's single source of truth:
bump it in the same commit, and confirm by resolution rather than by the PR's diff.

```bash
pnpm why <pkg> -r | grep -A1 <dependent>    # reports the version you actually intended?
grep -E '^  <pkg>@[0-9]' pnpm-lock.yaml     # exactly one line, or you have two copies
```

Worth checking the whole override block whenever a Dependabot PR touches a package that appears in
it, since the same silence applies to every entry.

## Step 5: verify the combined result, then land it as one change

With a shared lockfile, N PRs each rewrite it, so merging them serially costs N
rebase-and-retest cycles and arrives at a combined state nothing tested together. Consolidate
instead, off the current base:

```bash
git checkout -b deps/weekly-<YYYY-MM-DD> main
# apply each PR's package.json change, then a single `pnpm install`, or merge the
# Dependabot branches into a scratch branch and copy the resulting tree over
```

Then run the repo's full gate locally before pushing, because CI ran each PR in isolation and
never ran the combination:

```bash
# Pick ONE install. A frozen install verifies the lockfile still matches package.json, so use it
# when you have only combined already-locked branches. The moment you edit package.json yourself
# (adding an override, say) it is SUPPOSED to fail, because the two now disagree: switch to a plain
# `pnpm install` to rewrite the lockfile, and read the resulting diff.
pnpm install --frozen-lockfile   # unchanged package.json
pnpm install                     # you edited package.json

pnpm build && pnpm typecheck && pnpm lint && pnpm format:check && pnpm test
pnpm audit --audit-level=high
git diff main --stat             # confirm only the files you expect
```

Check the lockfile diff is proportionate. A one-line override that rewrites hundreds of
lockfile lines resolved something else too, and you want to know what.

`main` requires a PR, so open one; do not push to `main`. Record in the commit message and PR
body: each version delta, the verdict per update, the breaking changes and why they are
satisfied here, the defaults that changed, what was verified and how, and anything a downstream
consumer must do. Distinguish pre-existing conditions (say so explicitly) from what the change
introduces. Follow the repo's commit conventions: no AI-attribution trailers, and no em or en
dashes anywhere, PR text included.

## Step 6: GitHub Actions pins deserve a deliberate answer

Dependabot proposes moving a floating major (`@v4`) to an exact patch tag (`@v4.37.4`). Taken
at face value that is the worst of the three options: tags stay mutable, so it buys no
supply-chain immutability, and every future patch now needs its own PR. The three real choices:

- **Full commit SHA** with a version comment. Immutable, what GitHub's hardening guide
  recommends, and Dependabot maintains SHA pins. Right answer for a repo whose selling point is
  auditable controls.
- **Floating major tag.** Automatic patches including security fixes, no PR noise, at the cost
  of trusting the publisher's tag.
- **Exact patch tag.** Explicit and reviewable, but pick it knowingly, and pair it with an
  `ignore` rule for action patch updates if the noise is not wanted.

Pick one and apply it consistently across every workflow rather than letting the convention
drift file by file.

## Step 7: close the loop

- Once the consolidating PR merges, Dependabot closes its own superseded PRs on its next run
  because the target versions are already satisfied. Do not close them beforehand: if the
  consolidating PR stalls, those branches are the fallback.
- Closing a PR on the merits (an update this repo will not take) needs a comment saying why,
  plus an `ignore` entry in `.github/dependabot.yml` with the reason inline, or Dependabot
  reopens the same proposal next week. A close without an ignore rule is a snooze.
- Anything deferred (an action pinning policy, a peer-dependency mismatch left alone) goes in
  the PR body under an explicit follow-up heading, so it is visible rather than forgotten.

## Reporting

Give a verdict table (PR, update, decision, reason), what was verified and how, what changed
in the base branch and why, and what is left for the user to decide. State plainly what was
not done. Do not sit in a poll loop waiting for CI: report where things stand and hand back.
