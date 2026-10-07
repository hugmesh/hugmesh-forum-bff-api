# Runbook — register the self-hosted `hugmesh-x86` GitHub Actions runner

> **Update 2026-10-07: `release.yml` no longer needs this runner.** It now runs on a
> GitHub-hosted runner and resolves the private `net.hugmesh` libraries from GitHub Packages
> (`.github/maven-ci-settings.xml`, secret `PACKAGES_READ_TOKEN`), so the tailnet reachability
> argument in section 1 no longer applies to it, and GitHub-hosted jobs start again. This
> runbook still describes the `hugmesh-x86` runner for any workflow that still targets it
> (for example `ci.yml`, where present).

**Status: NOT DONE. This is the operator-held half of the work.** An agent cannot
create a runner. Until someone follows this runbook on a real host, every GitHub
Actions workflow in `hugmesh-forum-bff-api`, `hugmesh-wiki-bff-api` and
`hugmesh-mesh-bff-api` will keep queueing and being cancelled — which is the
measured status quo, not a regression introduced by the change that added this file.

This is the authoritative copy. `hugmesh-wiki-bff-api` and `hugmesh-mesh-bff-api`
carry a short pointer to it plus their own repo-specific commands.

Decision record: <https://github.com/hugmesh/hugmesh-generator/issues/347#issuecomment-5722430270>
(decision **48 = B**, register a self-hosted `hugmesh-x86` runner; decision
**43a = A**, unify the three `release.yml` files on the all-secrets spelling).

---

## 1. Why a self-hosted runner is the only option

The private Maven deps `net.hugmesh:hugmesh-parent` and `net.hugmesh:hugmesh-commons`
are **not on Maven Central**. They live only in the in-cluster GitLab group Maven
registry, which is reachable **only over the tailnet (Tailscale)**. A
github.com-hosted runner has no route to it, so `runs-on: ubuntu-latest` could
never have produced a successful build here regardless of how the secrets were set.

The two alternatives were considered and rejected in decision 48:

- **Publish the two artifacts to GitHub Packages** and point `settings.xml` at it
  with `GITHUB_TOKEN`. This is a much larger change — it touches `hugmesh-parent`,
  `hugmesh-commons`, and the `settings.xml` of *every* consumer — and it still
  needs the billing block in §6 lifted.
- **Go public and use the free tier.** This is the plan *later*, per the operator's
  note on decision 48. It is not available today. See §7 for the security
  consequence of doing that while a self-hosted runner is attached.

## 2. What is measured today (2026-09-17)

Numbers below came from the GitHub REST API on 2026-09-17. Re-run the commands in
§5 rather than trusting these once time has passed.

| Fact | Value |
|---|---|
| `GET /repos/hugmesh/hugmesh-forum-bff-api/actions/runners` | `total_count` **0** |
| `GET /repos/hugmesh/hugmesh-wiki-bff-api/actions/runners` | `total_count` **0** |
| `GET /repos/hugmesh/hugmesh-mesh-bff-api/actions/runners` | `total_count` **0** |
| `GET /orgs/hugmesh/actions/runners` | **403** — token lacks `admin:org`. **Unknown**, not zero. |
| forum-bff `CI` runs since 2026-07-30 | 29 total at 2026-09-17T23:55Z: **25 `cancelled`**, 4 still `queued`. This number only grows — `ci.yml` triggers on `pull_request`, so every push to an open PR queues another run that will also sit 24h and be cancelled. Run `35286623449` was queued three seconds after the PR carrying this file was opened. |
| Of those 25 cancelled | **15** sat ~24h before being cancelled (GitHub's queue limit for a job no runner picks up); the rest were cancelled sooner by a newer push |
| Runner ever assigned | **Never** — `runner_name` empty and `steps` empty on every job |
| github-HOSTED runners | Billing-blocked account-wide: jobs die in 3-5s with *"recent account payments have failed or your spending limit needs to be increased"* |
| `GET /repos/hugmesh/hugmesh-forum-bff-api/branches/main/protection` | **403** — *"Upgrade to GitHub Pro or make this repository public"* |

Two things follow, and they should be said plainly rather than implied away:

1. **Nothing in these repos goes green until the runner exists.** The workflow
   changes that accompany this runbook do not fix CI. They make CI *capable of*
   running once the runner is registered, and they make a missing secret fail by
   name instead of ten minutes later inside Maven.
2. **The org-level runner question is unanswered.** This token gets 403 on
   `/orgs/hugmesh/actions/runners`, so there may or may not already be an
   org-level runner. Check it with an `admin:org`-scoped token (§5) before
   registering anything new — registering a second runner is wasteful but
   harmless; *assuming* one exists is not.

## 3. The host

Match the existing GitLab runner's host class. `.gitlab-ci.yml` in all three repos
tags its jobs `[hugmesh-x86, privileged]` — a **shell executor with Docker**.

| Requirement | Value |
|---|---|
| Architecture | x86_64 (`hugmesh-x86` is a literal architecture claim; do not put this label on an arm64 host) |
| OS | Linux |
| Docker | Required, and the runner's user must be able to reach the daemon. `ci.yml`'s `build` job runs Testcontainers; its `sca` job and every `release.yml` run a container image. Both preflight this and fail loudly if Docker is missing. |
| Java | Not required on the host — `actions/setup-java@v4` installs Temurin **25** per run and caches Maven. |
| Disk | Allow room for the Maven cache, the NVD feed cache (`.nvd-cache`, re-synced monthly), and Docker layers. The Dependency-Check NVD data alone is multi-GB. |
| Workspace | **Persistent** across runs, unlike a throwaway GitLab job container. This is why the `sca` job passes `--user $(id -u):$(id -g)` to the Dependency-Check container — a root-owned `reports/` or `.nvd-cache/` would break the next `actions/checkout`. Keep that in mind for anything else that runs a container here. |

## 4. Network reach

The runner needs **both** directions. A host that has only one of these will fail
in a way that looks like the other.

**Tailnet (this is the whole reason for a self-hosted runner):**

- The in-cluster GitLab **API v4** endpoint — whatever `GITLAB_API_V4_URL` is set to.
- The GitLab **group Maven registry** under it:
  `"$GITLAB_API_V4_URL/groups/$GITLAB_GROUP_ID/-/packages/maven"`.

**Public egress:**

- `github.com`, `api.github.com` — checkout and the Actions control plane.
- `*.actions.githubusercontent.com` — the runner's job/queue channel. Outbound
  HTTPS only; **no inbound port needs to be opened**, the runner long-polls.
- `ghcr.io` — `release.yml` pushes the image there.
- `repo.maven.apache.org` and the Gradle/Maven plugin mirrors — everything that is
  not `net.hugmesh:*` still comes from Central.
- `services.nvd.nist.gov` — only for `ci.yml`'s `sca` job (forum-bff).

GitHub publishes the current address ranges at `GET https://api.github.com/meta`
if the runner sits behind an egress allowlist.

## 5. Register it

**Choose a level first.**

| | Repo level | Org level |
|---|---|---|
| Registrations needed | **3** (one per repo) | **1**, shared by all three |
| Permission needed | repo admin | **org owner** |
| Visible to this token | yes | **no — 403** |
| Recommendation | fine, and it is what this token can verify | better if you already own the org; see §7 before choosing a runner *group* open to all repos |

Repo-level, per repo (`Settings -> Actions -> Runners -> New self-hosted runner`
gives the exact commands with a short-lived token):

```
# on the runner host, once per repo
mkdir -p ~/actions-runner-forum && cd ~/actions-runner-forum
curl -o actions-runner-linux-x64.tar.gz -L \
  https://github.com/actions/runner/releases/download/v<VERSION>/actions-runner-linux-x64-<VERSION>.tar.gz
tar xzf actions-runner-linux-x64.tar.gz

./config.sh \
  --url https://github.com/hugmesh/hugmesh-forum-bff-api \
  --token <REGISTRATION_TOKEN_FROM_THE_SETTINGS_PAGE> \
  --labels hugmesh-x86 \
  --name hugmesh-x86-forum \
  --work _work --unattended

sudo ./svc.sh install && sudo ./svc.sh start   # run as a service, survives reboot
```

**The label must be exactly `hugmesh-x86`.** The workflows ask for
`runs-on: [self-hosted, hugmesh-x86]`. `self-hosted` is applied automatically; the
architecture label (`X64`) is too. A typo here does not error — the job simply
queues forever and is cancelled at 24h, which is indistinguishable from having no
runner at all.

Repeat with `--url https://github.com/hugmesh/hugmesh-wiki-bff-api` (name
`hugmesh-x86-wiki`) and `.../hugmesh-mesh-bff-api` (name `hugmesh-x86-mesh`), each
in its own directory. One host can run all three services concurrently.

**Then add the secrets** — `Settings -> Secrets and variables -> Actions ->
Secrets` (the **Secrets** tab, not **Variables**), in **each** of the three repos
or once at org level:

| Secret | Meaning |
|---|---|
| `GITLAB_MAVEN_TOKEN` | Read-scoped token (or long-lived deploy token) for the GitLab group Maven registry. Reaches the build as the BuildKit secret `ci_job_token` and as `$CI_JOB_TOKEN`. |
| `GITLAB_API_V4_URL` | The in-cluster GitLab API v4 base, e.g. `https://gitlab.<tailnet>/api/v4` |
| `GITLAB_GROUP_ID` | The HugMesh GitLab group id |
| `NVD_API_KEY` | **Optional**, forum-bff `ci.yml` `sca` only. Speeds the Dependency-Check feed sync; the scan runs without it, just slower on a cold cache. |

All four are `secrets.`, **never** `vars.` — see §8.

**One consequence of decision 43a worth knowing before you debug a log.** GitHub
masks the *value* of every secret wherever it appears in job output. `GITLAB_GROUP_ID`
is a short number, so once it is a secret **every unrelated occurrence of those same
digits is replaced by `***`** — a port, a byte count, a line number, a timestamp
fragment. Nothing breaks, but a log can read as though it is redacting things it is
not. That is the cost of the one-namespace rule the operator chose; it is not a
reason to move the group id back to `vars.`, where it would silently interpolate to
the empty string if unset.

If `hugmesh-wiki-bff-api` or `hugmesh-mesh-bff-api` still has Actions **Variables**
named `CI_API_V4_URL` or `GITLAB_GROUP_ID`, or a **secret** named
`GITLAB_CI_JOB_TOKEN`, those were what the old workflows read. They are no longer
read by anything. Re-create them under the names above and then **delete the stale
entries**, so a future reader cannot mistake them for live configuration.

**Verify it was picked up:**

```
# repo level — expect total_count >= 1, status "online", and hugmesh-x86 in labels
env -u GH_TOKEN -u GITHUB_TOKEN gh api repos/hugmesh/hugmesh-forum-bff-api/actions/runners \
  --jq '.total_count, (.runners[] | {name, status, busy, labels: [.labels[].name]})'

env -u GH_TOKEN -u GITHUB_TOKEN gh api repos/hugmesh/hugmesh-wiki-bff-api/actions/runners \
  --jq '.total_count, (.runners[] | {name, status, labels: [.labels[].name]})'

env -u GH_TOKEN -u GITHUB_TOKEN gh api repos/hugmesh/hugmesh-mesh-bff-api/actions/runners \
  --jq '.total_count, (.runners[] | {name, status, labels: [.labels[].name]})'

# org level — needs an admin:org-scoped token; 403 under the current one
env -u GH_TOKEN -u GITHUB_TOKEN gh api orgs/hugmesh/actions/runners
```

The `env -u GH_TOKEN -u GITHUB_TOKEN` prefix matters: the ambient fine-grained
token cannot see these private repos and fails in ways that look like the repo not
existing.

**Then prove a job actually lands on it.** `total_count 1` only means the runner
registered, not that a job reaches it:

```
env -u GH_TOKEN -u GITHUB_TOKEN gh workflow run Release --repo hugmesh/hugmesh-forum-bff-api
env -u GH_TOKEN -u GITHUB_TOKEN gh run list --repo hugmesh/hugmesh-forum-bff-api --limit 1
# then, on the finished run, the field that proves it:
env -u GH_TOKEN -u GITHUB_TOKEN gh api repos/hugmesh/hugmesh-forum-bff-api/actions/runs/<ID>/jobs \
  --jq '.jobs[] | {name, status, conclusion, runner_name}'
```

`runner_name` non-empty is the assertion. On all 25 cancelled runs it is empty.

## 6. What this does NOT fix

Do not read a registered runner as "CI is now enforced". Three separate blockers
remain, and each is operator-held:

1. **Billing.** github-hosted runners are blocked account-wide. Irrelevant once
   everything is on `hugmesh-x86`, but it means there is no fallback if the
   self-hosted runner is down.
2. **Branch protection.** `PUT/GET .../branches/main/protection` returns 403:
   private-repo branch protection needs GitHub Pro/Team. **On the current plan a
   required status check cannot be configured at all**, so even a green `build`
   check does not block a merge. Nothing in a workflow file can change this.
3. **The GitLab pipeline stays the source of truth** until 1 and 2 are resolved.
   `.gitlab-ci.yml` is the pipeline that actually executes today.

## 7. Security — read before going public

A self-hosted runner on the tailnet holds credentials and network reach into the
cluster. GitHub's own guidance is not to use self-hosted runners on public
repositories, and it applies with force here:

- On a **public** repo, a `pull_request` from any fork would run that fork's
  workflow code on this host. `ci.yml` triggers on `pull_request`. That is
  arbitrary code execution with tailnet reach and access to the Maven registry
  token.
- The operator's decision-48 note plans to **go public later and use the free
  tier**. When that happens, the self-hosted runner must be removed from the repo,
  or the repo's Actions settings must be restricted (require approval for all
  outside contributors, and do not put the runner in a group open to public repos)
  **before** the visibility flip, not after.
- Prefer a **dedicated, disposable host** over a box that does anything else. The
  Actions workspace is persistent between runs, so one job can leave state another
  job reads.
- Scope `GITLAB_MAVEN_TOKEN` to **read** on the Maven registry. Nothing in these
  workflows publishes to GitLab.
- **`secrets.` is not a confidentiality guarantee for the two non-credential inputs.**
  `GITLAB_API_V4_URL` and `GITLAB_GROUP_ID` are passed to `docker/build-push-action`
  as **build-args** (forum `release.yml:156-158`, wiki `:160-161`, mesh `:155-156`),
  and build-args are recorded in the image history — `docker history` on a published
  GHCR image shows them. They are sourced from `secrets.` for the namespace reason in
  §8, not for secrecy. The actual credential is *not* a build-arg: it is routed
  through the BuildKit `secrets:` block (`ci_job_token`), which is mounted for one
  RUN and never lands in a layer. Keep it that way. This pattern predates the change
  and was inherited from forum-bff; it is called out so nobody reads `secrets.` on a
  build-arg as "this value is private".

## 8. Why all three inputs are `secrets.` and not `vars.` (decision 43a = A)

`vars.X` and `secrets.X` are different namespaces. **An org or repo secret does not
satisfy a `vars.` expression** — an unset `vars.` expression interpolates to the
empty string with no warning at all. Before this change, `wiki-bff` and `mesh-bff`
read `secrets.GITLAB_CI_JOB_TOKEN` + `vars.CI_API_V4_URL` + `vars.GITLAB_GROUP_ID`,
while `forum-bff` read all three as secrets. All three now use the secrets form.

The failure that mix produced is quiet, which is what makes it worth a section.
Measured 2026-09-17 with `maven-help-plugin:3.5.1:effective-settings` against the
committed `settings.xml`, with `CI_API_V4_URL` / `GITLAB_GROUP_ID` / `CI_JOB_TOKEN`
unset:

```
<url>${env.CI_API_V4_URL}/groups/${env.GITLAB_GROUP_ID}/-/packages/maven</url>
<value>${env.CI_JOB_TOKEN}</value>
```

Maven does **not** interpolate an unset `${env.*}` to empty. It leaves the
**literal** text in the repository URL and in the `Job-Token` header. The same
command with the three set renders
`https://gitlab.example/api/v4/groups/42/-/packages/maven` and `tok`, so the
contrast is the variable and not the plugin.

The consequence: the build does not fail saying "a secret is missing". It fails
much later, and somewhere else, as an **unresolvable parent POM** against a URL
that is not a URL. Every `release.yml` now runs a preflight step that checks the
three by name and exits 1 with the missing names before anything reaches Maven.
Reproduce it yourself:

```
cd "$(mktemp -d)"
env -u CI_API_V4_URL -u GITLAB_GROUP_ID -u CI_JOB_TOKEN \
  mvn -o -q -s /path/to/repo/settings.xml \
  org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-settings -Doutput=eff.xml
grep -n 'packages/maven' eff.xml
```

### 8.1 This unified THREE repos, not the org. Do not read it as a convention that holds.

Decision 43a names "all three `release.yml`", and three is what this change touches.
**Six repos in the org consume these GitLab registry inputs, and after this change
three of them still disagree — in three further spellings.** A reader who lands on
§8 and concludes "the org uses `GITLAB_MAVEN_TOKEN` / `GITLAB_API_V4_URL` /
`GITLAB_GROUP_ID`" would be wrong in half the repos, so it is written down here
rather than left to be rediscovered.

Census taken 2026-09-17 by reading `.github/workflows/release.yml` on `main` through
the GitHub contents API in **every** repo in the org (41 repos; 25 have a
`release.yml`; 6 consume these inputs). Line numbers are on `main` at the time of
measurement.

| Repo | Token input | API URL input | Group id input | After this change |
|---|---|---|---|---|
| `hugmesh-forum-bff-api` | `secrets.GITLAB_MAVEN_TOKEN` | `secrets.GITLAB_API_V4_URL` | `secrets.GITLAB_GROUP_ID` | **unified** (was already this shape) |
| `hugmesh-wiki-bff-api` | `secrets.GITLAB_CI_JOB_TOKEN` | `vars.CI_API_V4_URL` | `vars.GITLAB_GROUP_ID` | **unified** by this change |
| `hugmesh-mesh-bff-api` | `secrets.GITLAB_CI_JOB_TOKEN` | `vars.CI_API_V4_URL` | `vars.GITLAB_GROUP_ID` | **unified** by this change |
| `hugmesh-mod-bff-api` | `secrets.CI_JOB_TOKEN` (`:68`) | `vars.CI_API_V4_URL` (`:70`) | `vars.GITLAB_GROUP_ID` (`:71`) | **UNCHANGED** — same `vars.`/`secrets.` split, third token name |
| `hugmesh-owncast-bff-api` | `secrets.CI_JOB_TOKEN` (`:35`, `:82`) | `secrets.CI_API_V4_URL` (`:33`, `:79`) | `secrets.GITLAB_GROUP_ID` (`:34`, `:80`) | **UNCHANGED** — all-secrets, but a fourth set of names |
| `hugmesh-admin-bff-api` | `secrets.MAVEN_REGISTRY_TOKEN` (`:63`) | `vars.MAVEN_REGISTRY_API_URL` (`:56`) | `vars.MAVEN_REGISTRY_GROUP_ID` (`:57`) | **UNCHANGED** — a fifth set of names, and another `vars.` split |

Two of those three (`mod-bff`, `admin-bff`) carry the *exact* defect 43a exists to
kill: a `vars.` expression that a configured secret can never satisfy, failing silently
as a literal `${env.*}` in the Maven repository URL. `owncast-bff` is internally
consistent but uses names nothing else uses.

**And the runner half is narrower still.** All **25** `release.yml` files on `main`
across the org say `runs-on: ubuntu-latest`. This change moves **three** of them to
`[self-hosted, hugmesh-x86]`. Every other workflow in the org remains pointed at a
github-hosted runner that (a) is billing-blocked and (b) could not reach the
tailnet-only registry even if it were not.

**Nothing tracks the remaining three.** No issue exists for them. An agent working
this lane was refused permission to create issues, stopped rather than routing
around it, and recorded the gap here and in the pull requests — see the "what the
operator must still do" list in the PR body. `hugmesh-admin-bff-api` in particular
**must not** be edited opportunistically: another workflow owns that repo.

