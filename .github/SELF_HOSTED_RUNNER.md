# Runners for this repo's GitHub Actions workflows

**The `hugmesh-x86` runner label is retired.** An earlier version of this file was a
runbook for registering a self-hosted runner with that label, so that jobs could
reach a tailnet-only GitLab Maven registry. No runner ever carried the label, so
every `ci.yml` run and every `release.yml` dispatch sat in `queued` until GitHub
cancelled it. Both workflows now pick their runner the same way as the rest of the
org:

```yaml
runs-on: ${{ fromJSON(vars.RUNS_ON || '["ubuntu-latest"]') }}
```

- `vars.RUNS_ON` is a repository (or org) **variable** holding a JSON array of labels.
  On this repo it is `["self-hosted","Linux","X64"]`, which the org-level runner
  matches. Unset it to fall back to github-hosted `ubuntu-latest`.
- Both workflows need **Docker** on whichever runner they land on (`ci.yml`'s
  Testcontainers tests and `sca`, `release.yml`'s image build). `release.yml` checks
  this first and says so by name.

## Private Maven dependencies

`hugmesh-parent`, `hugmesh-commons` and `hugmesh-build-config` come from the org's
GitHub Packages Maven registries through `.github/maven-ci-settings.xml` (header
explains why it is a settings file and why it declares plugin repositories). No
tailnet access is needed any more. The read credential is

- `secrets.PACKAGES_READ_TOKEN` (a classic PAT with `read:packages`; optional
  `secrets.PACKAGES_READ_ACTOR` for its user name), else
- the automatic `GITHUB_TOKEN`, which works only after each upstream package lists
  this repository under *Package settings -> Manage Actions access*.

The old `GITLAB_MAVEN_TOKEN`, `GITLAB_API_V4_URL` and `GITLAB_GROUP_ID` secrets are no
longer read by any GitHub workflow. They still feed `.gitlab-ci.yml` and the local
compose lane through the repo-root `settings.xml` and the Dockerfile defaults.

## Security note for a self-hosted runner

A self-hosted runner runs `pull_request` workflow code on the host. Do not attach it to
a public repository without restricting Actions to approved contributors first, and
prefer a host that does nothing else: the Actions workspace persists between runs.

History of the retired plan: operator decision 48 = B in
<https://github.com/hugmesh/hugmesh-generator/issues/347>.
