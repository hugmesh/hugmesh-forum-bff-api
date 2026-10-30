#!/usr/bin/env bash
# Tests for scripts/release-version.sh (the release.yml version guard) and for release.yml's
# overwrite guard step, executed under bash -e with docker stubbed. Pure text, no network.
# Run: bash scripts/test-release-version.sh
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${SCRIPT_DIR}/release-version.sh"
REAL_POM="${SCRIPT_DIR}/../pom.xml"
IMG=ghcr.io/hugmesh/hugmesh-forum-bff-api
SHA=0123456789abcdef0123456789abcdef01234567
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FAILURES=0

pom() {
  # $1 = project version. The parent carries a DIFFERENT version on purpose: the guard must
  # read <project><version>, never the first <version> in the file.
  cat > "${WORK}/pom.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>net.hugmesh</groupId>
    <artifactId>hugmesh-parent</artifactId>
    <version>9.9.9</version>
  </parent>
  <artifactId>forum-bff</artifactId>
  <version>$1</version>
</project>
EOF
}

run() {
  # $1 = ref; runs the guard against ${WORK}/pom.xml; sets OUT and RC.
  set +e
  OUT="$(RELEASE_POM="${WORK}/pom.xml" IMAGE="${IMG}" GITHUB_REF="$1" GITHUB_SHA="${SHA}" GITHUB_OUTPUT="" bash "${GUARD}" 2>&1)"
  RC=$?
  set -e
}

check() {
  # $1 = description, $2 = condition result (0 = pass)
  if [ "$2" -eq 0 ]; then
    printf 'ok   %s\n' "$1"
  else
    printf 'FAIL %s\n---- guard output:\n%s\n----\n' "$1" "${OUT}" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

has() { case "${OUT}" in *"$1"*) return 0 ;; *) return 1 ;; esac; }
lacks() { if has "$1"; then return 1; else return 0; fi; }

# 1. push to main: :main + :sha only, never a version, :beta or :latest.
pom 0.2.0-beta.1; run refs/heads/main
r=0; [ "${RC}" -eq 0 ] && has 'kind=main' && has "tags=${IMG}:main,${IMG}:sha-0123456789ab" \
  && lacks ':latest' && lacks ':beta' && lacks ":0.2.0-beta.1" || r=1
check "main publishes :main and :sha-<12> only" "${r}"

# 2. matching beta tag: :<version>, :sha, :beta; never :latest.
pom 0.2.0-beta.1; run refs/tags/v0.2.0-beta.1
r=0; [ "${RC}" -eq 0 ] && has 'kind=release' && has 'version=0.2.0-beta.1' \
  && has "${IMG}:0.2.0-beta.1" && has "${IMG}:sha-0123456789ab" && has "${IMG}:beta" && lacks ':latest' || r=1
check "beta tag publishes :<version>, :sha-<12> and :beta, no :latest" "${r}"

# 3. tag that does not match the pom version is refused.
pom 0.2.0-beta.1; run refs/tags/v0.2.0-beta.2
r=0; [ "${RC}" -ne 0 ] && has 'does not match' && lacks 'kind=' || r=1
check "tag v0.2.0-beta.2 against pom 0.2.0-beta.1 is refused" "${r}"

# 4. a SNAPSHOT is never published, not even from main.
pom 0.2.0-SNAPSHOT; run refs/heads/main
r=0; [ "${RC}" -ne 0 ] && has 'SNAPSHOT' && lacks 'kind=' || r=1
check "SNAPSHOT version is refused on main" "${r}"

# 5. other branches, pull-request refs and non-v tags are refused.
pom 0.2.0-beta.1
for ref in refs/heads/feature/x refs/pull/7/merge refs/tags/studio-v0.2.0-beta.1 refs/tags/0.2.0-beta.1; do
  run "${ref}"
  r=0; [ "${RC}" -ne 0 ] && lacks 'kind=' || r=1
  check "ref ${ref} is refused" "${r}"
done

# 6. '+build' metadata cannot become an OCI tag.
pom 0.2.0-beta.1+build.7; run refs/heads/main
r=0; [ "${RC}" -ne 0 ] && lacks 'kind=' || r=1
check "version with +build metadata is refused" "${r}"

# 7. only a final release moves :latest; another prerelease (rc) moves nothing.
pom 1.0.0; run refs/tags/v1.0.0
r=0; [ "${RC}" -eq 0 ] && has "${IMG}:latest" && lacks ':beta' || r=1
check "final 1.0.0 tag adds :latest" "${r}"
pom 1.0.0-rc.1; run refs/tags/v1.0.0-rc.1
r=0; [ "${RC}" -eq 0 ] && lacks ':latest' && lacks ':beta' || r=1
check "rc tag moves neither :beta nor :latest" "${r}"

# 8. the committed pom.xml passes the guard on main and names a beta (this repo is in beta).
set +e
OUT="$(RELEASE_POM="${REAL_POM}" IMAGE="${IMG}" GITHUB_REF=refs/heads/main GITHUB_SHA="${SHA}" GITHUB_OUTPUT="" bash "${GUARD}" 2>&1)"
RC=$?
set -e
r=0; [ "${RC}" -eq 0 ] && has 'version=' && has '-beta.' || r=1
check "committed pom.xml version passes the guard and is a -beta.N" "${r}"

# 9. GITHUB_OUTPUT receives the same four keys.
pom 0.2.0-beta.1
: > "${WORK}/out"
RELEASE_POM="${WORK}/pom.xml" IMAGE="${IMG}" GITHUB_REF=refs/tags/v0.2.0-beta.1 GITHUB_SHA="${SHA}" GITHUB_OUTPUT="${WORK}/out" bash "${GUARD}" >/dev/null
OUT="$(cat "${WORK}/out")"
r=0; has 'kind=release' && has 'version=0.2.0-beta.1' && has 'sha12=0123456789ab' && has "tags=${IMG}:0.2.0-beta.1" || r=1
check "GITHUB_OUTPUT gets kind, version, sha12 and tags" "${r}"

# 10-13. release.yml's "Refuse to overwrite a published version" step, EXECUTED rather than
# read. Its run block is lifted out of the workflow verbatim and run the way GitHub runs a
# step with no `shell:` key: `bash -e {0}`. `set -uo pipefail` inside the block does not turn
# -e off, so a bare `out=$(docker ...)` followed by `rc=$?` dies on the first failing probe,
# which is exactly the normal first-publish answer ("not found"). `docker` is a stub on PATH
# that logs its argv, so each case also proves the probe really ran.
WORKFLOW="${SCRIPT_DIR}/../.github/workflows/release.yml"
STEP_NAME='Refuse to overwrite a published version'
awk -v want="${STEP_NAME}" '
  function indent(s) { match(s, /^ */); return RLENGTH }
  !in_step && $0 ~ "^ *- name: " want "$" { in_step = 1; next }
  in_step && !in_run && /^ *- name: / { exit }
  in_step && !in_run && /^ *run: \|$/ { in_run = 1; run_ind = indent($0); next }
  in_run {
    if ($0 ~ /^ *$/) { print ""; next }
    if (indent($0) <= run_ind) exit
    if (!body_ind) body_ind = indent($0)
    print substr($0, body_ind + 1)
  }
' "${WORKFLOW}" > "${WORK}/overwrite-guard.sh"
OUT="$(cat "${WORK}/overwrite-guard.sh")"
r=0; has 'docker buildx imagetools inspect' && has 'already exists in GHCR' || r=1
check "release.yml still has the '${STEP_NAME}' step with a run block" "${r}"

mkdir -p "${WORK}/bin"
cat > "${WORK}/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_LOG}"
ref="${!#}"
case "${STUB_MODE}" in
  absent)  printf 'ERROR: %s: not found\n' "${ref}" >&2; exit 1 ;;
  present) printf 'Name:      %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    sha256:%064d\n' "${ref}" 0; exit 0 ;;
  denied)  printf 'ERROR: failed to authorize: failed to fetch anonymous token: unexpected status: 403 Forbidden\n' >&2; exit 1 ;;
  *)       echo "stub: unknown STUB_MODE" >&2; exit 99 ;;
esac
STUB
chmod +x "${WORK}/bin/docker"

run_step() {
  # $1 = stub mode; runs the extracted block under `bash -e`, as GitHub does; sets OUT and RC.
  : > "${WORK}/docker.log"
  set +e
  OUT="$(PATH="${WORK}/bin:${PATH}" STUB_MODE="$1" STUB_LOG="${WORK}/docker.log" \
    IMAGE="${IMG}" VERSION=0.2.0-beta.1 bash -e "${WORK}/overwrite-guard.sh" 2>&1)"
  RC=$?
  set -e
  PROBED="$(cat "${WORK}/docker.log")"
}
probed() { [ "${PROBED}" = "buildx imagetools inspect ${IMG}:0.2.0-beta.1" ]; }

run_step absent
r=0; [ "${RC}" -eq 0 ] && probed && has "${IMG}:0.2.0-beta.1 is not published yet; continuing." || r=1
check "overwrite guard under bash -e: not found -> continues to the build" "${r}"

run_step present
r=0; [ "${RC}" -ne 0 ] && probed && has 'already exists in GHCR' || r=1
check "overwrite guard under bash -e: tag exists -> refuses" "${r}"

run_step denied
r=0; [ "${RC}" -ne 0 ] && probed && has 'could not tell whether' && has '403 Forbidden' \
  && lacks 'not published yet' || r=1
check "overwrite guard under bash -e: any other error -> fails closed" "${r}"

if [ "${FAILURES}" -ne 0 ]; then
  printf '\ntest-release-version: %d failure(s)\n' "${FAILURES}" >&2
  exit 1
fi
printf '\ntest-release-version: all checks passed\n'
