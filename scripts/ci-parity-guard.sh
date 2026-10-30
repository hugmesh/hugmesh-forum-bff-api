#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ci-parity-guard.sh — pin the constants that three CI surfaces MUST agree on.
#
# WHY THIS EXISTS. `Makefile` calls itself a mirror of the CI pen-test stage and
# was wrong twice at once (SCA_FAIL_CVSS 9 vs CI's 7; JDK_IMAGE 21 vs a
# release-25 build), and NOTHING went red for either. A drifted mirror is worse
# than no mirror: it reports a clean repo for findings CI fails on, and it does
# so while its own comment asserts parity. This script is the committed guard
# that makes that drift fail a pipeline instead of waiting for a human to read
# `make -n`.
#
# WHERE IT RUNS. `.gitlab-ci.yml`'s `test` job — the ONLY pipeline in this repo
# that actually executes (GitHub Actions here has never been assigned a runner;
# see the header of .github/workflows/ci.yml). It is also wired into the GitHub
# `build` job so it enforces there too, the day a runner exists.
#
# IT IS PURE TEXT. No network, no Maven, no Docker: it greps the committed files
# against each other, so it costs milliseconds and cannot flake.
#
# Run locally:  make ci-parity     (or: bash scripts/ci-parity-guard.sh)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Resolve the repo root from this script's own location, so the guard works from
# any cwd (CI calls it as `bash scripts/ci-parity-guard.sh` from $CI_PROJECT_DIR;
# a developer may call it from anywhere).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

MAKEFILE="Makefile"
GH_CI=".github/workflows/ci.yml"
GL_CI=".gitlab-ci.yml"
DOCKERFILE="Dockerfile"

FAILURES=0
NOTES=0

fail() {
  printf 'PARITY FAIL: %s\n' "$*" >&2
  FAILURES=$((FAILURES + 1))
}

note() {
  printf 'PARITY NOTE: %s\n' "$*" >&2
  NOTES=$((NOTES + 1))
}

ok() {
  printf 'parity ok: %s\n' "$*"
}

# Every file this guard reasons about must exist. A renamed or deleted CI file
# must break the guard LOUDLY — a guard that silently checks nothing is the
# failure mode it was written to prevent.
for f in "${MAKEFILE}" "${GH_CI}" "${GL_CI}" "${DOCKERFILE}"; do
  if [ ! -f "${f}" ]; then
    fail "${f} does not exist. This guard cross-checks it; either restore it or update scripts/ci-parity-guard.sh deliberately."
  fi
done
if [ "${FAILURES}" -ne 0 ]; then
  printf '\nci-parity-guard: %d failure(s) — cannot continue.\n' "${FAILURES}" >&2
  exit 1
fi

# `grep -a` throughout: one NUL byte anywhere in a file makes GNU grep skip the
# WHOLE file and exit 1, which would look exactly like "the pin is missing".
# Pipelines are drained to a variable (never `grep -q` into a pipe), because
# under `set -o pipefail` a SIGPIPE from a short-circuiting reader can report
# failure on a match it did find.

# ── 1. JDK major version ────────────────────────────────────────────────────
# Sources, in the order a human would check them:
#   Dockerfile          FROM eclipse-temurin:<N>-jdk   (the shipped build)
#   .gitlab-ci.yml      eclipse-temurin:<N>-jdk-noble  (the executing pipeline)
#   .github/workflows   java-version: '<N>'            (setup-java)
#   Makefile            JDK_IMAGE ?= eclipse-temurin:<N>-...
# hugmesh-parent's <java.version> is the real upstream, but it lives in another
# repo and is not resolvable here, so the in-repo four must at least agree.
JDK_SRC=""
JDK_VALS=""

collect_jdk() {
  # $1 = label, $2 = file, $3 = extended regex whose match ends in the number
  CJ_LABEL="$1"
  CJ_FILE="$2"
  CJ_RE="$3"
  CJ_HITS="$(grep -aoE "${CJ_RE}" "${CJ_FILE}" || true)"
  if [ -z "${CJ_HITS}" ]; then
    fail "no JDK version pin matching /${CJ_RE}/ found in ${CJ_FILE} (${CJ_LABEL}). If the pin moved, update this guard in the same commit."
    return 0
  fi
  while IFS= read -r CJ_LINE; do
    [ -n "${CJ_LINE}" ] || continue
    CJ_NUM="$(printf '%s' "${CJ_LINE}" | grep -aoE '[0-9]+$' || true)"
    if [ -z "${CJ_NUM}" ]; then
      fail "could not read a JDK major out of '${CJ_LINE}' in ${CJ_FILE} (${CJ_LABEL})."
      continue
    fi
    JDK_VALS="${JDK_VALS}${CJ_NUM}"$'\n'
    JDK_SRC="${JDK_SRC}  ${CJ_NUM}  <- ${CJ_FILE} (${CJ_LABEL}): ${CJ_LINE}"$'\n'
  done <<< "${CJ_HITS}"
}

collect_jdk "image build stages"   "${DOCKERFILE}" '^FROM +eclipse-temurin:[0-9]+'
collect_jdk "test job image"       "${GL_CI}"      'eclipse-temurin:[0-9]+'
collect_jdk "setup-java"           "${GH_CI}"      "java-version: *'[0-9]+"
collect_jdk "JDK_IMAGE"            "${MAKEFILE}"   '^JDK_IMAGE[ 	]*\?=[ 	]*eclipse-temurin:[0-9]+'

JDK_DISTINCT="$(printf '%s' "${JDK_VALS}" | grep -av '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')"
JDK_COUNT="$(printf '%s' "${JDK_VALS}" | grep -acv '^$' || true)"
JDK_UNIQ="$(printf '%s' "${JDK_VALS}" | grep -av '^$' | sort -u | grep -ac . || true)"

if [ "${JDK_UNIQ}" = "1" ]; then
  ok "JDK major is ${JDK_DISTINCT} in all ${JDK_COUNT} in-repo pins (Dockerfile, .gitlab-ci.yml, .github/workflows/ci.yml, Makefile)."
elif [ "${JDK_UNIQ}" = "0" ]; then
  fail "found NO JDK pins at all — see the per-file failures above."
else
  fail "JDK major DIVERGED across CI surfaces (${JDK_DISTINCT}). A Maven build cannot target a release its JDK does not know, and a local 'mirror' on the wrong JDK reports a result CI will never reproduce. Sources:"
  printf '%s' "${JDK_SRC}" >&2
fi

# ── 2. SCA CVSS threshold ───────────────────────────────────────────────────
# Makefile's local mirror and the GitHub `sca` job must gate at the same CVSS.
# Both must equal the generator's `.pentest-sca` default, which is checked in
# section 3 when the generator checkout is reachable.
MK_CVSS="$(grep -aoE '^SCA_FAIL_CVSS[ 	]*\?=[ 	]*[0-9]+(\.[0-9]+)?' "${MAKEFILE}" | grep -aoE '[0-9]+(\.[0-9]+)?$' || true)"
GH_CVSS="$(grep -aoE '^[ 	]*SCA_FAIL_CVSS:[ 	]*"?[0-9]+(\.[0-9]+)?' "${GH_CI}" | grep -aoE '[0-9]+(\.[0-9]+)?$' || true)"

if [ -z "${MK_CVSS}" ]; then
  fail "no 'SCA_FAIL_CVSS ?= <n>' assignment found in ${MAKEFILE}."
fi
if [ -z "${GH_CVSS}" ]; then
  fail "no 'SCA_FAIL_CVSS: <n>' env pin found in ${GH_CI} (the sca job)."
fi

# The GitHub job must actually USE the variable it pins, or the pin is decoration.
FAILONCVSS_USE="$(grep -aoE -- '--failOnCVSS +"?\$\{SCA_FAIL_CVSS\}"?' "${GH_CI}" || true)"
if [ -z "${FAILONCVSS_USE}" ]; then
  fail "${GH_CI} pins SCA_FAIL_CVSS but never passes it as --failOnCVSS \"\${SCA_FAIL_CVSS}\" — the threshold would be Dependency-Check's default, not the pinned one."
fi

if [ -n "${MK_CVSS}" ] && [ -n "${GH_CVSS}" ]; then
  if [ "${MK_CVSS}" = "${GH_CVSS}" ]; then
    ok "SCA CVSS gate is ${MK_CVSS} in both ${MAKEFILE} and ${GH_CI}."
  else
    fail "SCA CVSS gate DIVERGED: ${MAKEFILE} gates at ${MK_CVSS}, ${GH_CI} gates at ${GH_CVSS}. The laxer of the two reports a clean repo for findings the other fails on."
  fi
fi

# ── 3. Cross-repo: the generator's .pentest-sca default ─────────────────────
# The real upstream for the CVSS number is the generator template this repo's
# `pentest:sca` extends. It is a DIFFERENT repository, so it is checkable only
# when a checkout happens to be reachable. When it is not, say so loudly and
# count it as UNCHECKED — never as a pass. Override with PENTEST_STAGE_FILE.
PENTEST_HARNESS_DIR="${PENTEST_HARNESS_DIR:-../hugmesh-generator/tests/pentest}"
PENTEST_STAGE_FILE="${PENTEST_STAGE_FILE:-${PENTEST_HARNESS_DIR}/ci/pentest-stage.gitlab-ci.yml}"

if [ -f "${PENTEST_STAGE_FILE}" ]; then
  GEN_CVSS="$(grep -aoE '^[ 	]*SCA_FAIL_CVSS:[ 	]*"?[0-9]+(\.[0-9]+)?' "${PENTEST_STAGE_FILE}" | grep -aoE '[0-9]+(\.[0-9]+)?$' | head -n 1 || true)"
  if [ -z "${GEN_CVSS}" ]; then
    fail "${PENTEST_STAGE_FILE} exists but carries no SCA_FAIL_CVSS default — the template changed shape; update this guard."
  elif [ "${GEN_CVSS}" = "${MK_CVSS}" ]; then
    ok "generator .pentest-sca default SCA_FAIL_CVSS is ${GEN_CVSS}, matching this repo (${PENTEST_STAGE_FILE})."
  else
    fail "this repo gates SCA at ${MK_CVSS} but the generator's .pentest-sca defaults to ${GEN_CVSS} (${PENTEST_STAGE_FILE}), and this repo's thin pentest:sca job does not override it. CI's verdict is the generator's number."
  fi
else
  note "generator template NOT reachable at ${PENTEST_STAGE_FILE}, so the CVSS number was checked only for INTERNAL consistency (${MK_CVSS:-?}). The authoritative value is .pentest-sca's SCA_FAIL_CVSS in hugmesh/hugmesh-generator; if it moves, nothing in THIS repo will go red. Set PENTEST_STAGE_FILE=<path> to close that gap in a pipeline that has both checkouts."
fi

# ── 4. Pull request jobs never reach the self-hosted runner ───────────────────
# Once this repository is PUBLIC, anyone can open a pull request from a fork, and
# a workflow triggered by `pull_request` runs that fork's code. On a self-hosted
# runner that is a stranger's code on our host. Every workflow here that reacts
# to pull requests must therefore name, for every job, a plain GitHub-hosted
# label (ubuntu-*, windows-*, macos-*), written literally on one line. An
# expression is not accepted, not even one that routes fork pull requests to a
# hosted runner and everything else to a self-hosted one: that still puts a
# same-repository pull request's code on our host, which is the state this repo
# was found in on 2026-10-29 (the ci.yml header said "ubuntu-latest, literal"
# while both jobs still carried the routing expression).
#
# Scope, said plainly: this stops US from re-adding the hole by accident. It does
# not stop a fork, which can edit the workflow file inside its own pull request;
# that boundary is the organisation's runner-group and fork-approval settings
# (see "PUBLIC-REPO SAFETY" in ci.yml). Only single-line `runs-on:` values can be
# read by a text guard, so any other shape fails here and asks to be rewritten.
#
# Which triggers count. `pull_request` and `workflow_call` (a reusable workflow
# runs with its caller's event) count, and so do the other events a stranger can
# start: `pull_request_target`, `pull_request_review`,
# `pull_request_review_comment`, `issue_comment` and `workflow_run`. A workflow
# whose `on:` block names none of them (release.yml: push, tags, manual dispatch)
# may pick its runner by expression.
PR_EVENTS_RE='(^|[^A-Za-z_])(pull_request|workflow_call)([^A-Za-z_]|$)'
STRANGER_EVENTS_RE='(^|[^A-Za-z_])(pull_request_target|pull_request_review|pull_request_review_comment|issue_comment|workflow_run)([^A-Za-z_]|$)'
WF_SEEN=0
for wf in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "${wf}" ] || continue
  WF_SEEN=$((WF_SEEN + 1))
  # Comment lines are dropped first: this repo's workflows carry long prose
  # headers that mention pull_request and self-hosted runners in passing.
  wf_code="$(grep -av '^[[:space:]]*#' "${wf}" || true)"
  # Triggers are read from the top-level `on:` block ONLY. Matching the whole
  # file made release.yml (push / tag / workflow_dispatch only) look like a
  # pull_request_target workflow, because its publish-runner expression names
  # that event to EXCLUDE it. A file with no readable `on:` block is checked in
  # full, so an unusual layout is judged strictly, never skipped.
  wf_on="$(printf '%s\n' "${wf_code}" | awk '/^("?on"?):/ {f=1; print; next} f && /^[^[:space:]]/ {f=0} f')"
  [ -n "${wf_on}" ] || wf_on="${wf_code}"
  wf_stranger=0
  if printf '%s\n' "${wf_on}" | grep -aE "${STRANGER_EVENTS_RE}" >/dev/null; then
    wf_stranger=1
  elif ! printf '%s\n' "${wf_on}" | grep -aE "${PR_EVENTS_RE}" >/dev/null; then
    continue
  fi
  runs_on_lines="$(printf '%s\n' "${wf_code}" | grep -anE '^[[:space:]]*runs-on:' || true)"
  if [ -z "${runs_on_lines}" ]; then
    fail "${wf} reacts to pull requests but has no single-line 'runs-on:' this guard can read."
    continue
  fi
  wf_bad=0
  while IFS= read -r line; do
    value="${line#*runs-on:}"
    value="$(printf '%s' "${value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    case "${value}" in
      ubuntu-*|windows-*|macos-*) ;;
      '')
        fail "${wf}: 'runs-on:' with its value on later lines cannot be checked by this guard. Write it on one line."
        wf_bad=1 ;;
      *)
        if [ "${wf_stranger}" -eq 1 ]; then
          fail "${wf} has a trigger a stranger can start (pull_request_target, pull_request_review, pull_request_review_comment, issue_comment or workflow_run) and a job on '${value}'. On a public repository that job would run on that runner. Use a GitHub-hosted label such as ubuntu-latest."
        else
          fail "${wf} reacts to pull requests and has a job on '${value}'. On a public repository a pull request would run its code on that runner. Use a literal GitHub-hosted label such as ubuntu-latest."
        fi
        wf_bad=1 ;;
    esac
  done <<< "${runs_on_lines}"
  if [ "${wf_bad}" -eq 0 ]; then
    ok "${wf}: every job that a pull request can start runs only on GitHub-hosted runners."
  fi
done
if [ "${WF_SEEN}" -eq 0 ]; then
  fail "no workflow files found under .github/workflows — this guard expected at least ${GH_CI}."
fi

printf '\n'
if [ "${FAILURES}" -ne 0 ]; then
  printf 'ci-parity-guard: %d FAILURE(S), %d note(s). The CI surfaces disagree — fix them in one commit.\n' "${FAILURES}" "${NOTES}" >&2
  exit 1
fi
printf 'ci-parity-guard: all in-repo CI parity constants agree (%d note(s) above are UNCHECKED cross-repo items, not passes).\n' "${NOTES}"
