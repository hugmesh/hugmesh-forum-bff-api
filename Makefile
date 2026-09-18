# Makefile — repo-local developer entrypoints that MIRROR the CI pen-test stage
# (.gitlab-ci.yml -> pentest:sca / pentest:dast, which extend the generator's
# centralized hidden .pentest-* jobs). DEV-ONLY convenience; CI remains the
# enforcing path. `make pentest` runs the local SCA self-scan + (when a target is
# set) delegates the full DAST harness, and never hard-fails on missing tooling.

# --- Pen-test knobs --------------------------------------------------------
# CVSS gate for the local SCA self-scan. MUST track CI, or `make pentest-sca`
# reports a clean repo for findings CI fails on.
#
# CI's threshold is 7, not 9: `.gitlab-ci.yml`'s `pentest:sca` extends the
# generator's hidden `.pentest-sca`, which defaults `SCA_FAIL_CVSS: "7"` and
# passes it as `--failOnCVSS "${SCA_FAIL_CVSS}"` (hugmesh-generator
# tests/pentest/ci/pentest-stage.gitlab-ci.yml:66 and :79), and this repo's thin
# `pentest:sca` job does not override it. The GitHub-side `sca` job in
# .github/workflows/ci.yml pins the same 7.
#
# This line used to read `?= 9` above a comment claiming it mirrored a CI flag
# `-DfailBuildOnCVSS=9`. `git log -S'failBuildOnCVSS' -- .gitlab-ci.yml` returns
# empty — but this repo's history is SQUASHED (everything before "Initial public
# release" is one commit), so that shows only that no SURVIVING revision used the
# flag; the pre-squash inline SCA job that .gitlab-ci.yml:113-116 describes is not
# in this history at all. What is certain is the present tense: CI passes the
# Dependency-Check CLI's `--failOnCVSS`, never the Maven plugin's
# `-DfailBuildOnCVSS`. Either way the local mirror was two CVSS points LAXER than
# CI while asserting parity, so every CVSS 7.0-8.9 finding passed locally and
# failed in CI.
SCA_FAIL_CVSS ?= 7
# JDK image for the USE_DOCKER=1 path. 25 is the only defensible value:
# hugmesh-parent sets <java.version>25</java.version> (hugmesh-parent/pom.xml:29),
# this repo's Dockerfile:15 builds on eclipse-temurin:25-jdk, and
# .gitlab-ci.yml:60's `test` job runs eclipse-temurin:25-jdk-noble. It was pinned
# at 21, which cannot compile a release-25 build.
#
# DO NOT READ THAT AS "the USE_DOCKER=1 path works now". IT DOES NOT, and the JDK
# was never the FIRST thing that broke it. Measured 2026-09-17: the recipe below
# mounts only $(CURDIR) and .dep-check-data — no `-s settings.xml`, no ~/.m2
# mount, no CI_JOB_TOKEN — while pom.xml:15-20 declares the parent
# net.hugmesh:hugmesh-parent:2.8.0 with an EMPTY <relativePath/>, and that
# artifact is PRIVATE: GET https://repo1.maven.org/maven2/net/hugmesh/
# hugmesh-parent/2.8.0/hugmesh-parent-2.8.0.pom -> HTTP 404 (it lives in the
# in-cluster GitLab group registry — see settings.xml). So the container cannot
# build the project MODEL at all, on any JDK, and bumping this line does not
# change that. The non-docker branch works on a dev box only because
# ~/.m2/repository/net/hugmesh/hugmesh-parent/2.8.0 is already installed there.
# Neither branch has been EXECUTED to prove any of this end to end; wiring the
# docker branch the way .gitlab-ci.yml:55-60 does (`-s settings.xml`, the three
# GitLab env vars, and `--user` so the container cannot root-own the mounted
# ~/.m2) is a numbered box on hugmesh/hugmesh-forum-bff-api#2, deliberately not
# done here.
#
# Both `|| { echo ...; exit 0; }` escapes below turn every one of those failures
# into a reassuring line and exit 0, so a dev cannot tell a scan that found
# nothing from a scan that never ran. Also boxed on #2; left in place because
# changing the local exit posture is not what this change is for.
JDK_IMAGE     ?= eclipse-temurin:25-jdk-noble
# Set USE_DOCKER=1 to run the SCA scan inside a JDK container instead of the host
# ./mvnw (needs docker). NOTE this is NOT byte-identical to CI: CI's `pentest:sca`
# runs the Dependency-Check CLI from the owasp/dependency-check image over the
# whole checkout, while both branches here drive the dependency-check-maven plugin.
# Same engine and same CVSS gate, different analyzer entry point — treat this as a
# fast local signal, not as a reproduction of the CI verdict.
USE_DOCKER    ?=
# DAST: when set, the full harness scans this already-running target. Unset =>
# DAST is skipped locally (the harness stands up its own env in CI).
DAST_TARGET_URL ?=
# Where to find / fetch the shared pen-test harness (generator tests/pentest).
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest
GENERATOR_REPO      ?= https://github.com/hugmesh/hugmesh-generator.git

.PHONY: pentest pentest-sca pentest-dast ci-parity

## pentest: run the local SCA self-scan + (optional) DAST harness, mirroring CI.
pentest: pentest-sca pentest-dast
	@echo "[pentest] done. CI runs the enforcing pentest:sca / pentest:dast jobs."

## pentest-sca: OWASP Dependency-Check over this repo (mirrors CI pentest:sca).
pentest-sca:
	@echo "[pentest-sca] OWASP Dependency-Check (failBuildOnCVSS=$(SCA_FAIL_CVSS))"
	@if [ -n "$(USE_DOCKER)" ]; then \
		echo "[pentest-sca] via $(JDK_IMAGE) (CI-equivalent)"; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-v "$(CURDIR)/.dep-check-data:/dep-check-data" \
			-w /workspace --entrypoint "" "$(JDK_IMAGE)" \
			./mvnw org.owasp:dependency-check-maven:check \
				-Dformat=HTML,JSON \
				-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
				-DdataDirectory=/dep-check-data -DautoUpdate=true -B \
		|| { echo "[pentest-sca] docker/scan unavailable or findings >= CVSS $(SCA_FAIL_CVSS) (non-fatal locally)"; exit 0; }; \
	elif [ -x ./mvnw ]; then \
		./mvnw org.owasp:dependency-check-maven:check \
			-Dformat=HTML,JSON -DfailBuildOnCVSS=$(SCA_FAIL_CVSS) -B \
		|| { echo "[pentest-sca] mvnw unavailable or findings >= CVSS $(SCA_FAIL_CVSS) (non-fatal locally)"; exit 0; }; \
	else \
		echo "[pentest-sca] no ./mvnw found; skipping (set USE_DOCKER=1 to run via $(JDK_IMAGE))"; \
	fi

## pentest-dast: delegate the full ZAP+probes+nuclei harness when a target is set.
pentest-dast:
	@if [ -z "$(DAST_TARGET_URL)" ]; then \
		echo "[pentest-dast] DAST_TARGET_URL unset; skipping local DAST."; \
		echo "[pentest-dast] CI's pentest:dast stands up env-test-build + runs the harness."; \
	elif [ -f "$(PENTEST_HARNESS_DIR)/run-pentest.sh" ]; then \
		echo "[pentest-dast] running harness against $(DAST_TARGET_URL)"; \
		ZAP_TARGET_URL="$(DAST_TARGET_URL)" \
		bash "$(PENTEST_HARNESS_DIR)/run-pentest.sh" --env external --scan baseline --pipeline main \
		|| { echo "[pentest-dast] harness reported findings/errors (non-fatal locally)"; exit 0; }; \
	else \
		echo "[pentest-dast] harness not found at $(PENTEST_HARNESS_DIR)."; \
		echo "[pentest-dast] clone it, e.g.:"; \
		echo "    git clone $(GENERATOR_REPO) /tmp/sg-gen && \\"; \
		echo "    PENTEST_HARNESS_DIR=/tmp/sg-gen/tests/pentest make pentest-dast DAST_TARGET_URL=$(DAST_TARGET_URL)"; \
	fi

## ci-parity: fail if the CI parity constants above have drifted apart.
# The two defects this file shipped (SCA_FAIL_CVSS 9 vs CI's 7, JDK_IMAGE 21 for a
# release-25 build) were BOTH invisible: nothing went red, and the comments above
# each one asserted parity while it was false. scripts/ci-parity-guard.sh is the
# committed guard that makes that drift fail a pipeline. It is pure text — no
# network, no Maven, no Docker — and runs first in .gitlab-ci.yml's `test` job
# (the only pipeline in this repo that actually executes) and in the GitHub
# `build` job.
ci-parity:
	@bash scripts/ci-parity-guard.sh
