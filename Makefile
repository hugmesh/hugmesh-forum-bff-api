# Makefile — repo-local developer entrypoints that MIRROR the CI pen-test stage
# (.gitlab-ci.yml -> pentest:sca / pentest:dast, which extend the generator's
# centralized hidden .pentest-* jobs). DEV-ONLY convenience; CI remains the
# enforcing path. `make pentest` runs the local SCA self-scan + (when a target is
# set) delegates the full DAST harness, and never hard-fails on missing tooling.

# --- Pen-test knobs --------------------------------------------------------
# CVSS gate for the local SCA self-scan (mirrors CI -DfailBuildOnCVSS=9).
SCA_FAIL_CVSS ?= 9
# JDK image used to run dependency-check exactly as CI does (when USE_DOCKER=1).
JDK_IMAGE     ?= eclipse-temurin:21-jdk-noble
# Set USE_DOCKER=1 to run the SCA scan inside the CI JDK image instead of the
# host ./mvnw (matches CI byte-for-byte; needs docker).
USE_DOCKER    ?=
# DAST: when set, the full harness scans this already-running target. Unset =>
# DAST is skipped locally (the harness stands up its own env in CI).
DAST_TARGET_URL ?=
# Where to find / fetch the shared pen-test harness (generator tests/pentest).
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest
GENERATOR_REPO      ?= https://github.com/hugmesh/hugmesh-generator.git

.PHONY: pentest pentest-sca pentest-dast

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
