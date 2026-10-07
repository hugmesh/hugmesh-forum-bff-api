# syntax=docker/dockerfile:1.7
# -----------------------------------------------------------------------------
# Multi-stage build for hugmesh-forum-bff-api.
#
# PRIVATE DEPENDENCY (hugmesh-commons): this service now depends on
# net.hugmesh:hugmesh-commons (managed by hugmesh-parent), which is NOT
# on Maven Central — it lives in the org's GitLab Maven Package Registry. The build
# stage resolves it via the committed `settings.xml` (the `gitlab-maven` repo) using
# the GitLab CI_JOB_TOKEN. The token is mounted as a BuildKit SECRET (never an ARG,
# never an ENV, never a layer), so it leaves no trace in the image history.
#
#   GitLab CI passes it as:  --secret id=ci_job_token,env=CI_JOB_TOKEN
#                            --build-arg CI_API_V4_URL --build-arg GITLAB_GROUP_ID
#
# GITHUB PACKAGES ROUTE (.github/workflows/release.yml): the same artifacts are also
# published to https://maven.pkg.github.com/hugmesh/<repo>. That workflow passes
#   --build-arg MAVEN_SETTINGS=.github/maven-ci-settings.xml
#   --build-arg UPSTREAM_PACKAGES_ACTOR=<user>
#   --secret id=packages_read_token,...        (a read:packages credential)
# MAVEN_SETTINGS defaults to settings.xml, so the GitLab route and the local
# compose lane (hugmesh-generator tests/stack) build exactly as before.
# -----------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk AS build
WORKDIR /work

# GitLab registry coordinates the settings.xml interpolates ($CI_API_V4_URL is the
# instance API base; GITLAB_GROUP_ID selects the org group whose package registry
# holds hugmesh-parent/hugmesh-commons).
ARG CI_API_V4_URL
ARG GITLAB_GROUP_ID
ENV CI_API_V4_URL=${CI_API_V4_URL} \
    GITLAB_GROUP_ID=${GITLAB_GROUP_ID}

# Which Maven settings file the build uses, and the (non-secret) user name that goes
# with the GitHub Packages read credential. The credential itself is a BuildKit secret.
ARG MAVEN_SETTINGS=settings.xml
ARG UPSTREAM_PACKAGES_ACTOR
ENV UPSTREAM_PACKAGES_ACTOR=${UPSTREAM_PACKAGES_ACTOR}

COPY . .

# Resolve + build. CI_JOB_TOKEN is read from a BuildKit secret file and exported only
# for the lifetime of this RUN (so it is never persisted). `-s settings.xml` points
# Maven at the gitlab-maven registry for the private hugmesh-commons artifact.
RUN --mount=type=secret,id=ci_job_token \
    --mount=type=secret,id=packages_read_token \
    sh -euc '\
      if [ -f /run/secrets/ci_job_token ]; then \
        export CI_JOB_TOKEN="$(cat /run/secrets/ci_job_token)"; \
      fi; \
      if [ -f /run/secrets/packages_read_token ]; then \
        export UPSTREAM_PACKAGES_TOKEN="$(cat /run/secrets/packages_read_token)"; \
      fi; \
      ./mvnw -B -s "${MAVEN_SETTINGS}" package -DskipTests'

FROM eclipse-temurin:25-jre
# curl is required by this image's docker-compose HEALTHCHECK (actuator/health/readiness);
# eclipse-temurin's jre base does not ship it, which silently breaks every
# `depends_on: condition: service_healthy` gate on a fresh compose boot.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /work/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
