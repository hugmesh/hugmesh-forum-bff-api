package net.hugmesh.forumbff.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.forumbff.security.ForumStepUpGate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The step-up WIRE CONTRACT, asserted at the type that mints it and the advice that renders
 * it. See hugmesh-forum-bff-api#15.
 *
 * <p>The load-bearing property of this class is that the contract is a PLATFORM one, not a
 * per-repo one: hugmesh-admin-bff-api is the reference emitter, hugmesh-mod-bff-api copied it
 * (PR #18), and the UIs are written against the platform spelling. A divergent spelling here
 * would be worse than no change at all — the client would see a signal it does not recognise
 * and fall through to a bare error. So the cross-repo constants are pinned as LITERALS below
 * rather than by referring to the constant that defines them: a rename that changes the wire
 * has to change this test too, which is the point.
 */
class StepUpSignalContractTest {

    // ---- the cross-repo constants, as literals -------------------------------

    @Test
    void theSignalHeaderIsThePlatformSpelling() {
        // admin-bff StepUpRequiredException.SIGNAL_HEADER, mod-bff's copy, and the UIs'
        // STEP_UP_SIGNAL_HEADER are all exactly this.
        assertThat(StepUpRequiredException.SIGNAL_HEADER).isEqualTo("X-Step-Up-Required");
    }

    @Test
    void theLegacyPhraseIsThePlatformSpelling() {
        // The UIs' fallback leg is /requires step-up/i.
        assertThat(StepUpRequiredException.LEGACY_PHRASE).isEqualTo("requires step-up");
    }

    @Test
    void theFlavourIsForum_andFitsThePlatformShape() {
        assertThat(ForumStepUpGate.STEP_UP_HEADER).isEqualTo("X-Forum-StepUp");
        assertThat(ForumStepUpGate.STEP_UP_HEADER)
                .as("the platform's X-<flavour>-StepUp shape, which the UIs validate before "
                        + "acting on a signal")
                .matches("^X-[A-Za-z0-9-]{1,60}-StepUp$");
    }

    /**
     * The canonical message template, byte for byte. admin-bff and mod-bff emit
     * {@code "<verb> requires step-up re-authentication (present <flavour>)"}; one client
     * sentence has to cover every service.
     */
    @Test
    void theMessageIsTheCanonicalPlatformTemplate() {
        assertThat(ForumStepUpGate.Surface.ADMIN.denial().getMessage())
                .isEqualTo("forum administration requires step-up re-authentication "
                        + "(present X-Forum-StepUp)");
        assertThat(ForumStepUpGate.Surface.MODERATION.denial().getMessage())
                .isEqualTo("forum moderation requires step-up re-authentication "
                        + "(present X-Forum-StepUp)");
    }

    // ---- the minted refusal ---------------------------------------------------

    @Test
    void theRefusalIs403_carriesTheFlavour_andKeepsTheLegacyPhrase() {
        StepUpRequiredException ex = ForumStepUpGate.Surface.MODERATION.denial();

        assertThat(ex.status()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.retryHeader()).isEqualTo(ForumStepUpGate.STEP_UP_HEADER);
        assertThat(ex.getMessage()).contains(StepUpRequiredException.LEGACY_PHRASE);
        assertThat(ex.getMessage()).startsWith("forum moderation");
        assertThat(ex).isInstanceOf(ApiException.class);
    }

    /** 428 is the "conventional" step-up status, but nothing on this platform emits it: every
     *  client branches on 403 and a status move would be a breaking, non-rolling-deployable
     *  change. Pinned so a later "make it a 428" is a decision rather than a drift. */
    @Test
    void theStatusIsDeliberatelyNot428() {
        assertThat(ForumStepUpGate.Surface.ADMIN.denial().status())
                .isNotEqualTo(HttpStatus.PRECONDITION_REQUIRED);
    }

    /**
     * The flavour is written to a response header, so a value carrying CR/LF would be a
     * header-injection vector. It is structurally impossible: a bad value throws at
     * construction and can never reach the wire.
     */
    @Test
    void aFlavourThatIsNotAGateConstant_isRefusedAtConstruction() {
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(
                        "X-Forum-StepUp\r\nX-Injected: yes", "forum moderation"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader("Authorization", "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Every surface in the enum produces a message an old phrase-sniffing client still
     *  recognises — the constructor composes the phrase rather than trusting callers, so a
     *  future third surface cannot ship an unrecognisable refusal. */
    @Test
    void everyDeclaredSurface_producesAPhraseSniffableMessage() {
        for (ForumStepUpGate.Surface surface : ForumStepUpGate.Surface.values()) {
            assertThat(surface.denial().getMessage())
                    .as("%s", surface)
                    .containsIgnoringCase(StepUpRequiredException.LEGACY_PHRASE)
                    .contains(ForumStepUpGate.STEP_UP_HEADER);
        }
    }

    // ---- the rendered response ------------------------------------------------

    @Test
    void theAdviceStampsTheSignalOnAStepUpRefusal_andLeavesTheBodyShapeAlone() {
        ResponseEntity<Map<String, Object>> response =
                new ApiExceptionHandler().handle(ForumStepUpGate.Surface.ADMIN.denial());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo(ForumStepUpGate.STEP_UP_HEADER);
        assertThat(response.getBody()).containsOnlyKeys("error");
        assertThat(String.valueOf(response.getBody().get("error")))
                .contains(StepUpRequiredException.LEGACY_PHRASE);
    }

    /** An ORDINARY 403 must stay bare, or every routine refusal pops an MFA dialog. */
    @Test
    void theAdviceLeavesAnOrdinaryApiExceptionUnsignalled() {
        ResponseEntity<Map<String, Object>> response = new ApiExceptionHandler()
                .handle(ApiException.forbidden("not a moderator of this domain"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsHeader(StepUpRequiredException.SIGNAL_HEADER))
                .isFalse();
        assertThat(response.getBody()).isEqualTo(Map.of("error", "not a moderator of this domain"));
    }

    // ---- the emitted-once invariant -------------------------------------------

    /**
     * The old-client contract is a free-text phrase, so it can only be trusted if exactly ONE
     * main source EMITS it — otherwise a reword somewhere else silently ships a refusal the
     * phrase-sniffing leg cannot match. Comment-aware on purpose: prose that mentions the
     * phrase reaches no client, so the invariant is about emission, not about the literal's
     * absence.
     *
     * <p>Read with the JDK rather than {@code grep}: GNU grep fails OPEN on a NUL byte
     * (skips the file, exit 1, indistinguishable from a real miss), which would make this
     * guard silently vacuous over a tree it could not read.
     */
    @Test
    void theEmittedLegacyPhraseLivesInExactlyOneMainSource() throws IOException {
        Path mainJava = Path.of("src", "main", "java");
        assertThat(mainJava).as("main sources must be where this test expects them").exists();

        List<String> emitters = new ArrayList<>();
        try (Stream<Path> files = Files.walk(mainJava)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String source = Files.readString(file, StandardCharsets.UTF_8);
                if (emitsPhrase(stripComments(source))) {
                    emitters.add(mainJava.relativize(file).toString());
                }
            }
        }

        assertThat(emitters)
                .as("main sources that EMIT the legacy phrase as a string literal - exactly "
                        + "one may, or an old client's sniff can be reworded away by editing "
                        + "somewhere else")
                .containsExactly(Path.of("net", "hugmesh", "forumbff", "web",
                        "StepUpRequiredException.java").toString());
    }

    /** Does any STRING LITERAL in this (comment-stripped) source contain the phrase? */
    private static boolean emitsPhrase(String source) {
        Matcher literals = Pattern.compile("\"(\\\\.|[^\"\\\\])*\"").matcher(source);
        while (literals.find()) {
            if (literals.group().toLowerCase(Locale.ROOT)
                    .contains(StepUpRequiredException.LEGACY_PHRASE)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Remove {@code //} and block comments without disturbing string literals - a
     * character-scanner rather than a regex, because {@code "http://x"} inside a literal is
     * not a comment and a naive strip would corrupt the very literals this guard inspects.
     */
    private static String stripComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (c == '"' || c == '\'') {
                char quote = c;
                out.append(c);
                i++;
                while (i < n) {
                    char d = source.charAt(i);
                    out.append(d);
                    i++;
                    if (d == '\\' && i < n) {
                        out.append(source.charAt(i));
                        i++;
                    } else if (d == quote) {
                        break;
                    }
                }
            } else if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') {
                    i++;
                }
            } else if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(source.charAt(i) == '*' && source.charAt(i + 1) == '/')) {
                    i++;
                }
                i = Math.min(i + 2, n);
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }
}
