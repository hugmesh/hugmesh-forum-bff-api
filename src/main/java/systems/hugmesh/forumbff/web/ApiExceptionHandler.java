package systems.hugmesh.forumbff.web;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;
import systems.hugmesh.commons.web.ApiException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Global exception handler for the forum BFF. Renders {@link ApiException} as the
 * {@code {"error": message}} JSON body (with the carried HTTP status) that the UIs
 * read, and maps Jakarta Bean Validation failures to clean {@code 400} responses in
 * the same shape (with an additional {@code fields} map of per-field error messages).
 *
 * <p>Works unchanged under WebFlux: {@code @RestControllerAdvice} +
 * {@code @ExceptionHandler} returning a {@code ResponseEntity} is handled reactively
 * — a controller's {@code Mono.error(new ApiException(...))} routes here.
 *
 * <h2>Response shape</h2>
 *
 * <pre>
 *  Exception type               │ HTTP status │ JSON body
 *  ─────────────────────────────┼─────────────┼──────────────────────────────────────────────
 *  ApiException                 │ carried     │ {"error": "message"}
 *  WebExchangeBindException     │ 400         │ {"error": "validation failed",
 *                               │             │  "fields": {"fieldName": "constraint message"}}
 *  ConstraintViolationException │ 400         │ {"error": "validation failed",
 *                               │             │  "fields": {"paramName": "constraint message"}}
 *  ServerWebInputException      │ 400         │ {"error": "validation failed",
 *                               │             │  "detail": "reason or 'malformed request'"}
 * </pre>
 *
 * @see ApiException
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /**
     * Maps a domain {@link ApiException} to a JSON error response carrying the status
     * and message the exception was constructed with.
     *
     * @param ex the thrown {@link ApiException}
     * @return a {@link ResponseEntity} with the exception's HTTP status and a
     *         {@code {"error": "message"}} body
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.getMessage()));
    }

    /**
     * Maps a {@code @Valid @RequestBody} DTO field-validation failure to a 400 response
     * with a {@code fields} map of per-field error messages.
     *
     * @param ex the {@link WebExchangeBindException} carrying the field errors
     * @return a 400 {@link ResponseEntity} with {@code {"error": "validation failed",
     *         "fields": {...}}}
     */
    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBodyValidation(WebExchangeBindException ex) {
        var fields = new TreeMap<String, String>();
        for (FieldError fe : ex.getFieldErrors()) {
            fields.putIfAbsent(fe.getField(), fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage());
        }
        return badRequest(fields);
    }

    /**
     * Maps a {@code @Validated} controller {@code @PathVariable} or
     * {@code @RequestParam} constraint violation to a 400 response with per-param
     * error messages.
     *
     * @param ex the {@link ConstraintViolationException} carrying the violations
     * @return a 400 {@link ResponseEntity} with {@code {"error": "validation failed",
     *         "fields": {...}}}
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleParamValidation(ConstraintViolationException ex) {
        Map<String, String> fields = new TreeMap<>();
        for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
            fields.putIfAbsent(lastNode(v), v.getMessage());
        }
        return badRequest(fields);
    }

    /**
     * Maps a malformed or missing request body / unparseable parameter to a 400 response.
     * Covers wrong {@code Content-Type}, a completely absent required body, and similar
     * input problems that the framework raises before reaching bean validation.
     * {@link WebExchangeBindException} subclasses this, so the more-specific handler above
     * wins for DTO field-level validation.
     *
     * @param ex the {@link ServerWebInputException} raised by Spring WebFlux
     * @return a 400 {@link ResponseEntity} with {@code {"error": "validation failed",
     *         "detail": "reason or 'malformed request'"}}
     */
    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<Map<String, Object>> handleInput(ServerWebInputException ex) {
        var body = new LinkedHashMap<String, Object>();
        body.put("error", "validation failed");
        body.put("detail", ex.getReason() == null ? "malformed request" : ex.getReason());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * Builds a standard 400 bad-request response body in the {@code {"error",
     * "fields"}} shape.
     *
     * @param fields a map of field/parameter name to constraint-violation message
     * @return a 400 {@link ResponseEntity} with the shared error body shape
     */
    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        var body = new LinkedHashMap<String, Object>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * Extracts the leaf property name from a constraint-violation path (the part after
     * the last dot), which equals the parameter or field name surfaced to the client.
     *
     * @param v the {@link ConstraintViolation} whose path to extract from
     * @return the leaf node of the property path (e.g. {@code "title"} from
     *         {@code "createTopic.title"})
     */
    private static String lastNode(ConstraintViolation<?> v) {
        String path = v.getPropertyPath().toString();
        int dot = path.lastIndexOf('.');
        return dot >= 0 ? path.substring(dot + 1) : path;
    }
}
