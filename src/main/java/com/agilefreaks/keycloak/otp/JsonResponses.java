package com.agilefreaks.keycloak.otp;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * OAuth-shaped JSON error bodies.
 *
 * <p>Keycloak's own {@code errorResponse(status, error, description)} can only emit
 * {@code {error, error_description}}, and a client driving its own login screen needs two more
 * fields — {@code otp_ttl} to show a countdown, and {@code retry_after} to disable its resend
 * button — so these are built by hand.
 */
public final class JsonResponses {

  public static final String ERROR_OTP_REQUIRED = "otp_required";
  public static final String ERROR_OTP_THROTTLED = "otp_throttled";
  public static final String ERROR_INVALID_REQUEST = "invalid_request";
  public static final String ERROR_INVALID_GRANT = "invalid_grant";
  public static final String ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

  private JsonResponses() {
    throw new UnsupportedOperationException("JsonResponses is a utility class");
  }

  /** 400 with the code just mailed — the app's cue to show the code-entry screen. */
  public static Response otpRequired(String email, int ttlSeconds) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", ERROR_OTP_REQUIRED);
    body.put("error_description", "code sent to " + email);
    body.put("otp_ttl", ttlSeconds);
    return json(Response.Status.BAD_REQUEST.getStatusCode(), body);
  }

  /** 429 — a send was refused by a rate guard; no mail left the building. */
  public static Response throttled(long retryAfterSeconds) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", ERROR_OTP_THROTTLED);
    body.put("error_description", "too many code requests; try again later");
    body.put("retry_after", retryAfterSeconds);
    return json(429, body);
  }

  /** 503 — the realm's hourly budget is spent, or SMTP failed. */
  public static Response temporarilyUnavailable(String description) {
    return error(
        Response.Status.SERVICE_UNAVAILABLE.getStatusCode(),
        ERROR_TEMPORARILY_UNAVAILABLE,
        description);
  }

  public static Response error(int status, String error, String description) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", error);
    body.put("error_description", description);
    return json(status, body);
  }

  private static Response json(int status, Map<String, Object> body) {
    try {
      return Response.status(status)
          .type(MediaType.APPLICATION_JSON_TYPE)
          .entity(JsonSerialization.writeValueAsString(body))
          .build();
    } catch (IOException e) {
      throw new IllegalStateException("could not serialize the error body", e);
    }
  }
}
