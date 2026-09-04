package com.agilefreaks.keycloak.otp;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * OAuth-shaped JSON error bodies. Built by hand because Keycloak's own
 * {@code errorResponse(status, error, description)} cannot carry {@code otp_ttl} or
 * {@code retry_after}.
 */
public final class JsonResponses {

  public static final String ERROR_OTP_REQUIRED = "otp_required";
  public static final String ERROR_OTP_THROTTLED = "otp_throttled";
  public static final String ERROR_INVALID_REQUEST = "invalid_request";
  public static final String ERROR_INVALID_GRANT = "invalid_grant";
  public static final String ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

  private JsonResponses() {}

  public static Response otpRequired(String email, int ttlSeconds) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", ERROR_OTP_REQUIRED);
    body.put("error_description", "code sent to " + email);
    body.put("otp_ttl", ttlSeconds);
    return json(Response.Status.BAD_REQUEST.getStatusCode(), body);
  }

  public static Response throttled(long retryAfterSeconds) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", ERROR_OTP_THROTTLED);
    body.put("error_description", "too many code requests; try again later");
    body.put("retry_after", retryAfterSeconds);
    return json(429, body);
  }

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
