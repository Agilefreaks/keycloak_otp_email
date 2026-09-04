package com.agilefreaks.keycloak.otp;

import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/** Reads a response body back as a map, so tests assert on the JSON the app actually receives. */
final class TestJson {

  private TestJson() {}

  @SuppressWarnings("unchecked")
  static Map<String, Object> parse(Response response) {
    Object entity = response.getEntity();
    try {
      return JsonSerialization.readValue(String.valueOf(entity), Map.class);
    } catch (Exception e) {
      throw new AssertionError("response entity is not JSON: " + entity, e);
    }
  }
}
