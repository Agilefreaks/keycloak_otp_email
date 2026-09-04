package com.agilefreaks.keycloak.otp;

import java.util.Map;
import java.util.Optional;

/**
 * The small slice of Keycloak's single-use object store this provider needs, narrowed to an
 * interface so the authenticators can be unit tested against an in-memory fake instead of Infinispan.
 */
public interface OtpStore {

  Optional<Map<String, String>> get(String key);

  /** Stores {@code notes} under {@code key}, replacing anything already there. */
  void put(String key, Map<String, String> notes, long ttlSeconds);

  void remove(String key);
}
