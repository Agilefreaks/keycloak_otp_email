package com.agilefreaks.keycloak.otp;

import java.util.Map;
import java.util.Optional;
import org.keycloak.models.KeycloakSession;

/**
 * {@link OtpStore} backed by Keycloak's single-use object store — the same cache action tokens use.
 * Entries expire on their own, so nothing has to be swept and nothing is left on the user record.
 */
public class SingleUseObjectOtpStore implements OtpStore {

  private final KeycloakSession session;

  public SingleUseObjectOtpStore(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Optional<Map<String, String>> get(String key) {
    return Optional.ofNullable(session.singleUseObjects().get(key));
  }

  @Override
  public void put(String key, Map<String, String> notes, long ttlSeconds) {
    // put() refuses to overwrite an existing key, so an update is a remove followed by a put; that
    // also makes the lifespan explicit on every write instead of inheriting the original one.
    session.singleUseObjects().remove(key);
    session.singleUseObjects().put(key, ttlSeconds, notes);
  }

  @Override
  public void remove(String key) {
    session.singleUseObjects().remove(key);
  }
}
