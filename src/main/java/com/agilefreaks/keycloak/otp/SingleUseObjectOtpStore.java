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
    // Straight put, and deliberately no remove first. The Infinispan implementation defers put()
    // to the request's transaction commit but applies remove() immediately, so removing first
    // would make the key read as absent to every concurrent request for the rest of the request —
    // long enough for a blocking mail send — and the rate-limit counters would read zero. The
    // deferred put overwrites whatever is there when it lands.
    //
    // The one rule this imposes: never put the same key twice in a single request. The transaction
    // rejects a second task for a key it already holds.
    session.singleUseObjects().put(key, ttlSeconds, notes);
  }

  @Override
  public void remove(String key) {
    session.singleUseObjects().remove(key);
  }
}
