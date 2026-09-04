package com.agilefreaks.keycloak.otp;

import java.util.Map;
import java.util.Optional;
import org.keycloak.models.KeycloakSession;

/** {@link OtpStore} backed by Keycloak's single-use object store. Entries expire on their own. */
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
    // No remove first, deliberately: Infinispan defers put() to the transaction commit but
    // applies remove() immediately, so removing would make the key read as absent to concurrent
    // requests for the rest of this one. The deferred put overwrites on commit.
    //
    // Imposes one rule: never put the same key twice in a request — the transaction rejects a
    // second task for a key it already holds.
    session.singleUseObjects().put(key, ttlSeconds, notes);
  }

  @Override
  public void remove(String key) {
    session.singleUseObjects().remove(key);
  }
}
