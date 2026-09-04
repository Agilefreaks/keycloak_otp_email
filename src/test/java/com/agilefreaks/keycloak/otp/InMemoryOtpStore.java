package com.agilefreaks.keycloak.otp;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Test double for the single-use store, with a manually advanced clock for expiry. */
class InMemoryOtpStore implements OtpStore {

  private record Entry(Map<String, String> notes, long expiresAtEpochSeconds) {}

  private final Map<String, Entry> entries = new HashMap<>();
  private long nowEpochSeconds;

  InMemoryOtpStore(long nowEpochSeconds) {
    this.nowEpochSeconds = nowEpochSeconds;
  }

  void setNow(long nowEpochSeconds) {
    this.nowEpochSeconds = nowEpochSeconds;
  }

  @Override
  public Optional<Map<String, String>> get(String key) {
    Entry entry = entries.get(key);
    if (entry == null) {
      return Optional.empty();
    }
    if (entry.expiresAtEpochSeconds() <= nowEpochSeconds) {
      entries.remove(key);
      return Optional.empty();
    }
    return Optional.of(new LinkedHashMap<>(entry.notes()));
  }

  @Override
  public void put(String key, Map<String, String> notes, long ttlSeconds) {
    entries.put(key, new Entry(new LinkedHashMap<>(notes), nowEpochSeconds + ttlSeconds));
  }

  @Override
  public void remove(String key) {
    entries.remove(key);
  }

  int size() {
    return entries.size();
  }
}
