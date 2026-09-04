package com.agilefreaks.keycloak.otp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A fixed-window counter. The window start is stored rather than inferred from the cache's TTL, so
 * the guard behaves the same whether or not the backing store resets a lifespan on write.
 */
public record CounterRecord(int count, long windowStartEpochSeconds) {

  static final String NOTE_COUNT = "count";
  static final String NOTE_WINDOW_START = "windowStart";

  public Map<String, String> toNotes() {
    Map<String, String> notes = new LinkedHashMap<>();
    notes.put(NOTE_COUNT, String.valueOf(count));
    notes.put(NOTE_WINDOW_START, String.valueOf(windowStartEpochSeconds));
    return notes;
  }

  public static Optional<CounterRecord> fromNotes(Map<String, String> notes) {
    if (notes == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(
          new CounterRecord(
              Integer.parseInt(notes.get(NOTE_COUNT)),
              Long.parseLong(notes.get(NOTE_WINDOW_START))));
    } catch (NumberFormatException | NullPointerException e) {
      return Optional.empty();
    }
  }

  public boolean isExpired(long nowEpochSeconds, long windowSeconds) {
    return nowEpochSeconds - windowStartEpochSeconds >= windowSeconds;
  }

  public CounterRecord increment() {
    return new CounterRecord(count + 1, windowStartEpochSeconds);
  }
}
