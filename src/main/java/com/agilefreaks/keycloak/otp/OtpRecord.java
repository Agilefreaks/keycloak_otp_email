package com.agilefreaks.keycloak.otp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** A pending code, as the opaque string map the single-use object store holds. */
public record OtpRecord(String hash, String salt, int attempts, long sentAtEpochSeconds) {

  static final String NOTE_HASH = "hash";
  static final String NOTE_SALT = "salt";
  static final String NOTE_ATTEMPTS = "attempts";
  static final String NOTE_SENT_AT = "sentAt";

  public Map<String, String> toNotes() {
    Map<String, String> notes = new LinkedHashMap<>();
    notes.put(NOTE_HASH, hash);
    notes.put(NOTE_SALT, salt);
    notes.put(NOTE_ATTEMPTS, String.valueOf(attempts));
    notes.put(NOTE_SENT_AT, String.valueOf(sentAtEpochSeconds));
    return notes;
  }

  /** Empty when the notes are absent or malformed — a corrupt record must read as "no code". */
  public static Optional<OtpRecord> fromNotes(Map<String, String> notes) {
    if (notes == null) {
      return Optional.empty();
    }
    String hash = notes.get(NOTE_HASH);
    String salt = notes.get(NOTE_SALT);
    if (hash == null || salt == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(
          new OtpRecord(
              hash,
              salt,
              Integer.parseInt(notes.get(NOTE_ATTEMPTS)),
              Long.parseLong(notes.get(NOTE_SENT_AT))));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  public OtpRecord withAttempt() {
    return new OtpRecord(hash, salt, attempts + 1, sentAtEpochSeconds);
  }

  /** {@code maxAttempts} of 0 means no cap. */
  public boolean exhausted(int maxAttempts) {
    return maxAttempts > 0 && attempts >= maxAttempts;
  }
}
