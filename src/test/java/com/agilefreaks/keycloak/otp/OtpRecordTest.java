package com.agilefreaks.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class OtpRecordTest {

  @Test
  void roundTripsThroughNotes() {
    OtpRecord original = new OtpRecord("the-hash", "the-salt", 2, 1_700_000_000L);

    Optional<OtpRecord> restored = OtpRecord.fromNotes(original.toNotes());

    assertEquals(Optional.of(original), restored);
  }

  @Test
  void notesAreAllStrings() {
    Map<String, String> notes = new OtpRecord("h", "s", 0, 1L).toNotes();

    assertTrue(notes.values().stream().allMatch(v -> v != null && !v.isBlank()));
  }

  @Test
  void readsAsAbsentWhenNotesAreMissingOrCorrupt() {
    assertEquals(Optional.empty(), OtpRecord.fromNotes(null));
    assertEquals(Optional.empty(), OtpRecord.fromNotes(Map.of()));
    assertEquals(Optional.empty(), OtpRecord.fromNotes(Map.of("hash", "h")));
    assertEquals(
        Optional.empty(),
        OtpRecord.fromNotes(Map.of("hash", "h", "salt", "s", "attempts", "x", "sentAt", "1")));
  }

  @Test
  void withAttemptBumpsOnlyTheCounter() {
    OtpRecord record = new OtpRecord("h", "s", 2, 1_700_000_000L);

    OtpRecord bumped = record.withAttempt();

    assertEquals(3, bumped.attempts());
    assertEquals(record.hash(), bumped.hash());
    assertEquals(record.salt(), bumped.salt());
    assertEquals(record.sentAtEpochSeconds(), bumped.sentAtEpochSeconds());
  }
}
