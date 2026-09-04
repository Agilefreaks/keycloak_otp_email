package com.agilefreaks.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OtpCodesTest {

  @Test
  void generatesRequestedNumberOfDigits() {
    String code = OtpCodes.generate(6);

    assertEquals(6, code.length());
    assertTrue(code.matches("\\d{6}"), "expected digits only, got " + code);
  }

  @Test
  void generatesDifferentCodes() {
    Set<String> codes = new HashSet<>();
    for (int i = 0; i < 50; i++) {
      codes.add(OtpCodes.generate(6));
    }

    // A generator stuck on one value would be a catastrophic, silent failure.
    assertTrue(codes.size() > 40, "expected varied codes, got " + codes.size() + " distinct");
  }

  @Test
  void saltsAreDistinct() {
    assertNotEquals(OtpCodes.newSalt(), OtpCodes.newSalt());
  }

  @Test
  void hashIsStableForSameSaltAndCode() {
    String salt = OtpCodes.newSalt();

    assertEquals(OtpCodes.hash(salt, "418322"), OtpCodes.hash(salt, "418322"));
  }

  @Test
  void hashDiffersPerSalt() {
    assertNotEquals(OtpCodes.hash("salt-a", "418322"), OtpCodes.hash("salt-b", "418322"));
  }

  @Test
  void neverLeaksThePlaintextCode() {
    assertFalse(OtpCodes.hash("salt", "418322").contains("418322"));
  }

  @Test
  void matchesTheOriginalCode() {
    String salt = OtpCodes.newSalt();
    String hash = OtpCodes.hash(salt, "418322");

    assertTrue(OtpCodes.matches(salt, hash, "418322"));
  }

  @Test
  void rejectsAWrongCode() {
    String salt = OtpCodes.newSalt();
    String hash = OtpCodes.hash(salt, "418322");

    assertFalse(OtpCodes.matches(salt, hash, "418323"));
  }

  @Test
  void rejectsNullAndBlankCandidatesWithoutThrowing() {
    String salt = OtpCodes.newSalt();
    String hash = OtpCodes.hash(salt, "418322");

    assertFalse(OtpCodes.matches(salt, hash, null));
    assertFalse(OtpCodes.matches(salt, hash, ""));
    assertFalse(OtpCodes.matches(salt, null, "418322"));
  }
}
