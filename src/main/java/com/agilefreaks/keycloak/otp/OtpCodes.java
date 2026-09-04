package com.agilefreaks.keycloak.otp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.keycloak.common.util.SecretGenerator;

/** Generation, salted hashing and constant-time comparison of the emailed one-time code. */
public final class OtpCodes {

  private static final int SALT_BYTES = 16;

  private OtpCodes() {
    throw new UnsupportedOperationException("OtpCodes is a utility class");
  }

  /** A code of {@code length} decimal digits, drawn from Keycloak's secure generator. */
  public static String generate(int length) {
    return SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
  }

  /** A fresh per-code salt, so two users holding the same code do not share a hash. */
  public static String newSalt() {
    return SecretGenerator.getInstance().randomBytesHex(SALT_BYTES);
  }

  /** SHA-256 over {@code salt:code}, hex encoded. The plaintext code is never stored. */
  public static String hash(String salt, String code) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update((salt + ":" + code).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required but unavailable", e);
    }
  }

  /** Constant-time comparison of {@code candidate} against a stored hash. */
  public static boolean matches(String salt, String expectedHash, String candidate) {
    if (expectedHash == null || candidate == null || candidate.isEmpty()) {
      return false;
    }
    return MessageDigest.isEqual(
        expectedHash.getBytes(StandardCharsets.UTF_8),
        hash(salt, candidate).getBytes(StandardCharsets.UTF_8));
  }
}
