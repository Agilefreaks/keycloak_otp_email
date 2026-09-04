package com.agilefreaks.keycloak.otp;

/** Keys into the single-use store. Addresses are hashed so the cache holds no readable PII. */
public final class OtpKeys {

  private static final String PREFIX = "keycloak-otp-email:";

  private OtpKeys() {
    throw new UnsupportedOperationException("OtpKeys is a utility class");
  }

  public static String code(String userId) {
    return PREFIX + "code:" + userId;
  }

  public static String emailDay(String realmId, String email) {
    return PREFIX + "email-day:" + OtpCodes.hash(realmId, normalize(email));
  }

  public static String ipHour(String realmId, String ip) {
    return PREFIX + "ip-hour:" + realmId + ":" + ip;
  }

  public static String realmHour(String realmId) {
    return PREFIX + "realm-hour:" + realmId;
  }

  private static String normalize(String email) {
    return email == null ? "" : email.trim().toLowerCase();
  }
}
