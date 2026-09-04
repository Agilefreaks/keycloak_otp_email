package com.agilefreaks.keycloak.otp;

import java.util.Map;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * Typed view of the execution config. Every limit is "0 disables this guard", so an operator can
 * relax one control without touching the others.
 */
public record OtpConfig(
    int codeLength,
    int codeTtlSeconds,
    int resendCooldownSeconds,
    int maxAttempts,
    int maxSendsPerEmailPerDay,
    int maxSendsPerIpPerHour,
    int maxSendsPerRealmPerHour,
    String startTokenHeader,
    String startTokenVerifyUrl,
    String emailTemplate,
    String emailSubjectKey) {

  public static final String CONFIG_CODE_LENGTH = "codeLength";
  public static final String CONFIG_CODE_TTL_SECONDS = "codeTtlSeconds";
  public static final String CONFIG_RESEND_COOLDOWN_SECONDS = "resendCooldownSeconds";
  public static final String CONFIG_MAX_ATTEMPTS = "maxAttempts";
  public static final String CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY = "maxSendsPerEmailPerDay";
  public static final String CONFIG_MAX_SENDS_PER_IP_PER_HOUR = "maxSendsPerIpPerHour";
  public static final String CONFIG_MAX_SENDS_PER_REALM_PER_HOUR = "maxSendsPerRealmPerHour";
  public static final String CONFIG_START_TOKEN_HEADER = "startTokenHeader";
  public static final String CONFIG_START_TOKEN_VERIFY_URL = "startTokenVerifyUrl";
  public static final String CONFIG_EMAIL_TEMPLATE = "emailTemplate";
  public static final String CONFIG_EMAIL_SUBJECT_KEY = "emailSubjectKey";

  public static final int DEFAULT_CODE_LENGTH = 6;
  public static final int DEFAULT_CODE_TTL_SECONDS = 300;
  public static final int DEFAULT_RESEND_COOLDOWN_SECONDS = 60;
  public static final int DEFAULT_MAX_ATTEMPTS = 5;
  public static final int DEFAULT_MAX_SENDS_PER_EMAIL_PER_DAY = 5;
  public static final int DEFAULT_MAX_SENDS_PER_IP_PER_HOUR = 10;
  public static final int DEFAULT_MAX_SENDS_PER_REALM_PER_HOUR = 500;

  public static OtpConfig from(AuthenticatorConfigModel model) {
    Map<String, String> config =
        (model == null || model.getConfig() == null) ? Map.of() : model.getConfig();
    return new OtpConfig(
        positive(config, CONFIG_CODE_LENGTH, DEFAULT_CODE_LENGTH),
        positive(config, CONFIG_CODE_TTL_SECONDS, DEFAULT_CODE_TTL_SECONDS),
        atLeastZero(config, CONFIG_RESEND_COOLDOWN_SECONDS, DEFAULT_RESEND_COOLDOWN_SECONDS),
        atLeastZero(config, CONFIG_MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS),
        atLeastZero(
            config, CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY, DEFAULT_MAX_SENDS_PER_EMAIL_PER_DAY),
        atLeastZero(config, CONFIG_MAX_SENDS_PER_IP_PER_HOUR, DEFAULT_MAX_SENDS_PER_IP_PER_HOUR),
        atLeastZero(
            config, CONFIG_MAX_SENDS_PER_REALM_PER_HOUR, DEFAULT_MAX_SENDS_PER_REALM_PER_HOUR),
        text(config, CONFIG_START_TOKEN_HEADER),
        text(config, CONFIG_START_TOKEN_VERIFY_URL),
        textOr(config, CONFIG_EMAIL_TEMPLATE, EmailOtpAuthenticator.DEFAULT_EMAIL_TEMPLATE),
        textOr(config, CONFIG_EMAIL_SUBJECT_KEY, EmailOtpAuthenticator.DEFAULT_EMAIL_SUBJECT_KEY));
  }

  private static String textOr(Map<String, String> config, String key, String fallback) {
    String value = text(config, key);
    return value.isEmpty() ? fallback : value;
  }

  private static String text(Map<String, String> config, String key) {
    String value = config.get(key);
    return (value == null || value.isBlank()) ? "" : value.trim();
  }

  /** A value that must be usable: a missing, unparseable or non-positive entry falls back. */
  private static int positive(Map<String, String> config, String key, int fallback) {
    int parsed = atLeastZero(config, key, fallback);
    return parsed > 0 ? parsed : fallback;
  }

  /** A limit where {@code 0} legitimately means "guard disabled". */
  private static int atLeastZero(Map<String, String> config, String key, int fallback) {
    String value = text(config, key);
    if (value.isEmpty()) {
      return fallback;
    }
    try {
      int parsed = Integer.parseInt(value);
      return parsed >= 0 ? parsed : fallback;
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
