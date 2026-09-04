package com.agilefreaks.keycloak.otp;

import java.util.Map;
import org.keycloak.models.AuthenticatorConfigModel;

/** Typed view of the execution config. Every limit takes 0 to disable that guard alone. */
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
  public static final String DEFAULT_EMAIL_TEMPLATE = "code-email.ftl";
  public static final String DEFAULT_EMAIL_SUBJECT_KEY = "emailCodeSubject";

  public static OtpConfig from(AuthenticatorConfigModel model) {
    Map<String, String> config =
        (model == null || model.getConfig() == null) ? Map.of() : model.getConfig();
    return new OtpConfig(
        number(config, CONFIG_CODE_LENGTH, 1, DEFAULT_CODE_LENGTH),
        number(config, CONFIG_CODE_TTL_SECONDS, 1, DEFAULT_CODE_TTL_SECONDS),
        number(config, CONFIG_RESEND_COOLDOWN_SECONDS, 0, DEFAULT_RESEND_COOLDOWN_SECONDS),
        number(config, CONFIG_MAX_ATTEMPTS, 0, DEFAULT_MAX_ATTEMPTS),
        number(config, CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY, 0, DEFAULT_MAX_SENDS_PER_EMAIL_PER_DAY),
        number(config, CONFIG_MAX_SENDS_PER_IP_PER_HOUR, 0, DEFAULT_MAX_SENDS_PER_IP_PER_HOUR),
        number(
            config, CONFIG_MAX_SENDS_PER_REALM_PER_HOUR, 0, DEFAULT_MAX_SENDS_PER_REALM_PER_HOUR),
        text(config, CONFIG_START_TOKEN_HEADER, ""),
        text(config, CONFIG_START_TOKEN_VERIFY_URL, ""),
        text(config, CONFIG_EMAIL_TEMPLATE, DEFAULT_EMAIL_TEMPLATE),
        text(config, CONFIG_EMAIL_SUBJECT_KEY, DEFAULT_EMAIL_SUBJECT_KEY));
  }

  private static String text(Map<String, String> config, String key, String fallback) {
    String value = config.get(key);
    return (value == null || value.isBlank()) ? fallback : value.trim();
  }

  private static int number(Map<String, String> config, String key, int min, int fallback) {
    try {
      int value = Integer.parseInt(text(config, key, ""));
      return value >= min ? value : fallback;
    } catch (NumberFormatException e) {
      return fallback;
    }
  }
}
