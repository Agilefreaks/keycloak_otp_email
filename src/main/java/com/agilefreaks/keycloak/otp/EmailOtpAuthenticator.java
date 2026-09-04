package com.agilefreaks.keycloak.otp;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.util.JsonSerialization;

/**
 * Emails a one-time code and verifies it, in a browser flow and in a direct grant flow.
 *
 * <p>Direct grant is recognised by {@code getFlowPath() == "token"}; anything else is treated as a
 * form flow, so an unexpected value renders a page rather than leaking one into a token response.
 * The code lives in the single-use object store rather than an auth-session note because direct
 * grant destroys its authentication session between the two calls.
 */
public class EmailOtpAuthenticator implements Authenticator, AuthenticatorFactory {

  public static final String ID = "email-otp";

  static final String FLOW_PATH_TOKEN = "token";

  static final String CODE_FORM_TEMPLATE = "email-code-form.ftl";

  static final String FIELD_CODE = "emailCode";
  static final String FIELD_RESEND = "resend";
  static final String PARAM_OTP = "otp";

  static final String ATTR_CODE_LENGTH = "codeLength";
  static final String ATTR_MAX_ATTEMPTS_REACHED = "maxAttemptsReached";

  static final String MSG_INVALID = "emailCodeInvalid";
  static final String MSG_EXPIRED = "emailCodeExpired";
  static final String MSG_TOO_MANY_ATTEMPTS = "emailCodeTooManyAttempts";
  static final String MSG_RESEND_COOLDOWN = "emailCodeResendCooldown";
  static final String MSG_SEND_FAILED = "emailCodeSendFailed";

  private static final Logger LOG = Logger.getLogger(EmailOtpAuthenticator.class);
  private static final HttpClient HTTP =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();

  private final Function<KeycloakSession, OtpStore> storeFactory;
  private final Clock clock;

  public EmailOtpAuthenticator() {
    this(SingleUseObjectOtpStore::new, Clock.systemUTC());
  }

  EmailOtpAuthenticator(Function<KeycloakSession, OtpStore> storeFactory, Clock clock) {
    this.storeFactory = storeFactory;
    this.clock = clock;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    Step step = open(context);
    if (step == null) {
      return;
    }
    String otp = step.directGrant() ? step.form().getFirst(PARAM_OTP) : null;
    if (isBlank(otp)) {
      sendCode(step);
    } else {
      verifyCode(step, otp.trim());
    }
  }

  /** Only reached from a form flow — direct grant never posts back. */
  @Override
  public void action(AuthenticationFlowContext context) {
    Step step = open(context);
    if (step == null) {
      return;
    }
    if (step.form().containsKey(FIELD_RESEND)) {
      sendCode(step);
      return;
    }
    String code = step.form().getFirst(FIELD_CODE);
    if (isBlank(code)) {
      challenge(step, new FormMessage(FIELD_CODE, MSG_INVALID));
    } else {
      verifyCode(step, code.trim());
    }
  }

  private record Step(
      AuthenticationFlowContext context,
      UserModel user,
      OtpConfig config,
      OtpStore store,
      MultivaluedMap<String, String> form,
      boolean directGrant) {

    String key() {
      return OtpKeys.code(user.getId());
    }
  }

  /** Null when the flow carries no user with an email address; the failure is already reported. */
  private Step open(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    boolean directGrant = FLOW_PATH_TOKEN.equals(context.getFlowPath());
    if (user == null || isBlank(user.getEmail())) {
      LOG.warnf(
          "No email address for the user on this flow; cannot send a code (user=%s)",
          user == null ? "none" : user.getId());
      // A JSON body here would land on a web page in a form flow.
      if (directGrant) {
        context.failure(
            AuthenticationFlowError.INVALID_USER,
            JsonResponses.error(
                400, JsonResponses.ERROR_INVALID_REQUEST, "Missing parameter: username"));
      } else {
        context.failure(AuthenticationFlowError.INVALID_USER);
      }
      return null;
    }
    return new Step(
        context,
        user,
        OtpConfig.from(context.getAuthenticatorConfig()),
        storeFactory.apply(context.getSession()),
        context.getHttpRequest().getDecodedFormParameters(),
        directGrant);
  }

  /**
   * Every outcome here goes out as a challenge, never a failure: {@code DefaultAuthenticationFlow}
   * calls {@code AuthenticationProcessor.logFailure()} for both {@code FAILED} and {@code
   * FAILURE_CHALLENGE}, which feeds the brute-force protector, and a cooldown, a send failure or a
   * request for a code is not a wrong credential. Reporting them as one locks users out.
   */
  private void sendCode(Step step) {
    OtpConfig config = step.config();
    if (!attestationAccepted(step)) {
      LOG.warnf(
          "Rejected a code request without a valid attestation token for '%s'",
          step.user().getId());
      if (step.directGrant()) {
        step.context()
            .forceChallenge(
                JsonResponses.error(
                    400, JsonResponses.ERROR_INVALID_REQUEST, "Missing or invalid app attestation"));
      } else {
        challenge(step, new FormMessage(FIELD_CODE, MSG_SEND_FAILED));
      }
      return;
    }

    long now = clock.instant().getEpochSecond();
    OtpRecord pending = step.store().get(step.key()).flatMap(OtpRecord::fromNotes).orElse(null);
    if (pending != null && config.resendCooldownSeconds() > 0) {
      long remaining = config.resendCooldownSeconds() - (now - pending.sentAtEpochSeconds());
      if (remaining > 0) {
        refuseThrottled(step, remaining);
        return;
      }
    }

    RealmModel realm = step.context().getRealm();
    OtpRateGate.Decision decision =
        new OtpRateGate(step.store(), clock, config)
            .reserve(realm.getId(), step.user().getEmail(), remoteAddress(step.context()));
    if (decision.outcome() == OtpRateGate.Outcome.BUDGET_EXHAUSTED) {
      LOG.warnf(
          "Realm '%s' has spent its hourly OTP budget; refusing to send more codes",
          realm.getName());
      refuseUnavailable(step, "code sending is temporarily unavailable");
      return;
    }
    if (!decision.allowed()) {
      refuseThrottled(step, decision.retryAfterSeconds());
      return;
    }

    String code = OtpCodes.generate(config.codeLength());
    String salt = OtpCodes.newSalt();

    // Mail first, store second: a failed send must not replace a code the user already holds, and
    // it cannot be undone afterwards (see SingleUseObjectOtpStore#put).
    try {
      mail(step, code);
    } catch (EmailException | RuntimeException e) {
      LOG.warnf(e, "Could not mail a code to '%s'", step.user().getEmail());
      refuseUnavailable(step, "could not send the code");
      return;
    }
    step.store()
        .put(
            step.key(),
            new OtpRecord(OtpCodes.hash(salt, code), salt, 0, now).toNotes(),
            config.codeTtlSeconds());

    if (step.directGrant()) {
      step.context()
          .forceChallenge(
              JsonResponses.otpRequired(step.user().getEmail(), config.codeTtlSeconds()));
    } else {
      challenge(step, null);
    }
  }

  private void refuseThrottled(Step step, long retryAfterSeconds) {
    if (step.directGrant()) {
      step.context().forceChallenge(JsonResponses.throttled(retryAfterSeconds));
    } else {
      challenge(step, new FormMessage(FIELD_CODE, MSG_RESEND_COOLDOWN, retryAfterSeconds));
    }
  }

  private void refuseUnavailable(Step step, String description) {
    if (step.directGrant()) {
      step.context().forceChallenge(JsonResponses.temporarilyUnavailable(description));
    } else {
      challenge(step, new FormMessage(FIELD_CODE, MSG_SEND_FAILED));
    }
  }

  private void mail(Step step, String code) throws EmailException {
    // Must stay mutable: EmailTemplateProvider adds its own entries to the map.
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("code", code);
    attributes.put("ttl", step.config().codeTtlSeconds());
    attributes.put("username", step.user().getEmail());
    attributes.put("realmName", step.context().getRealm().getName());

    step.context()
        .getSession()
        .getProvider(EmailTemplateProvider.class)
        .setRealm(step.context().getRealm())
        .setUser(step.user())
        .send(
            step.config().emailSubjectKey(), List.of(), step.config().emailTemplate(), attributes);
  }

  private enum Rejection {
    NO_CODE(AuthenticationFlowError.EXPIRED_CODE, "Code expired or not requested", MSG_EXPIRED),
    TOO_MANY_ATTEMPTS(
        AuthenticationFlowError.INVALID_CREDENTIALS, "Too many attempts", MSG_TOO_MANY_ATTEMPTS),
    INVALID(AuthenticationFlowError.INVALID_CREDENTIALS, "Invalid code", MSG_INVALID);

    final AuthenticationFlowError error;
    final String description;
    final String messageKey;

    Rejection(AuthenticationFlowError error, String description, String messageKey) {
      this.error = error;
      this.description = description;
      this.messageKey = messageKey;
    }
  }

  /** A wrong code is a credential failure and is reported as one; see {@link #sendCode}. */
  private void verifyCode(Step step, String submitted) {
    Rejection rejection = checkCode(step, submitted);
    if (rejection == null) {
      step.context().success();
      return;
    }
    if (step.directGrant()) {
      step.context()
          .failure(
              rejection.error,
              JsonResponses.error(400, JsonResponses.ERROR_INVALID_GRANT, rejection.description));
      return;
    }
    Response form =
        codeForm(
            step,
            new FormMessage(FIELD_CODE, rejection.messageKey),
            rejection == Rejection.TOO_MANY_ATTEMPTS);
    if (rejection == Rejection.NO_CODE) {
      step.context().challenge(form);
    } else {
      step.context().failureChallenge(rejection.error, form);
    }
  }

  /** Null when the code matched. */
  private Rejection checkCode(Step step, String submitted) {
    OtpRecord record = step.store().get(step.key()).flatMap(OtpRecord::fromNotes).orElse(null);
    if (record == null) {
      return Rejection.NO_CODE;
    }
    int maxAttempts = step.config().maxAttempts();
    // Only reachable if maxAttempts was lowered while a code was already pending.
    if (record.exhausted(maxAttempts)) {
      step.store().remove(step.key());
      return Rejection.TOO_MANY_ATTEMPTS;
    }
    if (OtpCodes.matches(record.salt(), record.hash(), submitted)) {
      step.store().remove(step.key());
      return null;
    }

    OtpRecord bumped = record.withAttempt();
    if (bumped.exhausted(maxAttempts)) {
      step.store().remove(step.key());
      return Rejection.TOO_MANY_ATTEMPTS;
    }
    // Re-stored with what is left of the original lifetime, never a fresh one. No failedLogin()
    // call either: reporting the credential failure already feeds the protector, and counting it
    // twice halved the effective failureFactor.
    long elapsed = clock.instant().getEpochSecond() - record.sentAtEpochSeconds();
    step.store()
        .put(step.key(), bumped.toNotes(), Math.max(step.config().codeTtlSeconds() - elapsed, 1));
    return Rejection.INVALID;
  }

  private void challenge(Step step, FormMessage error) {
    step.context().challenge(codeForm(step, error, false));
  }

  private Response codeForm(Step step, FormMessage error, boolean maxAttemptsReached) {
    LoginFormsProvider form =
        step.context()
            .form()
            .setAttribute(ATTR_CODE_LENGTH, step.config().codeLength())
            .setAttribute(ATTR_MAX_ATTEMPTS_REACHED, maxAttemptsReached);
    if (error != null) {
      form.setErrors(List.of(error));
    }
    return form.createForm(CODE_FORM_TEMPLATE);
  }

  private static String remoteAddress(AuthenticationFlowContext context) {
    ClientConnection connection = context.getConnection();
    return connection == null ? null : connection.getRemoteAddr();
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  private boolean attestationAccepted(Step step) {
    String header = step.config().startTokenHeader();
    if (header.isEmpty()) {
      return true;
    }
    String token = step.context().getHttpRequest().getHttpHeaders().getHeaderString(header);
    if (isBlank(token)) {
      return false;
    }
    String verifyUrl = step.config().startTokenVerifyUrl();
    return verifyUrl.isEmpty() || verifyAttestationToken(verifyUrl, token);
  }

  /** Overridable in tests. */
  boolean verifyAttestationToken(String verifyUrl, String token) {
    HttpRequest request;
    try {
      request =
          HttpRequest.newBuilder(URI.create(verifyUrl))
              .timeout(Duration.ofSeconds(4))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(
                  HttpRequest.BodyPublishers.ofString(
                      "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)))
              .build();
    } catch (IllegalArgumentException e) {
      // A URL that cannot be parsed will never work: failing open would disable the check for
      // good, so this one fails closed.
      LOG.errorf(e, "Attestation verify URL '%s' is not usable; rejecting the send", verifyUrl);
      return false;
    }

    try {
      HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        LOG.warnf("Attestation verifier returned HTTP %d; rejecting", response.statusCode());
        return false;
      }
      return JsonSerialization.mapper.readTree(response.body()).path("success").asBoolean(false);
    } catch (Exception e) {
      LOG.warnf(e, "Attestation verification call failed; allowing the send");
      return true;
    }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public Authenticator create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public String getDisplayType() {
    return "Email OTP";
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[] {Requirement.REQUIRED};
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Emails a one-time code and verifies it. In a browser flow it renders the code form; "
        + "in a direct grant flow it answers 400 otp_required and then accepts an 'otp' form "
        + "parameter. Rate limited per email address, per client IP and per realm.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return List.of(
        property(
            OtpConfig.CONFIG_CODE_LENGTH,
            "Code length",
            "Number of digits in the emailed code.",
            OtpConfig.DEFAULT_CODE_LENGTH),
        property(
            OtpConfig.CONFIG_CODE_TTL_SECONDS,
            "Code TTL (seconds)",
            "How long a code stays valid. Direct grant returns it to the app as 'otp_ttl'.",
            OtpConfig.DEFAULT_CODE_TTL_SECONDS),
        property(
            OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS,
            "Resend cooldown (seconds)",
            "Minimum gap between two codes for one address. 0 disables the cooldown.",
            OtpConfig.DEFAULT_RESEND_COOLDOWN_SECONDS),
        property(
            OtpConfig.CONFIG_MAX_ATTEMPTS,
            "Max verification attempts",
            "Wrong guesses allowed before the code is burned. 0 disables the cap.",
            OtpConfig.DEFAULT_MAX_ATTEMPTS),
        property(
            OtpConfig.CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY,
            "Max sends per email per day",
            "Caps how much mail one address can be made to receive. 0 disables the cap.",
            OtpConfig.DEFAULT_MAX_SENDS_PER_EMAIL_PER_DAY),
        property(
            OtpConfig.CONFIG_MAX_SENDS_PER_IP_PER_HOUR,
            "Max sends per IP per hour",
            "Caps a single source. Requires proxy-headers to be configured, so the real client "
                + "IP is visible. Keep it generous: carriers and shared networks put many users "
                + "behind one address. 0 disables the cap.",
            OtpConfig.DEFAULT_MAX_SENDS_PER_IP_PER_HOUR),
        property(
            OtpConfig.CONFIG_MAX_SENDS_PER_REALM_PER_HOUR,
            "Max sends per realm per hour",
            "Circuit breaker for a distributed flood, where every per-IP and per-address counter "
                + "still looks innocent. Protects the mail provider quota and sending reputation. "
                + "0 disables the budget.",
            OtpConfig.DEFAULT_MAX_SENDS_PER_REALM_PER_HOUR),
        property(
            OtpConfig.CONFIG_EMAIL_TEMPLATE,
            "Email template",
            "Freemarker template in the realm's email theme.",
            OtpConfig.DEFAULT_EMAIL_TEMPLATE),
        property(
            OtpConfig.CONFIG_EMAIL_SUBJECT_KEY,
            "Email subject key",
            "Message key resolved against the email theme's message bundle.",
            OtpConfig.DEFAULT_EMAIL_SUBJECT_KEY),
        property(
            OtpConfig.CONFIG_START_TOKEN_HEADER,
            "App attestation header",
            "When set, a code is only sent if the request carries this header. Point it at an App "
                + "Attest / Play Integrity / reCAPTCHA Enterprise token. Empty = no check.",
            ""),
        property(
            OtpConfig.CONFIG_START_TOKEN_VERIFY_URL,
            "App attestation verify URL",
            "Endpoint the attestation token is POSTed to as 'token'; a JSON body with "
                + "\"success\": false rejects the send. Empty = presence of the header is enough.",
            ""));
  }

  private static ProviderConfigProperty property(
      String name, String label, String help, Object defaultValue) {
    return new ProviderConfigProperty(
        name, label, help, ProviderConfigProperty.STRING_TYPE, String.valueOf(defaultValue));
  }
}
