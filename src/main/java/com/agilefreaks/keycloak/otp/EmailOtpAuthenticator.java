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
import java.util.Optional;
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
 * Emails a one-time code and verifies it — for the browser flow and for direct grant, from one
 * implementation.
 *
 * <p>The two differ only in how a step talks to its caller: a browser gets an HTML challenge and
 * posts back to {@link #action}, while a token request gets JSON and repeats the whole call with
 * the code. {@code getFlowPath()} tells them apart — the resource-owner password grant sets it to
 * {@code token}, and anything else is treated as a form flow, so an unexpected value renders a page
 * rather than leaking one into a token response.
 *
 * <p>The code lives in Keycloak's single-use object store rather than an auth-session note, because
 * direct grant builds and destroys its authentication session on every token request. The email
 * template and subject key are configuration, so the realm's own theme decides what the message
 * looks like.
 */
public class EmailOtpAuthenticator implements Authenticator, AuthenticatorFactory {

  public static final String ID = "email-otp";

  public static final String DEFAULT_EMAIL_TEMPLATE = "code-email.ftl";
  public static final String DEFAULT_EMAIL_SUBJECT_KEY = "emailCodeSubject";

  /** Flow path the resource-owner password grant runs under. Everything else renders a form. */
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

  // ------------------------------------------------------------------ entry points

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    Step step = open(context);
    if (step == null) {
      return;
    }

    if (step.directGrant) {
      String submitted = step.form.getFirst(PARAM_OTP);
      if (submitted == null || submitted.isBlank()) {
        sendAndReport(step);
      } else {
        verifyAndReport(step, submitted.trim());
      }
      return;
    }

    // A browser lands here on first entry into the step: mail a code, then ask for it.
    sendAndReport(step);
  }

  /** Only reached from a form flow — direct grant never posts back. */
  @Override
  public void action(AuthenticationFlowContext context) {
    Step step = open(context);
    if (step == null) {
      return;
    }

    if (step.form.containsKey(FIELD_RESEND)) {
      sendAndReport(step);
      return;
    }

    String submitted = step.form.getFirst(FIELD_CODE);
    if (submitted == null || submitted.isBlank()) {
      challenge(step, new FormMessage(FIELD_CODE, MSG_INVALID), false);
      return;
    }
    verifyAndReport(step, submitted.trim());
  }

  /** Gathers what every branch needs, or fails the flow and returns null. */
  private Step open(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user == null || user.getEmail() == null || user.getEmail().isBlank()) {
      context.failure(
          AuthenticationFlowError.INVALID_USER,
          JsonResponses.error(
              400, JsonResponses.ERROR_INVALID_REQUEST, "Missing parameter: username"));
      return null;
    }
    return new Step(context, user, OtpConfig.from(context.getAuthenticatorConfig()));
  }

  /** Everything one invocation needs, resolved once. */
  private final class Step {
    final AuthenticationFlowContext context;
    final UserModel user;
    final OtpConfig config;
    final OtpStore store;
    final String key;
    final MultivaluedMap<String, String> form;
    final boolean directGrant;

    Step(AuthenticationFlowContext context, UserModel user, OtpConfig config) {
      this.context = context;
      this.user = user;
      this.config = config;
      this.store = storeFactory.apply(context.getSession());
      this.key = OtpKeys.code(user.getId());
      this.form = context.getHttpRequest().getDecodedFormParameters();
      this.directGrant = FLOW_PATH_TOKEN.equals(context.getFlowPath());
    }
  }

  // ------------------------------------------------------------------ sending

  private enum SendResult {
    SENT,
    THROTTLED,
    BUDGET_EXHAUSTED,
    ATTESTATION_MISSING,
    MAIL_FAILED
  }

  /** Runs the send, then renders the outcome the way this flow expects. */
  private void sendAndReport(Step step) {
    long[] retryAfter = new long[1];
    SendResult result = deliverCode(step, retryAfter);

    if (step.directGrant) {
      switch (result) {
        case SENT ->
            step.context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                JsonResponses.otpRequired(step.user.getEmail(), step.config.codeTtlSeconds()));
        case THROTTLED ->
            step.context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                JsonResponses.throttled(retryAfter[0]));
        case BUDGET_EXHAUSTED ->
            step.context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                JsonResponses.temporarilyUnavailable("code sending is temporarily unavailable"));
        case ATTESTATION_MISSING ->
            step.context.failure(
                AuthenticationFlowError.ACCESS_DENIED,
                JsonResponses.error(
                    400,
                    JsonResponses.ERROR_INVALID_REQUEST,
                    "Missing or invalid app attestation"));
        case MAIL_FAILED ->
            step.context.failure(
                AuthenticationFlowError.INTERNAL_ERROR,
                JsonResponses.temporarilyUnavailable("could not send the code"));
      }
      return;
    }

    switch (result) {
      case SENT -> challenge(step, null, false);
      case THROTTLED ->
          challenge(step, new FormMessage(FIELD_CODE, MSG_RESEND_COOLDOWN, retryAfter[0]), false);
      // None of these are actionable by the user, so they all read as "we couldn't send it".
      case BUDGET_EXHAUSTED, MAIL_FAILED, ATTESTATION_MISSING ->
          challenge(step, new FormMessage(FIELD_CODE, MSG_SEND_FAILED), false);
    }
  }

  /** Mints, stores and mails a code, subject to the send guards. */
  private SendResult deliverCode(Step step, long[] retryAfter) {
    if (!attestationAccepted(step)) {
      LOG.warnf(
          "Rejected a code request without a valid attestation token for '%s'", step.user.getId());
      return SendResult.ATTESTATION_MISSING;
    }

    long now = clock.instant().getEpochSecond();
    Optional<OtpRecord> pending = step.store.get(step.key).flatMap(OtpRecord::fromNotes);
    if (step.config.resendCooldownSeconds() > 0 && pending.isPresent()) {
      long elapsed = now - pending.get().sentAtEpochSeconds();
      if (elapsed < step.config.resendCooldownSeconds()) {
        retryAfter[0] = step.config.resendCooldownSeconds() - elapsed;
        return SendResult.THROTTLED;
      }
    }

    RealmModel realm = step.context.getRealm();
    OtpRateGate.Decision decision =
        new OtpRateGate(step.store, clock, step.config)
            .reserve(realm.getId(), step.user.getEmail(), remoteAddress(step.context));
    if (!decision.allowed()) {
      if (decision.outcome() == OtpRateGate.Outcome.BUDGET_EXHAUSTED) {
        LOG.warnf(
            "Realm '%s' has spent its hourly OTP budget; refusing to send more codes",
            realm.getName());
        return SendResult.BUDGET_EXHAUSTED;
      }
      retryAfter[0] = decision.retryAfterSeconds();
      return SendResult.THROTTLED;
    }

    String code = OtpCodes.generate(step.config.codeLength());
    String salt = OtpCodes.newSalt();
    step.store.put(
        step.key,
        new OtpRecord(OtpCodes.hash(salt, code), salt, 0, now).toNotes(),
        step.config.codeTtlSeconds());

    try {
      mail(step, code);
    } catch (EmailException | RuntimeException e) {
      // A code the user never received must not sit there blocking the next send on the cooldown.
      step.store.remove(step.key);
      LOG.warnf(e, "Could not mail a code to '%s'", step.user.getEmail());
      return SendResult.MAIL_FAILED;
    }
    return SendResult.SENT;
  }

  /** Sends through the configured template — the same one both flows use. */
  private void mail(Step step, String code) throws EmailException {
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("code", code);
    attributes.put("ttl", step.config.codeTtlSeconds());
    attributes.put("username", step.user.getEmail());
    attributes.put("realmName", step.context.getRealm().getName());

    step.context
        .getSession()
        .getProvider(EmailTemplateProvider.class)
        .setRealm(step.context.getRealm())
        .setUser(step.user)
        .send(step.config.emailSubjectKey(), List.of(), step.config.emailTemplate(), attributes);
  }

  // ------------------------------------------------------------------ verifying

  private enum VerifyResult {
    OK,
    NO_CODE,
    TOO_MANY_ATTEMPTS,
    INVALID
  }

  private void verifyAndReport(Step step, String submitted) {
    VerifyResult result = checkCode(step, submitted);

    if (result == VerifyResult.OK) {
      step.context.success();
      return;
    }

    if (step.directGrant) {
      String description =
          switch (result) {
            case NO_CODE -> "Code expired or not requested";
            case TOO_MANY_ATTEMPTS -> "Too many attempts";
            default -> "Invalid code";
          };
      AuthenticationFlowError error =
          result == VerifyResult.NO_CODE
              ? AuthenticationFlowError.EXPIRED_CODE
              : AuthenticationFlowError.INVALID_CREDENTIALS;
      step.context.failure(
          error, JsonResponses.error(400, JsonResponses.ERROR_INVALID_GRANT, description));
      return;
    }

    String message =
        switch (result) {
          case NO_CODE -> MSG_EXPIRED;
          case TOO_MANY_ATTEMPTS -> MSG_TOO_MANY_ATTEMPTS;
          default -> MSG_INVALID;
        };
    // A wrong guess can be the one that burns the code, so ask the store rather than the result.
    boolean burned =
        result != VerifyResult.NO_CODE && step.store.get(step.key).isEmpty();
    challenge(step, new FormMessage(FIELD_CODE, message), burned);
  }

  private VerifyResult checkCode(Step step, String submitted) {
    Optional<OtpRecord> stored = step.store.get(step.key).flatMap(OtpRecord::fromNotes);
    if (stored.isEmpty()) {
      return VerifyResult.NO_CODE;
    }

    OtpRecord record = stored.get();
    // Only reachable if maxAttempts was lowered while a code was already pending.
    if (step.config.maxAttempts() > 0 && record.attempts() >= step.config.maxAttempts()) {
      step.store.remove(step.key);
      return VerifyResult.TOO_MANY_ATTEMPTS;
    }

    if (!OtpCodes.matches(record.salt(), record.hash(), submitted)) {
      OtpRecord bumped = record.withAttempt();
      boolean burned = step.config.maxAttempts() > 0 && bumped.attempts() >= step.config.maxAttempts();
      if (burned) {
        step.store.remove(step.key);
      } else {
        // Re-stored with what is left of the original lifetime, never a fresh one.
        step.store.put(step.key, bumped.toNotes(), remainingTtl(record, step.config));
      }
      // Direct grant does not feed Keycloak's brute-force counter on its own, so do it here.
      step.context
          .getProtector()
          .failedLogin(
              step.context.getRealm(),
              step.user,
              step.context.getConnection(),
              step.context.getUriInfo());
      // Say why the form just went dead, rather than "that code isn't right".
      return burned ? VerifyResult.TOO_MANY_ATTEMPTS : VerifyResult.INVALID;
    }

    step.store.remove(step.key);
    return VerifyResult.OK;
  }

  // ------------------------------------------------------------------ form rendering

  /** Renders the code form, with a field-scoped error when there is one. */
  private void challenge(Step step, FormMessage error, boolean maxAttemptsReached) {
    LoginFormsProvider form =
        step.context
            .form()
            .setAttribute(ATTR_CODE_LENGTH, step.config.codeLength())
            .setAttribute(ATTR_MAX_ATTEMPTS_REACHED, maxAttemptsReached);

    if (error == null) {
      step.context.challenge(form.createForm(CODE_FORM_TEMPLATE));
      return;
    }

    Response response = form.setErrors(List.of(error)).createForm(CODE_FORM_TEMPLATE);
    step.context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, response);
  }

  // ------------------------------------------------------------------ helpers

  private long remainingTtl(OtpRecord record, OtpConfig config) {
    long elapsed = clock.instant().getEpochSecond() - record.sentAtEpochSeconds();
    return Math.max(config.codeTtlSeconds() - elapsed, 1);
  }

  private static String remoteAddress(AuthenticationFlowContext context) {
    ClientConnection connection = context.getConnection();
    return connection == null ? null : connection.getRemoteAddr();
  }

  private boolean attestationAccepted(Step step) {
    if (step.config.startTokenHeader().isEmpty()) {
      return true;
    }
    String token =
        step.context
            .getHttpRequest()
            .getHttpHeaders()
            .getHeaderString(step.config.startTokenHeader());
    if (token == null || token.isBlank()) {
      return false;
    }
    return step.config.startTokenVerifyUrl().isEmpty()
        || verifyAttestationToken(step.config.startTokenVerifyUrl(), token);
  }

  /**
   * POSTs the attestation token for verification. Mirrors the browser CAPTCHA step: an explicit
   * rejection blocks the send, an unreachable verifier does not (overridable in tests).
   */
  boolean verifyAttestationToken(String verifyUrl, String token) {
    try {
      HttpRequest request =
          HttpRequest.newBuilder(URI.create(verifyUrl))
              .timeout(Duration.ofSeconds(4))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(
                  HttpRequest.BodyPublishers.ofString(
                      "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)))
              .build();
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

  // ------------------------------------------------------------------ SPI plumbing

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // no-op
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {
    // no-op
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // no-op
  }

  @Override
  public void close() {
    // no-op
  }

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
        text(
            OtpConfig.CONFIG_CODE_LENGTH,
            "Code length",
            "Number of digits in the emailed code.",
            String.valueOf(OtpConfig.DEFAULT_CODE_LENGTH)),
        text(
            OtpConfig.CONFIG_CODE_TTL_SECONDS,
            "Code TTL (seconds)",
            "How long a code stays valid. Direct grant returns it to the app as 'otp_ttl'.",
            String.valueOf(OtpConfig.DEFAULT_CODE_TTL_SECONDS)),
        text(
            OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS,
            "Resend cooldown (seconds)",
            "Minimum gap between two codes for one address. 0 disables the cooldown.",
            String.valueOf(OtpConfig.DEFAULT_RESEND_COOLDOWN_SECONDS)),
        text(
            OtpConfig.CONFIG_MAX_ATTEMPTS,
            "Max verification attempts",
            "Wrong guesses allowed before the code is burned. 0 disables the cap.",
            String.valueOf(OtpConfig.DEFAULT_MAX_ATTEMPTS)),
        text(
            OtpConfig.CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY,
            "Max sends per email per day",
            "Caps how much mail one address can be made to receive. 0 disables the cap.",
            String.valueOf(OtpConfig.DEFAULT_MAX_SENDS_PER_EMAIL_PER_DAY)),
        text(
            OtpConfig.CONFIG_MAX_SENDS_PER_IP_PER_HOUR,
            "Max sends per IP per hour",
            "Caps a single source. Requires proxy-headers to be configured, so the real client "
                + "IP is visible. Keep it generous: carriers and shared networks put many users "
                + "behind one address. 0 disables the cap.",
            String.valueOf(OtpConfig.DEFAULT_MAX_SENDS_PER_IP_PER_HOUR)),
        text(
            OtpConfig.CONFIG_MAX_SENDS_PER_REALM_PER_HOUR,
            "Max sends per realm per hour",
            "Circuit breaker for a distributed flood, where every per-IP and per-address counter "
                + "still looks innocent. Protects the mail provider quota and sending reputation. "
                + "0 disables the budget.",
            String.valueOf(OtpConfig.DEFAULT_MAX_SENDS_PER_REALM_PER_HOUR)),
        text(
            OtpConfig.CONFIG_EMAIL_TEMPLATE,
            "Email template",
            "Freemarker template in the realm's email theme.",
            DEFAULT_EMAIL_TEMPLATE),
        text(
            OtpConfig.CONFIG_EMAIL_SUBJECT_KEY,
            "Email subject key",
            "Message key resolved against the email theme's message bundle.",
            DEFAULT_EMAIL_SUBJECT_KEY),
        text(
            OtpConfig.CONFIG_START_TOKEN_HEADER,
            "App attestation header",
            "When set, a code is only sent if the request carries this header. Point it at an App "
                + "Attest / Play Integrity / reCAPTCHA Enterprise token. Empty = no check.",
            ""),
        text(
            OtpConfig.CONFIG_START_TOKEN_VERIFY_URL,
            "App attestation verify URL",
            "Endpoint the attestation token is POSTed to as 'token'; a JSON body with "
                + "\"success\": false rejects the send. Empty = presence of the header is enough.",
            ""));
  }

  private static ProviderConfigProperty text(
      String name, String label, String help, String defaultValue) {
    return new ProviderConfigProperty(
        name, label, help, ProviderConfigProperty.STRING_TYPE, defaultValue);
  }
}
