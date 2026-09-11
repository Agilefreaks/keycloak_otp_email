package com.agilefreaks.keycloak.otp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;

/** The event trail the OTP step leaves: a send, the ways it is refused, and a verification. */
class EmailOtpEventsTest {

  private static final long NOW = 1_700_000_000L;
  private static final String EMAIL = "visitor@example.com";

  private final MutableClock clock = new MutableClock(NOW);
  private final InMemoryOtpStore store = new InMemoryOtpStore(NOW);
  private final EmailOtpAuthenticator authenticator =
      new EmailOtpAuthenticator(session -> store, clock);

  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private RealmModel realm;
  private UserModel user;
  private EmailTemplateProvider email;
  private MultivaluedMap<String, String> form;
  private Map<String, String> config;
  private EventBuilder event;
  private EventBuilder sideEvent;
  private String flowPath = "token";

  @BeforeEach
  void setUp() {
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    realm = mock(RealmModel.class);
    user = mock(UserModel.class);
    email = mock(EmailTemplateProvider.class);
    event = mock(EventBuilder.class, RETURNS_SELF);
    sideEvent = mock(EventBuilder.class, RETURNS_SELF);
    form = new MultivaluedHashMap<>();
    config = new HashMap<>();

    when(realm.getId()).thenReturn("realm-1");
    when(realm.getName()).thenReturn("test-realm");
    when(user.getId()).thenReturn("user-1");
    when(user.getEmail()).thenReturn(EMAIL);
    when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
    when(email.setRealm(realm)).thenReturn(email);
    when(email.setUser(user)).thenReturn(email);
    stubRequest();
  }

  private void stubRequest() {
    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setConfig(config);
    LoginFormsProvider forms = mock(LoginFormsProvider.class);

    when(ctx.getFlowPath()).thenReturn(flowPath);
    when(ctx.getSession()).thenReturn(session);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getUser()).thenReturn(user);
    when(ctx.getHttpRequest()).thenReturn(request);
    when(ctx.getConnection()).thenReturn(connection);
    when(ctx.getUriInfo()).thenReturn(mock(UriInfo.class));
    when(ctx.getProtector()).thenReturn(mock(BruteForceProtector.class));
    when(ctx.getAuthenticatorConfig()).thenReturn(model);
    when(ctx.form()).thenReturn(forms);
    when(forms.setAttribute(anyString(), any())).thenReturn(forms);
    when(request.getDecodedFormParameters()).thenReturn(form);
    when(request.getHttpHeaders()).thenReturn(mock(HttpHeaders.class));
    when(connection.getRemoteAddr()).thenReturn("203.0.113.7");

    when(ctx.getEvent()).thenReturn(event);
    when(event.clone()).thenReturn(sideEvent);
  }

  private void nextRequest() {
    reset(ctx);
    stubRequest();
  }

  private String sendAndReadCode() throws EmailException {
    authenticator.authenticate(ctx);
    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> attributes = ArgumentCaptor.forClass(Map.class);
    verify(email)
        .send(
            eq(OtpConfig.DEFAULT_EMAIL_SUBJECT_KEY),
            anyList(),
            eq(OtpConfig.DEFAULT_EMAIL_TEMPLATE),
            attributes.capture());
    return String.valueOf(attributes.getValue().get("code"));
  }

  @Test
  void mailedCode_isReportedAsASentVerificationEmail() {
    authenticator.authenticate(ctx);

    verify(sideEvent).event(EventType.SEND_VERIFY_EMAIL);
    verify(sideEvent).detail(Details.EMAIL, EMAIL);
    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_FLOW, EmailOtpAuthenticator.FLOW_DIRECT_GRANT);
    verify(sideEvent)
        .detail(
            EmailOtpAuthenticator.DETAIL_OTP_TTL,
            String.valueOf(OtpConfig.DEFAULT_CODE_TTL_SECONDS));
    verify(sideEvent).success();
  }

  @Test
  void browserFlow_isReportedAsTheBrowserFlow() {
    flowPath = "authenticate";
    nextRequest();

    authenticator.authenticate(ctx);

    verify(sideEvent).detail(EmailOtpAuthenticator.DETAIL_FLOW, EmailOtpAuthenticator.FLOW_BROWSER);
  }

  @Test
  void smtpFailure_isReportedAsASendError() throws Exception {
    doThrow(new EmailException("smtp down"))
        .when(email)
        .send(anyString(), anyList(), anyString(), anyMap());

    authenticator.authenticate(ctx);

    verify(sideEvent).event(EventType.SEND_VERIFY_EMAIL);
    verify(sideEvent).error(Errors.EMAIL_SEND_FAILED);
    verify(sideEvent, never()).success();
  }

  @Test
  void resendCooldown_isReportedWithItsRetryAfter() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "60");
    sendAndReadCode();
    nextRequest();

    authenticator.authenticate(ctx);

    verify(sideEvent).detail(EmailOtpAuthenticator.DETAIL_REJECT, EmailOtpAuthenticator.REJECT_COOLDOWN);
    verify(sideEvent).detail(EmailOtpAuthenticator.DETAIL_RETRY_AFTER, "60");
    // A cooldown is a refusal by policy, not a send that failed.
    verify(sideEvent).error(Errors.NOT_ALLOWED);
  }

  @Test
  void perAddressCap_isReportedAsThatSpecificGuard() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "0");
    config.put(OtpConfig.CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY, "1");
    sendAndReadCode();
    nextRequest();

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_REJECT, OtpRateGate.Limit.EMAIL_DAY.detail);
  }

  @Test
  void realmBudget_isReportedAsTheBudgetItIs() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "0");
    config.put(OtpConfig.CONFIG_MAX_SENDS_PER_REALM_PER_HOUR, "1");
    sendAndReadCode();
    nextRequest();

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_REJECT, OtpRateGate.Limit.REALM_HOUR.detail);
  }

  @Test
  void missingAttestation_isReportedAsARejectedSend() {
    config.put(OtpConfig.CONFIG_START_TOKEN_HEADER, "X-App-Attest");

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_REJECT, EmailOtpAuthenticator.REJECT_ATTESTATION);
    verify(sideEvent).error(Errors.NOT_ALLOWED);
  }

  @Test
  void correctCode_recordsTheResultOnTheFlowsOwnEvent() throws Exception {
    String code = sendAndReadCode();
    nextRequest();
    form.putSingle(EmailOtpAuthenticator.PARAM_OTP, code);

    authenticator.authenticate(ctx);

    verify(event).detail(EmailOtpAuthenticator.DETAIL_OTP_RESULT, EmailOtpAuthenticator.RESULT_OK);
    verify(event).detail(EmailOtpAuthenticator.DETAIL_OTP_ATTEMPTS, "1");
    verify(ctx).success();
  }

  @Test
  void wrongCode_isReportedAsABadCredential() throws Exception {
    sendAndReadCode();
    nextRequest();
    form.putSingle(EmailOtpAuthenticator.PARAM_OTP, "000000");

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_OTP_RESULT, EmailOtpAuthenticator.RESULT_INVALID);
    verify(sideEvent).error(Errors.INVALID_USER_CREDENTIALS);
  }

  @Test
  void codeThatWasNeverRequested_isReportedAsExpired() {
    form.putSingle(EmailOtpAuthenticator.PARAM_OTP, "123456");

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(EmailOtpAuthenticator.DETAIL_OTP_RESULT, EmailOtpAuthenticator.RESULT_EXPIRED);
    verify(sideEvent).error(Errors.EXPIRED_CODE);
  }

  @Test
  void burningTheLastAttempt_isReportedAsSuch() throws Exception {
    config.put(OtpConfig.CONFIG_MAX_ATTEMPTS, "1");
    sendAndReadCode();
    nextRequest();
    form.putSingle(EmailOtpAuthenticator.PARAM_OTP, "000000");

    authenticator.authenticate(ctx);

    verify(sideEvent)
        .detail(
            EmailOtpAuthenticator.DETAIL_OTP_RESULT,
            EmailOtpAuthenticator.RESULT_ATTEMPTS_EXHAUSTED);
  }

  /** Regression guard: newEvent() would replace the flow's builder and break its LOGIN event. */
  @Test
  void neverReplacesTheFlowsEventBuilder() {
    authenticator.authenticate(ctx);

    verify(ctx, never()).newEvent();
  }
}
