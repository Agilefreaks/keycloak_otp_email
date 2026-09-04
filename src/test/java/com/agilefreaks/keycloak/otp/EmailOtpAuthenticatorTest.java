package com.agilefreaks.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.ClientConnection;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;

class EmailOtpAuthenticatorTest {

  private static final long NOW = 1_700_000_000L;
  private static final String EMAIL = "visitor@example.com";
  private static final String USER_ID = "user-1";
  private static final String REALM_ID = "realm-1";

  private final MutableClock clock = new MutableClock(NOW);
  private final InMemoryOtpStore store = new InMemoryOtpStore(NOW);
  private final EmailOtpAuthenticator authenticator =
      new EmailOtpAuthenticator(session -> store, clock);

  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private RealmModel realm;
  private UserModel user;
  private EmailTemplateProvider email;
  private BruteForceProtector protector;
  private MultivaluedMap<String, String> form;
  private Map<String, String> config;

  @BeforeEach
  void setUp() {
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    realm = mock(RealmModel.class);
    user = mock(UserModel.class);
    email = mock(EmailTemplateProvider.class);
    protector = mock(BruteForceProtector.class);
    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    form = new MultivaluedHashMap<>();
    config = new HashMap<>();

    when(ctx.getFlowPath()).thenReturn("token"); // what ROPC sets; the form flow sets something else
    when(ctx.getSession()).thenReturn(session);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getUser()).thenReturn(user);
    when(ctx.getHttpRequest()).thenReturn(request);
    when(ctx.getConnection()).thenReturn(connection);
    when(ctx.getUriInfo()).thenReturn(mock(UriInfo.class));
    when(ctx.getProtector()).thenReturn(protector);
    when(ctx.getAuthenticatorConfig()).thenReturn(configModel());
    when(request.getDecodedFormParameters()).thenReturn(form);
    when(request.getHttpHeaders()).thenReturn(mock(HttpHeaders.class));
    when(connection.getRemoteAddr()).thenReturn("203.0.113.7");
    when(realm.getId()).thenReturn(REALM_ID);
    when(realm.getName()).thenReturn("test-realm");
    when(user.getId()).thenReturn(USER_ID);
    when(user.getEmail()).thenReturn(EMAIL);
    when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
    when(email.setRealm(realm)).thenReturn(email);
    when(email.setUser(user)).thenReturn(email);
  }

  private Response captureFailure() {
    ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
    verify(ctx).failure(any(AuthenticationFlowError.class), captor.capture());
    return captor.getValue();
  }

  /** Runs the send half and returns the code that was mailed. */
  private String startAndReadMailedCode() throws EmailException {
    authenticator.authenticate(ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> attributes = ArgumentCaptor.forClass(Map.class);
    verify(email)
        .send(
            eq(EmailOtpAuthenticator.DEFAULT_EMAIL_SUBJECT_KEY),
            anyList(),
            eq(EmailOtpAuthenticator.DEFAULT_EMAIL_TEMPLATE),
            attributes.capture());
    Object code = attributes.getValue().get("code");
    assertNotNull(code, "the template must be given the code to render");
    return String.valueOf(code);
  }

  private void verifyNoMailSent() throws EmailException {
    verify(email, never()).send(anyString(), anyList(), anyString(), anyMap());
  }

  @Test
  void startPathMailsACodeAndAsksForIt() throws Exception {
    String code = startAndReadMailedCode();

    assertTrue(code.matches("\\d{6}"), "expected a 6 digit code, got " + code);

    Response response = captureFailure();
    assertEquals(400, response.getStatus());
    Map<String, Object> body = TestJson.parse(response);
    assertEquals(JsonResponses.ERROR_OTP_REQUIRED, body.get("error"));
    assertEquals(300, ((Number) body.get("otp_ttl")).intValue());
    assertTrue(String.valueOf(body.get("error_description")).contains(EMAIL));
    verify(ctx, never()).success();
  }

  @Test
  void startPathUsesTheSameEmailTemplateAsTheBrowserFlow() throws Exception {
    startAndReadMailedCode();

    verify(email).setRealm(realm);
    verify(email).setUser(user);
  }

  @Test
  void startPathHonoursAConfiguredTtl() throws Exception {
    config.put(OtpConfig.CONFIG_CODE_TTL_SECONDS, "120");

    authenticator.authenticate(ctx);

    assertEquals(120, ((Number) TestJson.parse(captureFailure()).get("otp_ttl")).intValue());
  }

  @Test
  void secondStartInsideTheCooldownSendsNothing() throws Exception {
    authenticator.authenticate(ctx);
    reset(ctx);
    setUpContextAgain();

    clock.advanceSeconds(30);
    store.setNow(clock.epochSeconds());
    authenticator.authenticate(ctx);

    Response response = captureFailure();
    assertEquals(429, response.getStatus());
    Map<String, Object> body = TestJson.parse(response);
    assertEquals(JsonResponses.ERROR_OTP_THROTTLED, body.get("error"));
    assertEquals(30, ((Number) body.get("retry_after")).intValue());
    verify(email, times(1)).send(anyString(), anyList(), anyString(), anyMap());
  }

  @Test
  void startAfterTheCooldownSendsAgain() throws Exception {
    authenticator.authenticate(ctx);
    reset(ctx);
    setUpContextAgain();

    clock.advanceSeconds(61);
    store.setNow(clock.epochSeconds());
    authenticator.authenticate(ctx);

    verify(email, times(2)).send(anyString(), anyList(), anyString(), anyMap());
  }

  @Test
  void refusesTheSendOnceTheDailyAddressCapIsSpent() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "0");
    config.put(OtpConfig.CONFIG_MAX_SENDS_PER_EMAIL_PER_DAY, "2");

    for (int i = 0; i < 2; i++) {
      authenticator.authenticate(ctx);
      reset(ctx);
      setUpContextAgain();
    }
    authenticator.authenticate(ctx);

    assertEquals(429, captureFailure().getStatus());
    verify(email, times(2)).send(anyString(), anyList(), anyString(), anyMap());
  }

  @Test
  void refusesTheSendOnceTheRealmBudgetIsSpent() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "0");
    config.put(OtpConfig.CONFIG_MAX_SENDS_PER_REALM_PER_HOUR, "1");

    authenticator.authenticate(ctx);
    reset(ctx);
    setUpContextAgain();
    authenticator.authenticate(ctx);

    Response response = captureFailure();
    assertEquals(503, response.getStatus());
    assertEquals(
        JsonResponses.ERROR_TEMPORARILY_UNAVAILABLE, TestJson.parse(response).get("error"));
    verify(email, times(1)).send(anyString(), anyList(), anyString(), anyMap());
  }

  @Test
  void aFailedSendLeavesNoCodeBehind() throws Exception {
    doThrow(new EmailException("smtp down"))
        .when(email)
        .send(anyString(), anyList(), anyString(), anyMap());

    authenticator.authenticate(ctx);

    Response response = captureFailure();
    assertEquals(503, response.getStatus());
    assertEquals(
        JsonResponses.ERROR_TEMPORARILY_UNAVAILABLE, TestJson.parse(response).get("error"));
    // A code the user never received must not block the next attempt on the cooldown.
    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
  }

  @Test
  void requiresTheAttestationHeaderWhenConfigured() throws Exception {
    config.put(OtpConfig.CONFIG_START_TOKEN_HEADER, "X-App-Attest");

    authenticator.authenticate(ctx);

    assertEquals(400, captureFailure().getStatus());
    verifyNoMailSent();
  }

  @Test
  void correctCodeSignsTheUserIn() throws Exception {
    String code = startAndReadMailedCode();
    reset(ctx);
    setUpContextAgain();
    form.putSingle("otp", code);

    authenticator.authenticate(ctx);

    verify(ctx).success();
    verify(ctx, never()).failure(any(), any());
    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
  }

  @Test
  void aCodeIsSingleUse() throws Exception {
    String code = startAndReadMailedCode();
    reset(ctx);
    setUpContextAgain();
    form.putSingle("otp", code);
    authenticator.authenticate(ctx);

    reset(ctx);
    setUpContextAgain();
    form.putSingle("otp", code);
    authenticator.authenticate(ctx);

    assertEquals(400, captureFailure().getStatus());
    verify(ctx, never()).success();
  }

  @Test
  void wrongCodeIsRejectedAndCountedAgainstTheUser() throws Exception {
    startAndReadMailedCode();
    reset(ctx);
    setUpContextAgain();
    form.putSingle("otp", "000000");

    authenticator.authenticate(ctx);

    Response response = captureFailure();
    assertEquals(400, response.getStatus());
    assertEquals(JsonResponses.ERROR_INVALID_GRANT, TestJson.parse(response).get("error"));
    verify(protector).failedLogin(eq(realm), eq(user), any(), any());
    verify(ctx, never()).success();
    // Still redeemable — one typo must not cost the user their code.
    assertTrue(store.get(OtpKeys.code(USER_ID)).isPresent());
  }

  @Test
  void tooManyWrongGuessesBurnTheCode() throws Exception {
    config.put(OtpConfig.CONFIG_MAX_ATTEMPTS, "3");
    String code = startAndReadMailedCode();

    for (int i = 0; i < 3; i++) {
      reset(ctx);
      setUpContextAgain();
      form.putSingle("otp", "000000");
      authenticator.authenticate(ctx);
    }

    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));

    // Even the right code is worthless now.
    reset(ctx);
    setUpContextAgain();
    form.putSingle("otp", code);
    authenticator.authenticate(ctx);

    assertEquals(400, captureFailure().getStatus());
    verify(ctx, never()).success();
  }

  @Test
  void anExpiredCodeIsRefused() throws Exception {
    String code = startAndReadMailedCode();
    reset(ctx);
    setUpContextAgain();

    clock.advanceSeconds(301);
    store.setNow(clock.epochSeconds());
    form.putSingle("otp", code);
    authenticator.authenticate(ctx);

    Response response = captureFailure();
    assertEquals(400, response.getStatus());
    assertEquals(JsonResponses.ERROR_INVALID_GRANT, TestJson.parse(response).get("error"));
    verify(ctx, never()).success();
  }

  @Test
  void verifyingWithoutEverRequestingACodeIsRefused() throws Exception {
    form.putSingle("otp", "123456");

    authenticator.authenticate(ctx);

    assertEquals(400, captureFailure().getStatus());
    verify(ctx, never()).success();
    verifyNoMailSent();
  }

  private AuthenticatorConfigModel configModel() {
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setConfig(config);
    return model;
  }

  /** Re-stubs the context after a {@code reset}, so one test can drive several token requests. */
  private void setUpContextAgain() {
    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    when(ctx.getFlowPath()).thenReturn("token"); // what ROPC sets; the form flow sets something else
    when(ctx.getSession()).thenReturn(session);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getUser()).thenReturn(user);
    when(ctx.getHttpRequest()).thenReturn(request);
    when(ctx.getConnection()).thenReturn(connection);
    when(ctx.getUriInfo()).thenReturn(mock(UriInfo.class));
    when(ctx.getProtector()).thenReturn(protector);
    when(ctx.getAuthenticatorConfig()).thenReturn(configModel());
    when(request.getDecodedFormParameters()).thenReturn(form);
    when(request.getHttpHeaders()).thenReturn(mock(HttpHeaders.class));
    when(connection.getRemoteAddr()).thenReturn("203.0.113.7");
  }

  @Test
  void factoryMetadataIsWired() {
    assertEquals("email-otp", authenticator.getId());
    assertTrue(authenticator.requiresUser());
    assertTrue(authenticator.isConfigurable());
    List<String> names =
        authenticator.getConfigProperties().stream().map(p -> p.getName()).toList();
    assertTrue(names.contains(OtpConfig.CONFIG_MAX_SENDS_PER_REALM_PER_HOUR), names.toString());
  }
}
