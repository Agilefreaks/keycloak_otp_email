package com.agilefreaks.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;

/**
 * The same authenticator driven through a form flow. It tells the two apart by
 * {@code getFlowPath()} — direct grant sets it to "token", so anything else renders the form
 * rather than leaking one into a token response.
 */
class EmailOtpBrowserFlowTest {

  private static final long NOW = 1_700_000_000L;
  private static final String EMAIL = "visitor@example.com";
  private static final String USER_ID = "user-1";

  private final MutableClock clock = new MutableClock(NOW);
  private final InMemoryOtpStore store = new InMemoryOtpStore(NOW);
  private final EmailOtpAuthenticator authenticator =
      new EmailOtpAuthenticator(session -> store, clock);

  private AuthenticationFlowContext ctx;
  private KeycloakSession session;
  private RealmModel realm;
  private UserModel user;
  private EmailTemplateProvider email;
  private LoginFormsProvider form;
  private BruteForceProtector protector;
  private Response formResponse;
  private MultivaluedMap<String, String> formData;
  private Map<String, String> config;

  @BeforeEach
  void setUp() {
    ctx = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    realm = mock(RealmModel.class);
    user = mock(UserModel.class);
    email = mock(EmailTemplateProvider.class);
    form = mock(LoginFormsProvider.class);
    protector = mock(BruteForceProtector.class);
    formResponse = Response.ok("the rendered form").build();
    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    formData = new MultivaluedHashMap<>();
    config = new HashMap<>();

    when(ctx.getFlowPath()).thenReturn("authenticate");
    when(ctx.getSession()).thenReturn(session);
    when(ctx.getRealm()).thenReturn(realm);
    when(ctx.getUser()).thenReturn(user);
    when(ctx.getHttpRequest()).thenReturn(request);
    when(ctx.getConnection()).thenReturn(connection);
    when(ctx.getUriInfo()).thenReturn(mock(UriInfo.class));
    when(ctx.getProtector()).thenReturn(protector);
    when(ctx.form()).thenReturn(form);
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setConfig(config);
    when(ctx.getAuthenticatorConfig()).thenReturn(model);
    when(request.getDecodedFormParameters()).thenReturn(formData);
    when(connection.getRemoteAddr()).thenReturn("203.0.113.7");
    when(realm.getId()).thenReturn("realm-1");
    when(realm.getName()).thenReturn("test-realm");
    when(user.getId()).thenReturn(USER_ID);
    when(user.getEmail()).thenReturn(EMAIL);
    when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
    when(email.setRealm(realm)).thenReturn(email);
    when(email.setUser(user)).thenReturn(email);
    when(form.setAttribute(anyString(), any())).thenReturn(form);
    when(form.setErrors(anyList())).thenReturn(form);
    when(form.createForm(anyString())).thenReturn(formResponse);
  }

  /** Runs the first entry into the step and returns the code that was mailed. */
  private String enterAndReadMailedCode() throws EmailException {
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
    assertNotNull(code);
    return String.valueOf(code);
  }

  /** The most recent setErrors call, for tests that drive several posts. */
  private List<FormMessage> captureLastErrors() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<FormMessage>> captor = ArgumentCaptor.forClass(List.class);
    verify(form, org.mockito.Mockito.atLeastOnce()).setErrors(captor.capture());
    return captor.getAllValues().get(captor.getAllValues().size() - 1);
  }

  private List<FormMessage> captureErrors() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<List<FormMessage>> captor = ArgumentCaptor.forClass(List.class);
    verify(form).setErrors(captor.capture());
    return captor.getValue();
  }

  @Test
  void firstEntryMailsACodeAndRendersTheForm() throws Exception {
    String code = enterAndReadMailedCode();

    assertTrue(code.matches("\\d{6}"));
    verify(form).createForm(EmailOtpAuthenticator.CODE_FORM_TEMPLATE);
    verify(ctx).challenge(formResponse);
    // The theme sizes its digit boxes from this.
    verify(form).setAttribute("codeLength", 6);
    verify(ctx, never()).success();
  }

  @Test
  void rendersAFormRatherThanJsonEvenWhenTheFlowPathIsUnexpected() throws Exception {
    when(ctx.getFlowPath()).thenReturn(null);

    authenticator.authenticate(ctx);

    verify(ctx).challenge(formResponse);
  }

  @Test
  void correctCodeSignsTheUserIn() throws Exception {
    String code = enterAndReadMailedCode();
    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, code);

    authenticator.action(ctx);

    verify(ctx).success();
    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
  }

  @Test
  void wrongCodeReRendersTheFormWithAFieldError() throws Exception {
    enterAndReadMailedCode();
    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, "000000");

    authenticator.action(ctx);

    List<FormMessage> errors = captureErrors();
    assertEquals(1, errors.size());
    // The theme reads messagesPerField.get('emailCode'), so the error must be field-scoped.
    assertEquals(EmailOtpAuthenticator.FIELD_CODE, errors.get(0).getField());
    assertEquals(EmailOtpAuthenticator.MSG_INVALID, errors.get(0).getMessage());
    verify(ctx).failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, formResponse);
    verify(protector).failedLogin(eq(realm), eq(user), any(), any());
    verify(ctx, never()).success();
    assertTrue(store.get(OtpKeys.code(USER_ID)).isPresent(), "one typo must not cost the code");
  }

  @Test
  void exhaustedAttemptsBurnTheCodeAndDisableTheForm() throws Exception {
    config.put(OtpConfig.CONFIG_MAX_ATTEMPTS, "2");
    enterAndReadMailedCode();

    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, "000000");
    authenticator.action(ctx);
    authenticator.action(ctx);

    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
    // The theme hides the Continue button and disables the inputs on this.
    verify(form).setAttribute("maxAttemptsReached", true);
    // The guess that burns the code must say so, not "that code isn't right".
    assertEquals(EmailOtpAuthenticator.MSG_TOO_MANY_ATTEMPTS, captureLastErrors().get(0).getMessage());
  }

  @Test
  void aLoweredAttemptCapRetiresAPendingCode() throws Exception {
    enterAndReadMailedCode();
    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, "000000");
    authenticator.action(ctx);

    config.put(OtpConfig.CONFIG_MAX_ATTEMPTS, "1"); // now below what the record already holds
    authenticator.action(ctx);

    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
    assertEquals(
        EmailOtpAuthenticator.MSG_TOO_MANY_ATTEMPTS, captureLastErrors().get(0).getMessage());
  }

  @Test
  void submittingWithoutAStoredCodeReportsExpiry() throws Exception {
    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, "123456");

    authenticator.action(ctx);

    assertEquals(EmailOtpAuthenticator.MSG_EXPIRED, captureErrors().get(0).getMessage());
    verify(ctx, never()).success();
  }

  @Test
  void resendMailsANewCodeOnceTheCooldownHasPassed() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "30");
    enterAndReadMailedCode();

    clock.advanceSeconds(31);
    store.setNow(clock.epochSeconds());
    formData.putSingle(EmailOtpAuthenticator.FIELD_RESEND, "");
    authenticator.action(ctx);

    verify(email, times(2)).send(anyString(), anyList(), anyString(), anyMap());
    verify(ctx, times(2)).challenge(formResponse);
  }

  @Test
  void resendInsideTheCooldownSendsNothingAndSaysWhy() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "30");
    enterAndReadMailedCode();

    clock.advanceSeconds(10);
    store.setNow(clock.epochSeconds());
    formData.putSingle(EmailOtpAuthenticator.FIELD_RESEND, "");
    authenticator.action(ctx);

    verify(email, times(1)).send(anyString(), anyList(), anyString(), anyMap());
    FormMessage error = captureErrors().get(0);
    assertEquals(EmailOtpAuthenticator.MSG_RESEND_COOLDOWN, error.getMessage());
    assertEquals(20L, error.getParameters()[0], "the message tells the user how long is left");
  }

  @Test
  void resendKeepsTheOldCodeUsableWhenItIsRefused() throws Exception {
    config.put(OtpConfig.CONFIG_RESEND_COOLDOWN_SECONDS, "30");
    String code = enterAndReadMailedCode();

    formData.putSingle(EmailOtpAuthenticator.FIELD_RESEND, "");
    authenticator.action(ctx);

    formData.remove(EmailOtpAuthenticator.FIELD_RESEND);
    formData.putSingle(EmailOtpAuthenticator.FIELD_CODE, code);
    authenticator.action(ctx);

    verify(ctx).success();
  }

  @Test
  void aFailedSendShowsAnErrorAndLeavesNoCodeBehind() throws Exception {
    org.mockito.Mockito.doThrow(new EmailException("smtp down"))
        .when(email)
        .send(anyString(), anyList(), anyString(), anyMap());

    authenticator.authenticate(ctx);

    assertEquals(EmailOtpAuthenticator.MSG_SEND_FAILED, captureErrors().get(0).getMessage());
    assertEquals(Optional.empty(), store.get(OtpKeys.code(USER_ID)));
  }
}
