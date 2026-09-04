# keycloak-otp-email

A Keycloak authenticator that emails a one-time code and verifies it — in a
**browser flow**, where it renders the code form, and in a **direct grant flow**,
where it answers JSON so a native app can drive its own login screens. One
implementation, so the two cannot drift apart.

Built and tested against **Keycloak 26.5** (`keycloak.version` in `pom.xml`).

## What it provides

| Provider id | `requiresUser()` | What it does |
|---|---|---|
| `email-otp` | `true` | No code pending → mints one, mails it, and asks for it. Code submitted → verifies it against a salted hash and lets the flow continue. Rate limited per address, per client IP and per realm. |

It identifies the user from the flow, so pair it **after** a step that sets one —
[`email-lookup-or-create`](https://github.com/Agilefreaks/keycloak_email_lookup_or_create)
for a passwordless login-or-signup, or any built-in username step.

## One authenticator, two flows

`getFlowPath()` tells them apart: the resource-owner password grant sets it to
`token`, and anything else is treated as a form flow — so an unexpected value
renders a page rather than leaking one into a token response.

| | Browser flow | Direct grant |
|---|---|---|
| First contact | mails a code, renders `email-code-form.ftl` | mails a code, answers `400 {"error":"otp_required","otp_ttl":…}` |
| Code arrives | posted back as `emailCode` | `otp` form parameter of the next token request |
| Resend | the `resend` button re-enters the send path | call again without `otp` |
| Errors | field-scoped message on `emailCode`, form re-rendered | OAuth JSON: `invalid_request`, `invalid_grant`, `otp_throttled`, `temporarily_unavailable` |

`otp` is not a standard OAuth parameter — it arrives as a form parameter and this
authenticator reads it, exactly as Keycloak's built-in
`direct-grant-validate-otp` reads `totp`:

```bash
TOKEN=https://id.example.com/realms/example/protocol/openid-connect/token

# 1. Start: no otp yet. Mails the code.
curl -s -X POST "$TOKEN" -d grant_type=password -d client_id=my-app \
  -d scope=openid -d username=visitor@example.com
# HTTP 400
# {"error":"otp_required","error_description":"code sent to visitor@example.com","otp_ttl":300}

# 2. Complete: the same call plus the code.
curl -s -X POST "$TOKEN" -d grant_type=password -d client_id=my-app \
  -d scope=openid -d username=visitor@example.com -d otp=418322
# HTTP 200 — access_token / refresh_token / id_token
```

## Why the code is not in the authentication session

Keycloak builds a fresh `AuthenticationSessionModel` for every direct grant token
request and destroys it before responding, so nothing carries between the two
calls — which is why a form-based OTP step, holding its code in an auth-session
note, cannot serve direct grant at all.

The pending code lives in Keycloak's **single-use object store** instead (the
cache action tokens use), keyed by user id and holding a salted SHA-256 hash,
never the code itself. Entries expire on their own, so there is nothing to sweep
and nothing left on the user record. The cost is that the store is not durable:
restarting the server drops codes in flight, and the user requests a new one.

## Rate limiting

The first call is unauthenticated and sends mail, and **Keycloak's brute-force
protection does not cover direct grant** — in 26.5 the only production caller of
`BruteForceProtector.failedLogin` is `AuthenticationProcessor.logFailure()`,
which runs on the browser path alone. So these limits are the guard, not a
supplement to one. Each is `0` to disable, and each execution carries its own
config, so a browser flow and a direct grant flow can be tuned independently.

| Config | Default | Stops |
|---|---|---|
| `codeLength` | `6` | — |
| `codeTtlSeconds` | `300` | — (returned to a direct grant client as `otp_ttl`) |
| `resendCooldownSeconds` | `60` | Hammering one address |
| `maxAttempts` | `5` | Guessing. On the last wrong guess the code is burned; every wrong guess also calls `BruteForceProtector.failedLogin`. |
| `maxSendsPerEmailPerDay` | `5` | Using the endpoint to fill someone's inbox — the gap a cooldown alone leaves |
| `maxSendsPerIpPerHour` | `10` | A single scripted source. Needs `proxy-headers` configured so the real client IP is visible. Keep it generous: carriers and offices share addresses. |
| `maxSendsPerRealmPerHour` | `500` | A distributed flood, where every per-IP and per-address counter still looks innocent. Over budget the step answers `503 temporarily_unavailable`. This is what protects the SMTP quota and the sending reputation. |
| `emailTemplate` | `code-email.ftl` | — Freemarker template in the realm's email theme |
| `emailSubjectKey` | `emailCodeSubject` | — message key in the email theme's bundle |
| `startTokenHeader` | *(empty)* | When set, a code is only sent if the request carries this header — point it at an App Attest / Play Integrity / reCAPTCHA Enterprise token. |
| `startTokenVerifyUrl` | *(empty)* | Where that token is POSTed as `token`; a JSON body with `"success": false` rejects the send. An unreachable verifier does not block the send. |

A refused send short-circuits before the user lookup and before SMTP, so it costs
a few local cache reads rather than a mail round trip.

## The theme

The browser branch renders `email-code-form.ftl` from the login theme and expects
a small contract:

| The authenticator provides | The template should |
|---|---|
| `codeLength` attribute | size its input(s) |
| `maxAttemptsReached` attribute | disable the input and hide the submit button when true |
| field-scoped errors on `emailCode` | show `messagesPerField.get('emailCode')` |
| — | post the code back as `emailCode`, and offer a submit button named `resend` |

Message keys to define in the login theme's bundle: `emailCodeInvalid`,
`emailCodeExpired`, `emailCodeTooManyAttempts`, `emailCodeResendCooldown`
(takes the remaining seconds as `{0}`) and `emailCodeSendFailed`.

The email itself is the realm's own template, rendered through
`EmailTemplateProvider` with `code`, `ttl`, `username` and `realmName`.

## Build

No local JDK/Maven required — build in Docker:

```bash
docker compose run --rm build
# -> target/keycloak-otp-email.jar  (unit tests and an 80% coverage gate run first)
```

Or with Maven directly: `mvn clean verify`.

## Install

Copy `target/keycloak-otp-email.jar` into Keycloak's `/opt/keycloak/providers/`
(before `kc.sh build` for an optimized image, or the providers dir + restart),
then add `email-otp` to a flow — via the admin console (Authentication → Flows)
or your infrastructure-as-code.

## Test

JUnit 5 + Mockito, with an in-memory store and a hand-advanced clock, so expiry,
cooldowns and window rollover are deterministic. Covers both flows and every
limit; `resteasy-core` is a test-scope dependency only, because `Response.status()`
wants a JAX-RS `RuntimeDelegate` outside a server.

## Compatibility

The Keycloak Authenticator SPI can change across major versions. Bump
`keycloak.version` in `pom.xml` and rebuild when upgrading Keycloak.

## License

Apache 2.0 — see [LICENSE](LICENSE).
