package com.agilefreaks.keycloak.otp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import com.agilefreaks.keycloak.otp.OtpRateGate.Outcome;

class OtpRateGateTest {

  private static final long NOW = 1_700_000_000L;
  private static final String REALM = "test-realm";
  private static final String EMAIL = "visitor@example.com";
  private static final String IP = "203.0.113.7";

  private final InMemoryOtpStore store = new InMemoryOtpStore(NOW);
  private final MutableClock clock = new MutableClock(NOW);

  private OtpRateGate gate(int perEmailPerDay, int perIpPerHour, int perRealmPerHour) {
    return new OtpRateGate(
        store,
        clock,
        new OtpConfig(
            6, 300, 60, 5, perEmailPerDay, perIpPerHour, perRealmPerHour, "", "", "code-email.ftl", "emailCodeSubject"));
  }

  private void advanceSeconds(long seconds) {
    clock.advanceSeconds(seconds);
    store.setNow(clock.epochSeconds());
  }

  @Test
  void allowsTheFirstSend() {
    assertEquals(Outcome.ALLOW, gate(5, 10, 500).reserve(REALM, EMAIL, IP).outcome());
  }

  @Test
  void throttlesTheSixthSendToOneAddressInADay() {
    OtpRateGate gate = gate(5, 100, 1000);

    for (int i = 0; i < 5; i++) {
      assertEquals(Outcome.ALLOW, gate.reserve(REALM, EMAIL, IP).outcome(), "send " + (i + 1));
    }

    OtpRateGate.Decision sixth = gate.reserve(REALM, EMAIL, IP);
    assertEquals(Outcome.THROTTLED, sixth.outcome());
    assertTrue(sixth.retryAfterSeconds() > 0, "throttled responses must say when to retry");
  }

  @Test
  void addressCapDoesNotAffectOtherAddresses() {
    OtpRateGate gate = gate(1, 100, 1000);
    gate.reserve(REALM, EMAIL, IP);

    assertEquals(Outcome.THROTTLED, gate.reserve(REALM, EMAIL, IP).outcome());
    assertEquals(Outcome.ALLOW, gate.reserve(REALM, "someone.else@example.com", IP).outcome());
  }

  @Test
  void addressCapResetsAfterItsWindow() {
    OtpRateGate gate = gate(1, 100, 1000);
    gate.reserve(REALM, EMAIL, IP);
    assertEquals(Outcome.THROTTLED, gate.reserve(REALM, EMAIL, IP).outcome());

    advanceSeconds(OtpRateGate.DAY_SECONDS + 1);

    assertEquals(Outcome.ALLOW, gate.reserve(REALM, EMAIL, IP).outcome());
  }

  @Test
  void throttlesTheEleventhStartFromOneIpInAnHour() {
    OtpRateGate gate = gate(0, 10, 1000);

    for (int i = 0; i < 10; i++) {
      assertEquals(Outcome.ALLOW, gate.reserve(REALM, "user" + i + "@example.com", IP).outcome());
    }

    assertEquals(Outcome.THROTTLED, gate.reserve(REALM, "user11@example.com", IP).outcome());
    assertEquals(
        Outcome.ALLOW, gate.reserve(REALM, "user12@example.com", "198.51.100.4").outcome());
  }

  @Test
  void exhaustsTheRealmBudget() {
    OtpRateGate gate = gate(0, 0, 3);

    for (int i = 0; i < 3; i++) {
      assertEquals(Outcome.ALLOW, gate.reserve(REALM, "user" + i + "@example.com", "10.0.0." + i).outcome());
    }

    // Distributed flood: every per-address and per-IP counter still looks innocent.
    assertEquals(
        Outcome.BUDGET_EXHAUSTED,
        gate.reserve(REALM, "user99@example.com", "10.0.0.99").outcome());
  }

  @Test
  void realmBudgetIsPerRealm() {
    OtpRateGate gate = gate(0, 0, 1);
    gate.reserve(REALM, EMAIL, IP);

    assertEquals(Outcome.BUDGET_EXHAUSTED, gate.reserve(REALM, EMAIL, IP).outcome());
    assertEquals(Outcome.ALLOW, gate.reserve("other-realm", EMAIL, IP).outcome());
  }

  @Test
  void zeroDisablesOnlyThatGuard() {
    OtpRateGate onlyRealm = gate(0, 0, 2);

    assertEquals(Outcome.ALLOW, onlyRealm.reserve(REALM, EMAIL, IP).outcome());
    assertEquals(Outcome.ALLOW, onlyRealm.reserve(REALM, EMAIL, IP).outcome());
    assertEquals(Outcome.BUDGET_EXHAUSTED, onlyRealm.reserve(REALM, EMAIL, IP).outcome());
  }

  @Test
  void allGuardsDisabledNeverRefuses() {
    OtpRateGate open = gate(0, 0, 0);

    for (int i = 0; i < 25; i++) {
      assertEquals(Outcome.ALLOW, open.reserve(REALM, EMAIL, IP).outcome());
    }
  }

  @Test
  void refusalDoesNotConsumeFurtherBudget() {
    OtpRateGate gate = gate(1, 100, 100);
    gate.reserve(REALM, EMAIL, IP);
    gate.reserve(REALM, EMAIL, IP); // refused on the address cap

    // The realm budget must not have been charged for a send that never happened.
    assertEquals(Outcome.ALLOW, gate.reserve(REALM, "another@example.com", IP).outcome());
  }

  @Test
  void missingIpDoesNotBlowUp() {
    assertEquals(Outcome.ALLOW, gate(5, 10, 500).reserve(REALM, EMAIL, null).outcome());
  }
}
