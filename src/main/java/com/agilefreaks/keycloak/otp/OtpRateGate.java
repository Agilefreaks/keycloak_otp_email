package com.agilefreaks.keycloak.otp;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * The send-rate guards: per address per day, per client IP per hour, and a realm-wide hourly
 * budget. {@link #reserve} consumes as well as checks, so a send that later fails still costs
 * budget — failing sends are what an abuser produces.
 */
public class OtpRateGate {

  static final long DAY_SECONDS = 86_400L;
  static final long HOUR_SECONDS = 3_600L;

  private final OtpStore store;
  private final Clock clock;
  private final OtpConfig config;

  public OtpRateGate(OtpStore store, Clock clock, OtpConfig config) {
    this.store = store;
    this.clock = clock;
    this.config = config;
  }

  public Decision reserve(String realmId, String email, String ip) {
    long now = clock.instant().getEpochSecond();

    List<Guard> guards = new ArrayList<>(3);
    if (config.maxSendsPerEmailPerDay() > 0) {
      guards.add(
          new Guard(
              OtpKeys.emailDay(realmId, email),
              DAY_SECONDS,
              config.maxSendsPerEmailPerDay(),
              Limit.EMAIL_DAY));
    }
    if (config.maxSendsPerIpPerHour() > 0 && ip != null && !ip.isBlank()) {
      guards.add(
          new Guard(
              OtpKeys.ipHour(realmId, ip),
              HOUR_SECONDS,
              config.maxSendsPerIpPerHour(),
              Limit.IP_HOUR));
    }
    if (config.maxSendsPerRealmPerHour() > 0) {
      guards.add(
          new Guard(
              OtpKeys.realmHour(realmId),
              HOUR_SECONDS,
              config.maxSendsPerRealmPerHour(),
              Limit.REALM_HOUR));
    }

    // Every guard is read before any is written, so a refusal never charges the ones that passed.
    List<CounterRecord> charged = new ArrayList<>(guards.size());
    for (Guard guard : guards) {
      CounterRecord current = currentCount(guard, now);
      if (current.count() >= guard.max()) {
        long elapsed = now - current.windowStartEpochSeconds();
        return new Decision(guard.limit(), Math.max(guard.windowSeconds() - elapsed, 1));
      }
      charged.add(current.increment());
    }

    for (int i = 0; i < guards.size(); i++) {
      store.put(guards.get(i).key(), charged.get(i).toNotes(), guards.get(i).windowSeconds());
    }
    return new Decision(Limit.NONE, 0);
  }

  private CounterRecord currentCount(Guard guard, long now) {
    return store
        .get(guard.key())
        .flatMap(CounterRecord::fromNotes)
        .filter(record -> !record.isExpired(now, guard.windowSeconds()))
        .orElseGet(() -> new CounterRecord(0, now));
  }

  private record Guard(String key, long windowSeconds, int max, Limit limit) {}

  public enum Outcome {
    ALLOW,
    THROTTLED,
    BUDGET_EXHAUSTED
  }

  public enum Limit {
    NONE(Outcome.ALLOW, null),
    EMAIL_DAY(Outcome.THROTTLED, "throttled_email"),
    IP_HOUR(Outcome.THROTTLED, "throttled_ip"),
    REALM_HOUR(Outcome.BUDGET_EXHAUSTED, "realm_budget");

    final Outcome outcome;
    public final String detail;

    Limit(Outcome outcome, String detail) {
      this.outcome = outcome;
      this.detail = detail;
    }
  }

  public record Decision(Limit limit, long retryAfterSeconds) {

    public Outcome outcome() {
      return limit.outcome;
    }

    public boolean allowed() {
      return limit == Limit.NONE;
    }
  }
}
