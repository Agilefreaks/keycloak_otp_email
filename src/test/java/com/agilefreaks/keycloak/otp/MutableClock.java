package com.agilefreaks.keycloak.otp;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A clock the tests move by hand, so expiry and cooldown behaviour is deterministic. */
class MutableClock extends Clock {

  private long epochSeconds;

  MutableClock(long epochSeconds) {
    this.epochSeconds = epochSeconds;
  }

  long epochSeconds() {
    return epochSeconds;
  }

  void advanceSeconds(long seconds) {
    epochSeconds += seconds;
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }

  @Override
  public Instant instant() {
    return Instant.ofEpochSecond(epochSeconds);
  }
}
