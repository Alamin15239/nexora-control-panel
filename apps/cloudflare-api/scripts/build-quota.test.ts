import test from "node:test";
import assert from "node:assert/strict";
import { isBuildQuotaAvailable } from "../src/build-quota.ts";

test("build quota admits usage below the monthly allowance", () => {
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0, buildMinutesLimit: 60 }), true);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 3599, buildMinutesLimit: 60 }), true);
});

test("build quota rejects usage at or above the monthly allowance", () => {
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 3600, buildMinutesLimit: 60 }), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 3601, buildMinutesLimit: 60 }), false);
});

test("build quota treats a zero-minute allowance as exhausted", () => {
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0, buildMinutesLimit: 0 }), false);
});

test("build quota fails closed for missing or malformed snapshots", () => {
  assert.equal(isBuildQuotaAvailable(null), false);
  assert.equal(isBuildQuotaAvailable(undefined), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: -1, buildMinutesLimit: 60 }), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0.5, buildMinutesLimit: 60 }), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0, buildMinutesLimit: -1 }), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0, buildMinutesLimit: 1.5 }), false);
  assert.equal(isBuildQuotaAvailable({ buildSecondsUsed: 0, buildMinutesLimit: 100001 }), false);
});
