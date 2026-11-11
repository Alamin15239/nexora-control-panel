import test from "node:test";
import assert from "node:assert/strict";
import { addMonthsClamped } from "../src/index.ts";

// ---------------------------------------------------------------------------
// backup-scheduler-recurrence.test.ts
//
// Fix 3 — calendar-month recurrence with end-of-month clamping.
//
// The backup scheduler computes the next run time for a monthly schedule by
// adding one calendar month to the current time. JavaScript's built-in
// `Date.setUTCMonth(current + 1)` does NOT clamp to end-of-month — Jan 31
// + 1 month overflows to March 3 (Feb 3 + 28 days). That is wrong for a
// monthly schedule: a customer who sets a monthly backup on Jan 31 should
// see the next run on Feb 28 (or Feb 29 in a leap year), not March 3.
//
// `addMonthsClamped(from, months)` computes the correct target month and
// clamps the day to the last day of that month. All arithmetic is in UTC
// to avoid daylight-saving drift — a monthly schedule that fires at 02:00
// UTC on Jan 31 should next fire at 02:00 UTC on Feb 28, not at 03:00 UTC
// because DST kicked in. UTC has no DST.
//
// These tests cover:
//   - Jan 29, 30, 31 → Feb 28 (non-leap year) or Feb 29 (leap year).
//   - Feb 29 → March 29 (leap-year anchor).
//   - Month-end recurrence across multiple months (Jan 31 → Feb 28 →
//     March 28 — wait, that's wrong; the clamp should re-expand on the
//     next iteration. We test the underlying primitive, not the iteration
//     loop, so each call clamps independently to the target month.)
//   - Cross-year boundary (Dec 31 → Jan 31).
//   - Hour/minute preservation across the clamp.
//   - Daily and weekly use fixed-length intervals (not tested here —
//     they're just `now + N ms`).
// ---------------------------------------------------------------------------

test("addMonthsClamped: Jan 31 + 1 month = Feb 28 in a non-leap year (2025)", () => {
  const jan31 = new Date(Date.UTC(2025, 0, 31, 2, 0, 0));
  const result = addMonthsClamped(jan31, 1);
  assert.equal(result.getUTCFullYear(), 2025);
  assert.equal(result.getUTCMonth(), 1); // February (0-indexed)
  assert.equal(result.getUTCDate(), 28);
  assert.equal(result.getUTCHours(), 2); // hour preserved
});

test("addMonthsClamped: Jan 31 + 1 month = Feb 29 in a leap year (2024)", () => {
  const jan31 = new Date(Date.UTC(2024, 0, 31, 2, 0, 0));
  const result = addMonthsClamped(jan31, 1);
  assert.equal(result.getUTCFullYear(), 2024);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 29);
  assert.equal(result.getUTCHours(), 2);
});

test("addMonthsClamped: Jan 29 + 1 month = Feb 28 (non-leap year)", () => {
  const jan29 = new Date(Date.UTC(2025, 0, 29, 0, 0, 0));
  const result = addMonthsClamped(jan29, 1);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 28);
});

test("addMonthsClamped: Jan 30 + 1 month = Feb 28 (non-leap year)", () => {
  const jan30 = new Date(Date.UTC(2025, 0, 30, 0, 0, 0));
  const result = addMonthsClamped(jan30, 1);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 28);
});

test("addMonthsClamped: Feb 29 + 1 month = March 29 (leap-year anchor)", () => {
  const feb29 = new Date(Date.UTC(2024, 1, 29, 0, 0, 0));
  const result = addMonthsClamped(feb29, 1);
  assert.equal(result.getUTCMonth(), 2); // March
  assert.equal(result.getUTCDate(), 29);
});

test("addMonthsClamped: March 31 + 1 month = April 30 (30-day month)", () => {
  const mar31 = new Date(Date.UTC(2025, 2, 31, 12, 30, 0));
  const result = addMonthsClamped(mar31, 1);
  assert.equal(result.getUTCMonth(), 3); // April
  assert.equal(result.getUTCDate(), 30);
  assert.equal(result.getUTCHours(), 12);
  assert.equal(result.getUTCMinutes(), 30);
});

test("addMonthsClamped: Dec 31 + 1 month = Jan 31 (cross-year boundary)", () => {
  const dec31 = new Date(Date.UTC(2025, 11, 31, 0, 0, 0));
  const result = addMonthsClamped(dec31, 1);
  assert.equal(result.getUTCFullYear(), 2026);
  assert.equal(result.getUTCMonth(), 0); // January
  assert.equal(result.getUTCDate(), 31);
});

test("addMonthsClamped: Aug 31 + 1 month = Sept 30 (30-day September)", () => {
  // September has 30 days. Aug 31 + 1 month should clamp to Sept 30, not
  // October 1.
  const aug31 = new Date(Date.UTC(2025, 7, 31, 0, 0, 0));
  const result = addMonthsClamped(aug31, 1);
  assert.equal(result.getUTCMonth(), 8); // September
  assert.equal(result.getUTCDate(), 30);
});

test("addMonthsClamped: day <= 28 never clamps (mid-month anchor)", () => {
  // A schedule anchored on the 15th should always land on the 15th next
  // month, regardless of month length.
  for (let month = 0; month < 12; month++) {
    const anchor = new Date(Date.UTC(2025, month, 15, 9, 0, 0));
    const result = addMonthsClamped(anchor, 1);
    assert.equal(result.getUTCDate(), 15, `month ${month + 1}: day should be 15`);
    assert.equal(result.getUTCHours(), 9);
  }
});

test("addMonthsClamped: preserves UTC across the clamp (no DST drift)", () => {
  // A monthly schedule at 02:00 UTC on Jan 31 should next fire at 02:00
  // UTC on Feb 28. UTC has no DST so the hour is stable.
  const jan31_2am = new Date(Date.UTC(2025, 0, 31, 2, 0, 0));
  const result = addMonthsClamped(jan31_2am, 1);
  assert.equal(result.getUTCHours(), 2);
  assert.equal(result.getUTCMinutes(), 0);
  assert.equal(result.getUTCSeconds(), 0);
});

test("addMonthsClamped: +12 months = same month/day next year", () => {
  const anchor = new Date(Date.UTC(2025, 5, 15, 0, 0, 0)); // June 15
  const result = addMonthsClamped(anchor, 12);
  assert.equal(result.getUTCFullYear(), 2026);
  assert.equal(result.getUTCMonth(), 5);
  assert.equal(result.getUTCDate(), 15);
});

test("addMonthsClamped: Feb 29 + 12 months = Feb 28 next year (non-leap)", () => {
  // Leap-day anchor: +12 months lands on Feb 28 of a non-leap year.
  const feb29 = new Date(Date.UTC(2024, 1, 29, 0, 0, 0));
  const result = addMonthsClamped(feb29, 12);
  assert.equal(result.getUTCFullYear(), 2025);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 28);
});
