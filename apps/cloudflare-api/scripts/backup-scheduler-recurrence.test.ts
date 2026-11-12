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

// ---------------------------------------------------------------------------
// Stable calendar anchor tests (Fix 2, this batch).
//
// The previous addMonthsClamped computed the next run from the execution
// date, causing permanent drift: Jan 31 → Feb 28 → March 28 → April 28.
// nextMonthlyRunFromAnchor computes from a stable anchor day instead:
// Jan 31 (anchor=31) → Feb 28 (clamped) → March 31 (re-expanded) → April 30.
// ---------------------------------------------------------------------------

import { nextMonthlyRunFromAnchor } from "../src/index.ts";

test("nextMonthlyRunFromAnchor: Jan 31 anchor → Feb 28 → March 31 (no drift)", () => {
  // Anchor day = 31. Start from Jan 31.
  const jan31 = new Date(Date.UTC(2025, 0, 31, 2, 0, 0));
  const feb28 = nextMonthlyRunFromAnchor(31, jan31, 1);
  assert.equal(feb28.getUTCMonth(), 1); // Feb
  assert.equal(feb28.getUTCDate(), 28); // clamped
  // CRITICAL: the next run after Feb 28 must be March 31 (re-expanded),
  // NOT March 28 (which is what the old drift-prone code would produce).
  const march31 = nextMonthlyRunFromAnchor(31, feb28, 1);
  assert.equal(march31.getUTCMonth(), 2); // March
  assert.equal(march31.getUTCDate(), 31); // re-expanded from anchor
  // Continue: March 31 → April 30 (clamped, April has 30 days)
  const april30 = nextMonthlyRunFromAnchor(31, march31, 1);
  assert.equal(april30.getUTCMonth(), 3); // April
  assert.equal(april30.getUTCDate(), 30); // clamped
  // April 30 → May 31 (re-expanded)
  const may31 = nextMonthlyRunFromAnchor(31, april30, 1);
  assert.equal(may31.getUTCMonth(), 4); // May
  assert.equal(may31.getUTCDate(), 31);
});

test("nextMonthlyRunFromAnchor: Jan 31 → Feb 29 → March 31 in a leap year", () => {
  const jan31_2024 = new Date(Date.UTC(2024, 0, 31, 0, 0, 0));
  const feb29 = nextMonthlyRunFromAnchor(31, jan31_2024, 1);
  assert.equal(feb29.getUTCMonth(), 1);
  assert.equal(feb29.getUTCDate(), 29); // leap year
  const march31 = nextMonthlyRunFromAnchor(31, feb29, 1);
  assert.equal(march31.getUTCMonth(), 2);
  assert.equal(march31.getUTCDate(), 31); // re-expanded
});

test("nextMonthlyRunFromAnchor: Feb 29 anchor → Feb 28 in non-leap year", () => {
  // Anchor day = 29. Start from Feb 29, 2024 (leap year).
  const feb29_2024 = new Date(Date.UTC(2024, 1, 29, 12, 0, 0));
  // +12 months → Feb 28, 2025 (non-leap year, clamped from 29)
  const feb28_2025 = nextMonthlyRunFromAnchor(29, feb29_2024, 12);
  assert.equal(feb28_2025.getUTCFullYear(), 2025);
  assert.equal(feb28_2025.getUTCMonth(), 1);
  assert.equal(feb28_2025.getUTCDate(), 28);
});

test("nextMonthlyRunFromAnchor: March 30 → April 30 → May 30 (mid-month anchor)", () => {
  const mar30 = new Date(Date.UTC(2025, 2, 30, 9, 0, 0));
  const apr30 = nextMonthlyRunFromAnchor(30, mar30, 1);
  assert.equal(apr30.getUTCMonth(), 3);
  assert.equal(apr30.getUTCDate(), 30);
  const may30 = nextMonthlyRunFromAnchor(30, apr30, 1);
  assert.equal(may30.getUTCMonth(), 4);
  assert.equal(may30.getUTCDate(), 30); // no drift
});

test("nextMonthlyRunFromAnchor: Dec 31 → Jan 31 (cross-year)", () => {
  const dec31_2025 = new Date(Date.UTC(2025, 11, 31, 0, 0, 0));
  const jan31_2026 = nextMonthlyRunFromAnchor(31, dec31_2025, 1);
  assert.equal(jan31_2026.getUTCFullYear(), 2026);
  assert.equal(jan31_2026.getUTCMonth(), 0);
  assert.equal(jan31_2026.getUTCDate(), 31);
});

test("nextMonthlyRunFromAnchor: preserves UTC hour across clamped and re-expanded months", () => {
  const jan31_2am = new Date(Date.UTC(2025, 0, 31, 2, 30, 0));
  const feb28 = nextMonthlyRunFromAnchor(31, jan31_2am, 1);
  assert.equal(feb28.getUTCHours(), 2);
  assert.equal(feb28.getUTCMinutes(), 30);
  const march31 = nextMonthlyRunFromAnchor(31, feb28, 1);
  assert.equal(march31.getUTCHours(), 2);
  assert.equal(march31.getUTCMinutes(), 30);
});

test("nextMonthlyRunFromAnchor: delayed execution does not cause drift when scheduler passes original nextRunAt", () => {
  // Simulate: scheduler was supposed to fire on Jan 31 but actually fired
  // on Feb 2 (2 days late). The anchor is 31. The SCHEDULER should pass
  // the original next_run_at (Jan 31) as the 'from' date, not the
  // execution date (Feb 2). This way the next run is computed from the
  // original intended date:
  //   nextMonthlyRunFromAnchor(31, jan31, 1) = Feb 28 (clamped)
  // NOT from the execution date:
  //   nextMonthlyRunFromAnchor(31, feb2, 1) = March 31 (wrong — skips Feb)
  const jan31_original = new Date(Date.UTC(2025, 0, 31, 2, 0, 0));
  const nextRun = nextMonthlyRunFromAnchor(31, jan31_original, 1);
  assert.equal(nextRun.getUTCMonth(), 1); // Feb
  assert.equal(nextRun.getUTCDate(), 28); // clamped from anchor 31
  // Verify the WRONG approach (computing from execution date) would skip Feb:
  const feb2_late = new Date(Date.UTC(2025, 1, 2, 2, 0, 0));
  const wrongNextRun = nextMonthlyRunFromAnchor(31, feb2_late, 1);
  assert.equal(wrongNextRun.getUTCMonth(), 2); // March — skips Feb entirely
  assert.equal(wrongNextRun.getUTCDate(), 31);
});

test("nextMonthlyRunFromAnchor: null anchor falls back to addMonthsClamped", () => {
  const jan31 = new Date(Date.UTC(2025, 0, 31, 0, 0, 0));
  const result = nextMonthlyRunFromAnchor(null, jan31, 1);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 28);
});

test("nextMonthlyRunFromAnchor: invalid anchor (0) falls back", () => {
  const jan31 = new Date(Date.UTC(2025, 0, 31, 0, 0, 0));
  const result = nextMonthlyRunFromAnchor(0, jan31, 1);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 28);
});

test("nextMonthlyRunFromAnchor: invalid anchor (32) falls back", () => {
  const jan15 = new Date(Date.UTC(2025, 0, 15, 0, 0, 0));
  const result = nextMonthlyRunFromAnchor(32, jan15, 1);
  assert.equal(result.getUTCMonth(), 1);
  assert.equal(result.getUTCDate(), 15);
});

test("nextMonthlyRunFromAnchor: last-day-of-month anchor (31) chains correctly across 6 months", () => {
  // Verify the full chain: Jan 31 → Feb 28 → March 31 → April 30 →
  // May 31 → June 30 → July 31. No drift at any step.
  let current = new Date(Date.UTC(2025, 0, 31, 0, 0, 0));
  const expected = [
    [1, 28], // Feb 28
    [2, 31], // March 31
    [3, 30], // April 30
    [4, 31], // May 31
    [5, 30], // June 30
    [6, 31], // July 31
  ];
  for (const [month, day] of expected) {
    current = nextMonthlyRunFromAnchor(31, current, 1);
    assert.equal(current.getUTCMonth(), month, `month ${month}: expected ${day}, got ${current.getUTCDate()}`);
    assert.equal(current.getUTCDate(), day, `day mismatch for month ${month}`);
  }
});
