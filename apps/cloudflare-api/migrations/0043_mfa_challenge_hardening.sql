-- MFA challenge hardening: per-challenge attempt limiting and TOTP replay protection.
--
-- Background:
--   The login endpoint (post password verification) creates an mfa_challenges
--   row and the dashboard submits the user's 6-digit code to
--   /v1/auth/login/mfa. Before this migration the challenge row only tracked
--   expiry + consumed_at, which left two gaps:
--
--     1. No brute-force protection. A challengeId is a 128-bit UUID so it is
--        not guessable, but if an attacker obtains one (logs, referrer, MITM
--        on a non-TLS dev environment) they could submit 1,000,000 codes
--        within the 10-minute challenge window until they hit the single
--        valid 30-second TOTP. Adding failed_attempts + a cap at 5 invalid
--        submissions per challenge makes brute force useless: after 5 wrong
--        codes the challenge is locked and the user must restart login.
--
--     2. No TOTP replay protection. A valid 6-digit code can be submitted
--        twice within the same 30-second TOTP period. Without tracking the
--        last successful TOTP counter on the factor, two parallel submissions
--        with the same code could both consume the challenge. The atomic
--        UPDATE on consumed_at prevents the second from issuing a session,
--        but storing last_used_totp_period on mfa_factors lets the verify
--        step reject any code whose TOTP counter is <= the last successful
--        one, eliminating replay even within the same window.
--
-- Schema additions:
--   mfa_challenges.failed_attempts  INTEGER NOT NULL DEFAULT 0
--     - Incremented on every invalid code submission.
--     - The verify endpoint refuses to issue a session once this reaches 5.
--   mfa_factors.last_used_totp_period INTEGER NULL
--     - The TOTP counter (floor(timestamp/30)) of the last successful
--       verification. NULL until the first successful verify after this
--       migration ships. The verify step rejects codes whose counter is
--       <= this value (replay prevention within the same 30s window and
--       against repeated submissions of the same code).
--   mfa_challenges.locked_at TEXT NULL
--     - Timestamp the challenge was locked by the attempt cap. The verify
--       endpoint sets this when failed_attempts reaches the cap so the
--       dashboard can distinguish "expired" from "locked" in the error
--       message. Audit-logged as auth.login_mfa_locked.
--
-- All three columns are additive. Existing rows get the NOT NULL defaults
-- and NULL for the new nullable columns. No data is rewritten; no index is
-- dropped. SQLite does not support ADD COLUMN IF NOT EXISTS, so each ALTER
-- is a one-shot statement; the migration tracker ensures it runs exactly once.

ALTER TABLE mfa_challenges ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mfa_challenges ADD COLUMN locked_at TEXT;
ALTER TABLE mfa_factors ADD COLUMN last_used_totp_period INTEGER;

-- Index for the locked-challenge diagnostic and for the operator dashboard
-- that surfaces locked challenges during incident response.
CREATE INDEX IF NOT EXISTS mfa_challenges_locked_idx
  ON mfa_challenges(locked_at)
  WHERE locked_at IS NOT NULL;
