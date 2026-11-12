export type BuildQuotaSnapshot = {
  buildSecondsUsed: number;
  buildMinutesLimit: number;
};

/**
 * New builds are admitted only while measured usage remains below the plan's
 * monthly allowance. Invalid or missing quota data fails closed.
 *
 * This is a pre-dispatch gate; it does not terminate a build already running.
 */
export function isBuildQuotaAvailable(snapshot: BuildQuotaSnapshot | null | undefined): boolean {
  if (!snapshot || typeof snapshot !== "object") return false;
  const { buildSecondsUsed, buildMinutesLimit } = snapshot;
  if (!Number.isSafeInteger(buildSecondsUsed) || buildSecondsUsed < 0 ||
      !Number.isSafeInteger(buildMinutesLimit) || buildMinutesLimit < 0 ||
      buildMinutesLimit > 100_000) {
    return false;
  }
  return buildSecondsUsed < buildMinutesLimit * 60;
}
