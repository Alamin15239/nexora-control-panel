import assert from "node:assert/strict";
import test from "node:test";
import { hasRequiredRole } from "./roles.guard";

test("checks explicit organization membership roles", () => {
  assert.equal(hasRequiredRole("OWNER", ["OWNER", "ADMIN"]), true);
  assert.equal(hasRequiredRole("MEMBER", ["OWNER", "ADMIN"]), false);
  assert.equal(hasRequiredRole(undefined, ["OWNER"]), false);
  assert.equal(hasRequiredRole("SUPPORT", []), true);
});
