import assert from "node:assert/strict";
import test from "node:test";
import { hashPassword, verifyPassword } from "./password-hash";

test("hashes passwords with unique salts and verifies the correct password", async () => {
  const first = await hashPassword("correct horse battery staple");
  const second = await hashPassword("correct horse battery staple");
  assert.notEqual(first, second);
  assert.equal(await verifyPassword("correct horse battery staple", first), true);
  assert.equal(await verifyPassword("incorrect password", first), false);
});

test("rejects weak passwords and malformed stored hashes", async () => {
  await assert.rejects(() => hashPassword("too-short"));
  assert.equal(await verifyPassword("anything", "not-a-hash"), false);
  assert.equal(await verifyPassword("anything", "scrypt$999$8$1$bad$bad"), false);
});
