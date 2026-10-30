import { test } from "node:test";
import assert from "node:assert/strict";
import { publicKeyOf } from "./crypto";
import {
  checkRevoked, credIdToBytes32, encodeIsRevoked, encodeRevoke, ethAddressOf, recoverRevoker, selector, signRevocation,
} from "./registry";

const ISSUER = "11".repeat(32);
const REGISTRY = "0x" + "ab".repeat(20);
const CRED = "00112233445566778899aabbccddeeff";

test("selector matches the well-known ERC-20 transfer selector", () => {
  assert.equal(selector("transfer(address,uint256)"), "a9059cbb");
});

test("ethAddressOf matches the well-known address of private key 1", () => {
  assert.equal(ethAddressOf(publicKeyOf("00".repeat(31) + "01")), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
});

test("revocation signature recovers to the issuer address, low-S", () => {
  const sig = signRevocation(ISSUER, REGISTRY, 300, CRED);
  assert.ok(sig.v === 27 || sig.v === 28);
  assert.ok(BigInt("0x" + sig.s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n);
  assert.equal(recoverRevoker(sig, REGISTRY, 300, CRED), ethAddressOf(publicKeyOf(ISSUER)));
  // Bound to the chain and the registry: replay elsewhere recovers a different, useless signer.
  assert.notEqual(recoverRevoker(sig, REGISTRY, 324, CRED), ethAddressOf(publicKeyOf(ISSUER)));
});

test("calldata layout", () => {
  const sig = signRevocation(ISSUER, REGISTRY, 300, CRED);
  const data = encodeRevoke(CRED, sig);
  assert.equal(data.length, 2 + 8 + 64 * 4);
  assert.equal(data.slice(10, 74), credIdToBytes32(CRED));
  const call = encodeIsRevoked(ethAddressOf(publicKeyOf(ISSUER)), CRED);
  assert.equal(call.length, 2 + 8 + 64 * 2);
});

test("checkRevoked reads the registry and fails closed", async () => {
  const reply = (result: unknown) => (async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }))) as typeof fetch;
  const pub = publicKeyOf(ISSUER);
  assert.equal(await checkRevoked("http://rpc", REGISTRY, pub, CRED, reply("0x" + "0".repeat(63) + "1")), true);
  assert.equal(await checkRevoked("http://rpc", REGISTRY, pub, CRED, reply("0x" + "0".repeat(64))), false);
  assert.equal(await checkRevoked("http://rpc", REGISTRY, pub, CRED, reply("0x")), null);
  const down = (async () => { throw new Error("offline"); }) as typeof fetch;
  assert.equal(await checkRevoked("http://rpc", REGISTRY, pub, CRED, down), null);
});
