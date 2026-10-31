import test from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, normalizeKey } from '../src/index.js';

test('normalizeKey lower-cases and validates', () => {
  assert.equal(normalizeKey('ZEBRA'), 'zebra');
  assert.equal(normalizeKey('a'), 'a');
  assert.throws(() => normalizeKey(''), /empty/);
  assert.throws(() => normalizeKey('a b'), /letters/);
  assert.throws(() => normalizeKey('123'), /letters/);
  assert.throws(() => normalizeKey(null), TypeError);
});

test('encrypt pads the final row with X', () => {
  assert.equal(encrypt('HELLO', 'KEY'), 'EOHLLX');
});

test('round trip for a plaintext that is a whole number of rows', () => {
  const plain = 'ATTACKATDAWN';
  const cipher = encrypt(plain, 'ZEBRA');
  assert.equal(decrypt(cipher, 'ZEBRA'), plain);
});

test('round trip for a plaintext that needs padding', () => {
  const plain = 'HELLOWORLD';
  const cipher = encrypt(plain, 'KEY');
  assert.equal(decrypt(cipher, 'KEY'), plain);
});

test('empty plaintext encrypts to empty and decrypts back', () => {
  assert.equal(encrypt('', 'KEY'), '');
  assert.equal(decrypt('', 'KEY'), '');
});

test('decrypt rejects a ciphertext whose length is not a multiple of the key', () => {
  assert.throws(() => decrypt('ABCD', 'KEY'), /multiple/);
});

test('encrypt rejects a non-string plaintext', () => {
  assert.throws(() => encrypt(42, 'KEY'), TypeError);
});

test('decrypt rejects a non-string ciphertext', () => {
  assert.throws(() => decrypt(42, 'KEY'), TypeError);
});

test('equal letters in the key are ordered by original position', () => {
  // Both A's rank equally; the left one is read first.
  assert.equal(encrypt('ABCD', 'AA'), 'ACBD');
});

test('trailing X padding is stripped on decryption', () => {
  const plain = 'AB';
  const cipher = encrypt(plain, 'KEY');
  assert.equal(cipher.length, 3);
  assert.equal(decrypt(cipher, 'KEY'), plain);
});
