# simple-columnar-transposition-cipher

Enciphers and deciphers text by arranging characters in a grid and reading columns off in a keyword-determined order.

```js
import { encrypt, decrypt, normalizeKey } from 'simple-columnar-transposition-cipher';

const cipher = encrypt('HELLOWORLD', 'KEY'); // 'EOLLHXWDLR'
const plain = decrypt(cipher, 'KEY');          // 'HELLOWORLD'

normalizeKey('ZEBRA'); // 'zebra'
```

## Why this exists

Classical columnar transposition is easy to describe but easy to get subtly wrong: the column ordering rule, the padding rule, and the padding-stripping rule all have to agree between encryption and decryption. This library fixes one interpretation and tests it. The keyword is ranked alphabetically with ties broken by original column position, the plaintext is padded with `X` to a whole number of rows, and decryption strips trailing `X` characters. The trade-off is that a plaintext ending in `X` will lose those characters on decryption; that is the normal behaviour for this cipher and is documented here so it is not a surprise.

## API

- `encrypt(plaintext, key)` returns the ciphertext. The key must be a non-empty string of letters.
- `decrypt(ciphertext, key)` returns the plaintext with trailing `X` padding removed. The ciphertext length must be a multiple of the key length.
- `normalizeKey(key)` lower-cases and validates a keyword.

## The awkward edge

A ciphertext whose length is not a multiple of the key length is rejected by `decrypt` with an error, because it cannot correspond to any rectangular grid produced by `encrypt`. If you truncate or concatenate ciphertexts, decryption will fail rather than silently return nonsense.
