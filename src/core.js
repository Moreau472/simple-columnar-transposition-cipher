/**
 * Columnar transposition cipher.
 *
 * The plaintext is written row by row into a grid whose width equals the
 * keyword length. The keyword's letters are ranked alphabetically (ties broken
 * by original position) to produce the column read order. Reading columns in
 * that order produces the ciphertext.
 *
 * Padding: when the plaintext length is not a multiple of the keyword length,
 * the final row is padded with the letter X. The ciphertext therefore always
 * has length ceil(n / k) * k. Decryption strips trailing X padding.
 *
 * This design was chosen because it keeps the grid rectangular, which makes
 * both encryption and decryption simple and unambiguous. The cost is that
 * plaintexts ending in X may lose those trailing X characters on decryption;
 * that is the standard trade-off for this cipher.
 */

/**
 * Validate and normalize a keyword.
 *
 * The keyword must be a non-empty string of letters. Case is ignored and the
 * result is always lower-case. Rejecting non-letters keeps the ranking step
 * unambiguous and avoids locale-dependent sorting.
 *
 * @param {string} key
 * @returns {string} lower-case keyword
 * @throws {TypeError} if key is not a string
 * @throws {Error} if key is empty or contains non-letters
 */
export function normalizeKey(key) {
  if (typeof key !== 'string') {
    throw new TypeError('key must be a string');
  }
  if (key.length === 0) {
    throw new Error('key must not be empty');
  }
  const lower = key.toLowerCase();
  if (!/^[a-z]+$/.test(lower)) {
    throw new Error('key must contain only letters');
  }
  return lower;
}

/**
 * Compute the column read order for a keyword.
 *
 * Columns are ranked by the keyword letter at that position. Equal letters are
 * ordered by their original column index so the result is deterministic.
 *
 * @param {string} key lower-case keyword
 * @returns {number[]} column indices in read order
 */
function columnOrder(key) {
  const indexed = [];
  for (let i = 0; i < key.length; i++) {
    indexed.push({ ch: key[i], index: i });
  }
  indexed.sort((a, b) => {
    if (a.ch < b.ch) return -1;
    if (a.ch > b.ch) return 1;
    return a.index - b.index;
  });
  return indexed.map((entry) => entry.index);
}

/**
 * Encipher text with a keyword.
 *
 * @param {string} plaintext
 * @param {string} key
 * @returns {string} ciphertext
 * @throws {TypeError} if plaintext is not a string
 */
export function encrypt(plaintext, key) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('plaintext must be a string');
  }
  const normalized = normalizeKey(key);
  const width = normalized.length;
  const height = Math.ceil(plaintext.length / width);
  const paddedLength = height * width;

  // Pad with X so every column has the same number of characters.
  const padded = plaintext.padEnd(paddedLength, 'X');

  const order = columnOrder(normalized);
  let output = '';
  for (const col of order) {
    for (let row = 0; row < height; row++) {
      output += padded[row * width + col];
    }
  }
  return output;
}

/**
 * Decipher text with a keyword.
 *
 * @param {string} ciphertext
 * @param {string} key
 * @returns {string} plaintext with trailing X padding removed
 * @throws {TypeError} if ciphertext is not a string
 */
export function decrypt(ciphertext, key) {
  if (typeof ciphertext !== 'string') {
    throw new TypeError('ciphertext must be a string');
  }
  const normalized = normalizeKey(key);
  const width = normalized.length;
  const length = ciphertext.length;

  // A ciphertext of length zero decrypts to an empty string; there is no grid.
  if (length === 0) {
    return '';
  }

  // The ciphertext must be a whole number of complete rows.
  if (length % width !== 0) {
    throw new Error('ciphertext length must be a multiple of key length');
  }

  const height = length / width;
  const order = columnOrder(normalized);

  // Reconstruct the grid by placing each ciphertext block into its column.
  const grid = new Array(length);
  let pos = 0;
  for (const col of order) {
    for (let row = 0; row < height; row++) {
      grid[row * width + col] = ciphertext[pos];
      pos += 1;
    }
  }

  // Read row by row, then strip the X padding from the end.
  let plain = grid.join('');
  plain = plain.replace(/X+$/, '');
  return plain;
}
