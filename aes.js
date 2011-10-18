/*global console */

/**
 * The Advanced Encryption Standard (AES) specifies a FIPS-approved
 * cryptographic algorithm that can be used to protect electronic data.
 * The AES algorithm is a symmetric block cipher that can encrypt (encipher)
 * and decrypt (decipher) information. Encryption converts data to an
 * unintelligible form called ciphertext; decrypting the ciphertext converts
 * the data back into its original form, called plaintext.
 */
var AES = {};

(function() {
  "use strict";

  /**
   * Non-linear substitution table used in several byte substitution
   * transformations and in the Key Expansion routine to perform a one-for-one
   * substitution of a byte value.
   */
  const sBox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

  /**
   * The round constant word array.
   */
  const rCon = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]];

  /**
   * The inverse S-box.
   */
  const inv_sBox = (function() {
    for (var i = 0, box = []; i < 256; i++) {
      box[sBox[i]] = i;
    }
    return box;
  })();

  /**
   * The block size.
   */
  const Nb = 4;

  /**
   * The SubBytes() transformation is a non-linear byte substitution that
   * operates independently on each byte of the State using a substitution
   * table (S-box).
   */
  function subBytes(_s, box) {                                       // [5.1.1]
    box = box || sBox;

    var r, c;

    for (r = 0; r < 4; r++) {
      for (c = 0; c < Nb; c++) {
        _s[r][c] = box[_s[r][c]];
      }
    }
    return _s;
  }

  /**
   * InvSubBytes() is the inverse of the byte substitution transformation,
   * in which the inverse S- box is applied to each byte of the State.
   */
  function invSubBytes(_s) {                                         // [5.3.2]
    return subBytes(_s, inv_sBox);
  }

  /**
   * In the ShiftRows() transformation, the bytes in the last three rows of the
   * State are cyclically shifted over different numbers of bytes (offsets).
   * The first row, r = 0, is not shifted.
   */
  function shiftRows(_s, inverse) {                                  // [5.1.2]
    var r, c, t = [];

    // the shift value shift(r, Nb) depends on the row number
    function shift(_r, _Nb) {
      if (_Nb === 4) {
        switch (_r) {
          case 1: return 1; // shift(1, 4) = 1;
          case 2: return 2; // shift(2, 4) = 2;
          case 3: return 3; // shift(3, 4) = 3;
        }
      }
    }

    for (r = 1; r < 4; r++) {
      for (c = 0; c < Nb; c++) {
        if (!inverse) {
          t[c] = _s[(c + shift(r, Nb)) % Nb][r];
        } else {
          t[(c + shift(r, Nb)) % Nb] = _s[c][r];
        }
      }
      for (c = 0; c < Nb; c++) {
        _s[c][r] = t[c];
      }
    }
    return _s;
  }

  /**
   * InvShiftRows() is the inverse of the ShiftRows() transformation. The bytes
   * in the last three rows of the State are cyclically shifted over different
   * numbers of bytes (offsets). The first row, r = 0, is not shifted.
   * The bottom three rows are cyclically shifted by Nb − shift(r, Nb) bytes,
   * where the shift value shift(r, Nb) depends on the row number.
   */
  function invShiftRows(_s) {                                        // [5.3.1]
    return shiftRows(_s, -1);
  }

  /**
   * The MixColumns() transformation operates on the State column-by-column,
   * treating each column as a four-term polynomial. The columns are considered
   * as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a fixed
   * polynomial {03}*x3 + {01}*x2 + {01}*x + {02}.
   */
  function mixColumns(_s, inverse) {                                 // [5.1.3]
    var c, i, temp, fact;

    if (!inverse) {
      fact = [[0x02, 0x03, 0x01, 0x01],
              [0x01, 0x02, 0x03, 0x01],
              [0x01, 0x01, 0x02, 0x03],
              [0x03, 0x01, 0x01, 0x02]];
    } else {
      fact = [[0x0e, 0x0b, 0x0d, 0x09],
              [0x09, 0x0e, 0x0b, 0x0d],
              [0x0d, 0x09, 0x0e, 0x0b],
              [0x0b, 0x0d, 0x09, 0x0e]];
    }

    for (c = 0; c < Nb; c++) {
      temp = _s[c].AES_cloneWord();

      for (i = 0; i < 4; i++) {
        _s[c][i] = temp[0].AES_mulPoly(fact[i][0]) ^
                   temp[1].AES_mulPoly(fact[i][1]) ^
                   temp[2].AES_mulPoly(fact[i][2]) ^
                   temp[3].AES_mulPoly(fact[i][3]);
      }
    }
    return _s;
  }

  /**
   * InvMixColumns() is the inverse of the MixColumns() transformation.
   * InvMixColumns() operates on the State column-by-column, treating each
   * column as a four-term polynomial. The columns are considered as
   * polynomials over GF(2^8) and multiplied modulo x4 + 1 with a fixed
   * polynomial {0b}*x3 + {0d}*x2 + {09}*x + {0e}.
   */
  function invMixColumns(_s) {                                       // [5.3.3]
    return mixColumns(_s, -1);
  }

  /**
   * In the AddRoundKey() transformation, a Round Key is added to the State by a
   * simple bitwise AES_xorWord operation. Each Round Key consists of Nb words from the
   * key schedule.
   */
  function addRoundKey(_s, _w, _round) {                             // [5.1.4]
    var r, c;

    for (r = 0; r < 4; r++) {
      for (c = 0; c < Nb; c++) {
        _s[c][r] ^= _w[_round * Nb + c][r];
      }
    }
    return _s;
  }

  /**
   * The function RotWord() takes a word [a0,a1,a2,a3] as input, performs a
   * cyclic permutation, and returns the word [a1,a2,a3,a0].
   */
  function rotWord(_w) {                                             // [5.2]
    for (var i = 0, temp = _w[0]; i < 3; i++) {
      _w[i] = _w[i + 1];
    } _w[3] = temp;

    return _w;
  }

  /**
   * SubWord() is a function that takes a four-byte input word and applies the
   * S-box to each of the four bytes to produce an output word.
   */
  function subWord(_w) {                                             // [5.2]
    for (var i = 0; i < 4; i++) {
      _w[i] = sBox[_w[i]];
    }
    return _w;
  }

  /**
   * The AES algorithm takes the Cipher Key, K, and performs a Key Expansion
   * routine to generate a key schedule. The Key Expansion generates a total of
   * Nb (Nr + 1) words: the algorithm requires an initial set of Nb words, and
   * each of the Nr rounds requires Nb words of key data. The resulting key
   * schedule consists of a linear array of 4-byte words, denoted [wi], with i
   * in the range 0 ≤ i < Nb(Nr + 1).
   */
  function keyExpansion(_key, _w) {                                  // [5.2]
    _w = _w || [];

    var Nk = _key.length / Nb, // key length: 4/6/8 for 128/192/256-bit keys
        Nr = Nk + 6;           // rounds: 10/12/14 for 128/192/256-bit keys

    (function(i) {
      while (i < Nk) {
        _w[i] = [_key[4 * i], _key[4 * i + 1], _key[4 * i + 2], _key[4 * i + 3]];
        i++;
      }
    })(0);

    (function(i, temp) {
      while (i < Nb * (Nr + 1)) {
        temp = _w[i - 1].AES_cloneWord();

        if (i % Nk === 0) {
          temp = subWord(rotWord(temp)).AES_xorWord(rCon[i / Nk]);
        } else if (Nk > 6 && i % Nk === 4) {
          temp = subWord(temp);
        }

        _w[i] = _w[i - Nk].AES_xorWord(temp);
        i++;
      }
    })(Nk);

    return _w;
  }

  /**
   * Each Round Key consists of Nb words from the key schedule.
   */
  function roundKey(_w, _round) {
    return _w.slice(_round * 4, _round * 4 + 4);
  }

  /**
   * At the start of the Cipher, the input is copied to the State array.
   * After an initial Round Key addition, the State array is transformed by
   * implementing a round function 10, 12, or 14 times (depending on the key
   * length), with the final round differing slightly from the first Nr − 1
   * rounds. The final State is then copied to the output.
   */
  function cipher(_in, _out, _w) {                                   // [5.1]
    var Nr = _w.length / Nb - 1; // rounds: 10/12/14 for 128/192/256-bit keys

    return (function(state) {
      var i, round;

      // copy input to the state array using the conventions in [3.4]
      for (i = 0; i < 4 * Nb; i++) {
        state[Math.floor(i / 4)][i % 4] = _in[i];
      }

      // initial round key addition
      state = addRoundKey(state, _w, 0);

      // 9, 11 or 13 rounds
      for (round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, _w, round);
      }

      // final round
      subBytes(state);
      shiftRows(state);
      addRoundKey(state, _w, Nr);

      // the final state is copied to the output as described in [3.4]
      for (i = 0; i < 4 * Nb; i++) {
        _out[i] = state[Math.floor(i / 4)][i % 4];
      }

      return _out;

    })([[], [], [], []]);
  }

  /**
   * The Cipher transformations can be inverted and then implemented in reverse
   * order to produce a straightforward Inverse Cipher for the AES algorithm.
   */
  function invCipher(_in, _out, _w) {
    var Nr = _w.length / Nb - 1; // rounds: 10/12/14 for 128/192/256-bit keys

    return (function(state) {
      var i, round;

      // copy input to the state array using the conventions in [3.4]
      for (i = 0; i < 4 * Nb; i++) {
        state[Math.floor(i / 4)][i % 4] = _in[i];
      }

      // initial round key addition
      state = addRoundKey(state, _w, Nr);

      // 9, 11 or 13 rounds
      for (round = 1; round <= Nr - 1; round++) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, _w, Nr - round);
        invMixColumns(state);
      }

      // final round
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, _w, 0);

      // the final state is copied to the output as described in [3.4]
      for (i = 0; i < 4 * Nb; i++) {
        _out[i] = state[Math.floor(i / 4)][i % 4];
      }

      return _out;

    })([[], [], [], []]);
  }

  /**
   * Clones the first 4 elements of an array into a new object.
   */
  Array.prototype.AES_cloneWord = function() {
    for (var i = 0, that = []; i < 4; i++) {
      that[i] = this[i];
    }

    return that;
  };

  /**
   * Performs a xor operation with the first 4 elements of an array.
   */
  Array.prototype.AES_xorWord = function(word) {
    for (var i = 0, that = this.AES_cloneWord(); i < 4; i++) {
      that[i] ^= word[i];
    }
    return that;
  };

  /**
   * Saturates a key to be exactly 16, 24, or 32 bits.
   */
  Array.prototype.AES_saturateKey = function() {
    if (this.length) {
      var ret = this.slice(0, 32), ok = [16, 24, 32].indexOf(this.length) !== -1;

      if (!ok) {
        while (ret.length < 16) { ret.push(0x0); ok = true; }
      }
      if (!ok) {
        while (ret.length < 24) { ret.push(0x0); ok = true; }
      }
      if (!ok) {
        while (ret.length < 32) { ret.push(0x0); ok = true; }
      }
      return ret;
    }
    return this;
  };

  /**
   * Saturates an input vector to be exactly 16 bits.
   */
  Array.prototype.AES_saturateInput = function() {
    if (this.length) {
      var ret = this.slice(0, 16);

      while (ret.length < 16) { ret.push(0x0); }
      return ret;
    }
    return this;
  };

  /**
   * Splits an input vector in parts of exactly 16 bits.
   */
  Array.prototype.AES_splitInput = function() {
    for (var i = 0, len = this.length, ret = []; i < len; i += 16) {
      ret.push(this.slice(i, i + 16).AES_saturateInput());
    }

    return ret;
  };

  /**
   * In the polynomial representation, multiplication in GF(2^8) corresponds
   * with the multiplication of polynomials modulo an irreducible polynomial
   * of degree 8. A polynomial is irreducible if its only divisors are one
   * and itself.
   */
  Number.prototype.AES_mulPoly = function(that) {

    /* For the AES algorithm, this irreducible polynomial is
     * x^8 + x^4 + x^3 + x + 1 ≈ 100011011. */
    const irreducible = 0x11b;

    // for each bit in the polynomial b7*x^8 + b6*x^7 + ... + b1*x^2 + b0*x
    for (var i = 0, a = this, b = that, ret = 0x00, bit = 0; i < 8; i++) {

      // check if the current bit is 1
      if ((b & 1) === 1) {
        ret ^= a;
      }

      // check for overflow on the left
      bit = (a & 128);

      // shift left one bit
      a <<= 1;

      // if overflow, subtract with the irreductible polynomial
      if (bit === 128) {
        a ^= irreducible;
      }

      // advance to the next bit
      b >>= 1;
    }

    return ret;
  };

  AES.subBytes = subBytes;
  AES.invSubBytes = invSubBytes;
  AES.shiftRows = shiftRows;
  AES.invShiftRows = invShiftRows;
  AES.mixColumns = mixColumns;
  AES.invMixColumns = invMixColumns;
  AES.addRoundKey = addRoundKey;
  AES.rotWord = rotWord;
  AES.subWord = subWord;
  AES.keyExpansion = keyExpansion;
  AES.cipher = cipher;
  AES.invCipher = invCipher;

})();
