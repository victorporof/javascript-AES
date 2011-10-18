/*global AES, jsSHA */

(function() {
  "use strict";

  var e$key = document.getElementById("key"),
      e$input = document.getElementById("input"),
      e$output = document.getElementById("output"),
      e$sha = document.getElementById("sha");

  function test() {
    var sha = e$sha.checked,
        key = e$key.value.ascii().AES_saturateKey(),
        input = e$input.value.ascii().AES_splitInput(),
        cipher = [],
        invCipher = [];

    (function test_sha() {
      if (sha) {
        key = new jsSHA(key.str(), "ASCII").getHash("SHA-256", "HEX").ascii();
      }
    })();

    (function test_aes() {
      if (key && input) {
        for (var i = 0, len = input.length, output = []; i < len; i++) {

          cipher.push(AES.cipher(input[i], output, AES.keyExpansion(key)));
          invCipher.push(AES.invCipher(output, [], AES.keyExpansion(key)));

        }
      }
    })();

    e$output.innerHTML =
      "<span>Key     = </span>" + key.hex() + "<br>" +
      "<span>        = </span>" + key.str() + "<br><br>" +
      "<span>Input   = </span>" + input.hex() + "<br>" +
      "<span>        = </span>" + input.str() + "<br><br>" +
      "<span>Cipher  = </span>" + cipher.hex() + "<br>" +
      "<span>        = </span>" + cipher.str() + "<br><br>" +
      "<span>Inverse = </span>" + invCipher.hex() + "<br>" +
      "<span>        = </span>" + invCipher.str();
  }

  e$sha.onchange = function() { test(); };
  e$key.onkeyup = function() { test(); };
  e$input.onkeyup = function() { test(); };

  test();
})();
