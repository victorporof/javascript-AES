/**
 * Returns an array containing the ascii representation of the string.
 */
String.prototype.ascii = function() {
  for (var i = 0, len = this.length, ascii = []; i < len; i++) {
    ascii[i] = this.charCodeAt(i);
  }

  return ascii;
};

/**
 * Returns an array containing the hex representation for all the elements.
 */
Array.prototype.hex = function() {
  for (var i = 0, len = this.length, ret = []; i < len; i++) {
    if (this[i] instanceof Array) {
      ret[i] = this[i].hex();
    } else {
      ret[i] = (this[i] < 16 ? "0" : "") + this[i].toString(16);
    }
  }

  return ret;
};

/**
 * Returns a string created from the char codes of the current ascii array.
 */
Array.prototype.str = function() {
  for (var i = 0, len = this.length, ret = []; i < len; i++) {
    if (this[i] instanceof Array) {
      ret.push(this[i].str());
    } else {
      ret.push(String.fromCharCode(this[i]));
    }
  }

  return ret.join("");
};

/**
 * Verifies if two arrays contain identical elements.
 */
Array.prototype.is = function(that) {
  var i, len, ok = true;

  for (i = 0, len = this.length; i < len && ok; i++) {
    if (this[i] instanceof Array && that[i] instanceof Array) {
      ok = this[i].is(that[i]);
    } else {
      ok = this[i] === that[i];
    }
  }

  return ok;
};

/**
 * Logs the elements in an array and returns the same array.
 */
Array.prototype.log = function() {
  console.log(this.hex());
  return this;
};
