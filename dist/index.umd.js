(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('crypto')) :
  typeof define === 'function' && define.amd ? define(['exports', 'crypto'], factory) :
  (global = global || self, factory(global.VueUUID = {}, global.crypto));
}(this, (function (exports, crypto) { 'use strict';

  crypto = crypto && Object.prototype.hasOwnProperty.call(crypto, 'default') ? crypto['default'] : crypto;

  const rnds8Pool = new Uint8Array(256); // # of random values to pre-allocate

  let poolPtr = rnds8Pool.length;
  function rng() {
    if (poolPtr > rnds8Pool.length - 16) {
      crypto.randomFillSync(rnds8Pool);
      poolPtr = 0;
    }

    return rnds8Pool.slice(poolPtr, poolPtr += 16);
  }

  var REGEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

  function validate(uuid) {
    return typeof uuid === 'string' && REGEX.test(uuid);
  }

  /**
   * Convert array of 16 byte values to UUID string format of the form:
   * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
   */

  const byteToHex = [];

  for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 0x100).toString(16).substr(1));
  }

  function stringify(arr, offset = 0) {
    // Note: Be careful editing this code!  It's been tuned for performance
    // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
    const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
    // of the following:
    // - One or more input array values don't map to a hex octet (leading to
    // "undefined" in the uuid)
    // - Invalid input values for the RFC `version` or `variant` fields

    if (!validate(uuid)) {
      throw TypeError('Stringified UUID is invalid');
    }

    return uuid;
  }

  //
  // Inspired by https://github.com/LiosK/UUID.js
  // and http://docs.python.org/library/uuid.html

  let _nodeId;

  let _clockseq; // Previous uuid creation time


  let _lastMSecs = 0;
  let _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

  function v1(options, buf, offset) {
    let i = buf && offset || 0;
    const b = buf || new Array(16);
    options = options || {};
    let node = options.node || _nodeId;
    let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
    // specified.  We do this lazily to minimize issues related to insufficient
    // system entropy.  See #189

    if (node == null || clockseq == null) {
      const seedBytes = options.random || (options.rng || rng)();

      if (node == null) {
        // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
        node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
      }

      if (clockseq == null) {
        // Per 4.2.2, randomize (14 bit) clockseq
        clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
      }
    } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
    // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
    // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
    // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


    let msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
    // cycle to simulate higher resolution clock

    let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

    const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

    if (dt < 0 && options.clockseq === undefined) {
      clockseq = clockseq + 1 & 0x3fff;
    } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
    // time interval


    if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
      nsecs = 0;
    } // Per 4.2.1.2 Throw error if too many uuids are requested


    if (nsecs >= 10000) {
      throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
    }

    _lastMSecs = msecs;
    _lastNSecs = nsecs;
    _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

    msecs += 12219292800000; // `time_low`

    const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
    b[i++] = tl >>> 24 & 0xff;
    b[i++] = tl >>> 16 & 0xff;
    b[i++] = tl >>> 8 & 0xff;
    b[i++] = tl & 0xff; // `time_mid`

    const tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
    b[i++] = tmh >>> 8 & 0xff;
    b[i++] = tmh & 0xff; // `time_high_and_version`

    b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

    b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

    b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

    b[i++] = clockseq & 0xff; // `node`

    for (let n = 0; n < 6; ++n) {
      b[i + n] = node[n];
    }

    return buf || stringify(b);
  }

  function parse(uuid) {
    if (!validate(uuid)) {
      throw TypeError('Invalid UUID');
    }

    let v;
    const arr = new Uint8Array(16); // Parse ########-....-....-....-............

    arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
    arr[1] = v >>> 16 & 0xff;
    arr[2] = v >>> 8 & 0xff;
    arr[3] = v & 0xff; // Parse ........-####-....-....-............

    arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
    arr[5] = v & 0xff; // Parse ........-....-####-....-............

    arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
    arr[7] = v & 0xff; // Parse ........-....-....-####-............

    arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
    arr[9] = v & 0xff; // Parse ........-....-....-....-############
    // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

    arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
    arr[11] = v / 0x100000000 & 0xff;
    arr[12] = v >>> 24 & 0xff;
    arr[13] = v >>> 16 & 0xff;
    arr[14] = v >>> 8 & 0xff;
    arr[15] = v & 0xff;
    return arr;
  }

  function stringToBytes(str) {
    str = unescape(encodeURIComponent(str)); // UTF8 escape

    const bytes = [];

    for (let i = 0; i < str.length; ++i) {
      bytes.push(str.charCodeAt(i));
    }

    return bytes;
  }

  const DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  const URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
  function v35 (name, version, hashfunc) {
    function generateUUID(value, namespace, buf, offset) {
      if (typeof value === 'string') {
        value = stringToBytes(value);
      }

      if (typeof namespace === 'string') {
        namespace = parse(namespace);
      }

      if (namespace.length !== 16) {
        throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
      } // Compute hash of namespace and value, Per 4.3
      // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
      // hashfunc([...namespace, ... value])`


      let bytes = new Uint8Array(16 + value.length);
      bytes.set(namespace);
      bytes.set(value, namespace.length);
      bytes = hashfunc(bytes);
      bytes[6] = bytes[6] & 0x0f | version;
      bytes[8] = bytes[8] & 0x3f | 0x80;

      if (buf) {
        offset = offset || 0;

        for (let i = 0; i < 16; ++i) {
          buf[offset + i] = bytes[i];
        }

        return buf;
      }

      return stringify(bytes);
    } // Function#name is not settable on some platforms (#270)


    try {
      generateUUID.name = name; // eslint-disable-next-line no-empty
    } catch (err) {} // For CommonJS default export support


    generateUUID.DNS = DNS;
    generateUUID.URL = URL;
    return generateUUID;
  }

  function md5(bytes) {
    if (Array.isArray(bytes)) {
      bytes = Buffer.from(bytes);
    } else if (typeof bytes === 'string') {
      bytes = Buffer.from(bytes, 'utf8');
    }

    return crypto.createHash('md5').update(bytes).digest();
  }

  const v3 = v35('v3', 0x30, md5);

  function v4(options, buf, offset) {
    options = options || {};
    const rnds = options.random || (options.rng || rng)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`

    rnds[6] = rnds[6] & 0x0f | 0x40;
    rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

    if (buf) {
      offset = offset || 0;

      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = rnds[i];
      }

      return buf;
    }

    return stringify(rnds);
  }

  function sha1(bytes) {
    if (Array.isArray(bytes)) {
      bytes = Buffer.from(bytes);
    } else if (typeof bytes === 'string') {
      bytes = Buffer.from(bytes, 'utf8');
    }

    return crypto.createHash('sha1').update(bytes).digest();
  }

  const v5 = v35('v5', 0x50, sha1);

  /**
   * @typedef {Object} UUID
   * @property {typeof v1} v1
   * @property {typeof v3} v3
   * @property {typeof v4} v4
   * @property {typeof v5} v5
   */

  /**
   * An object with uuid's v1, v3, v4 and v5 functions.
   * @type {UUID}
   */

  var uuid = {
    v1: v1,
    v3: v3,
    v4: v4,
    v5: v5
  };
  /**
   * Installs UUID on Vue instance. It creates a property on Vue instance to
   * expose an object with uuid's v1, v3, v4 and v5 functions.
   * @example ```js
   * import Vue from 'vue';
   * import VueUUID from 'vue-uuid';
   *
   * Vue.use(VueUUID);
   *
   * new Vue({
   *   mounted () {
   *     console.log(this.$uuid.v1());
   *   }
   * });
   * ```
   * @param {import('vue').default} Vue Vue constructor.
   */

  function install(Vue) {
    console.log('vue3 uuid install');
  }

  exports.default = install;
  exports.uuid = uuid;

  Object.defineProperty(exports, '__esModule', { value: true });

})));
