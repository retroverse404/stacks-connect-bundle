const ERROR_CODES = {
    MISSING_PARAMETER: 'missing_parameter',
    REMOTE_SERVICE_ERROR: 'remote_service_error',
    INVALID_STATE: 'invalid_state',
    NO_SESSION_DATA: 'no_session_data',
    DOES_NOT_EXIST: 'does_not_exist',
    FAILED_DECRYPTION_ERROR: 'failed_decryption_error',
    INVALID_DID_ERROR: 'invalid_did_error',
    NOT_ENOUGH_FUNDS_ERROR: 'not_enough_error',
    INVALID_AMOUNT_ERROR: 'invalid_amount_error',
    LOGIN_FAILED_ERROR: 'login_failed',
    SIGNATURE_VERIFICATION_ERROR: 'signature_verification_failure',
    CONFLICT_ERROR: 'conflict_error',
    NOT_ENOUGH_PROOF_ERROR: 'not_enough_proof_error',
    BAD_PATH_ERROR: 'bad_path_error',
    VALIDATION_ERROR: 'validation_error',
    PAYLOAD_TOO_LARGE_ERROR: 'payload_too_large_error',
    PRECONDITION_FAILED_ERROR: 'precondition_failed_error',
    UNKNOWN: 'unknown',
};
Object.freeze(ERROR_CODES);
class BlockstackError extends Error {
    constructor(error) {
        super();
        let message = error.message;
        let bugDetails = `Error Code: ${error.code}`;
        let stack = this.stack;
        if (!stack) {
            try {
                throw new Error();
            }
            catch (e) {
                stack = e.stack;
            }
        }
        else {
            bugDetails += `Stack Trace:\n${stack}`;
        }
        message += `\nIf you believe this exception is caused by a bug in stacks.js,
      please file a bug report: https://github.com/blockstack/stacks.js/issues\n\n${bugDetails}`;
        this.message = message;
        this.code = error.code;
        this.parameter = error.parameter ? error.parameter : undefined;
    }
    toString() {
        return `${super.toString()}
    code: ${this.code} param: ${this.parameter ? this.parameter : 'n/a'}`;
    }
}
class NoSessionDataError extends BlockstackError {
    constructor(message) {
        super({ code: ERROR_CODES.INVALID_STATE, message });
        this.message = message;
        this.name = 'NoSessionDataError';
    }
}

function intToBytes$1(value, byteLength) {
    return bigIntToBytes$1(intToBigInt$1(value), byteLength);
}
function intToBigInt$1(value) {
    if (typeof value === 'bigint')
        return value;
    if (typeof value === 'string')
        return BigInt(value);
    if (typeof value === 'number') {
        if (!Number.isInteger(value)) {
            throw new RangeError(`Invalid value. Values of type 'number' must be an integer.`);
        }
        if (value > Number.MAX_SAFE_INTEGER) {
            throw new RangeError(`Invalid value. Values of type 'number' must be less than or equal to ${Number.MAX_SAFE_INTEGER}. For larger values, try using a BigInt instead.`);
        }
        return BigInt(value);
    }
    if (isInstance(value, Uint8Array))
        return BigInt(`0x${bytesToHex$2(value)}`);
    throw new TypeError(`intToBigInt: Invalid value type. Must be a number, bigint, BigInt-compatible string, or Uint8Array.`);
}
function without0x(value) {
    return /^0x/i.test(value)
        ? value.slice(2)
        : value;
}
function hexToBigInt(hex) {
    if (typeof hex !== 'string')
        throw new TypeError(`hexToBigInt: expected string, got ${typeof hex}`);
    return BigInt(`0x${hex}`);
}
function intToHex$1(integer, byteLength = 8) {
    const value = typeof integer === 'bigint' ? integer : intToBigInt$1(integer);
    return value.toString(16).padStart(byteLength * 2, '0');
}
function hexToInt(hex) {
    return parseInt(hex, 16);
}
function bigIntToBytes$1(value, length = 16) {
    const hex = intToHex$1(value, length);
    return hexToBytes$2(hex);
}
function toTwos$1(value, width) {
    if (value < -(BigInt(1) << (width - BigInt(1))) ||
        (BigInt(1) << (width - BigInt(1))) - BigInt(1) < value) {
        throw `Unable to represent integer in width: ${width}`;
    }
    if (value >= BigInt(0)) {
        return BigInt(value);
    }
    return value + (BigInt(1) << width);
}
function nthBit(value, n) {
    return value & (BigInt(1) << n);
}
function bytesToTwosBigInt(bytes) {
    return fromTwos(BigInt(`0x${bytesToHex$2(bytes)}`), BigInt(bytes.byteLength * 8));
}
function fromTwos(value, width) {
    if (nthBit(value, width - BigInt(1))) {
        return value - (BigInt(1) << width);
    }
    return value;
}
const hexes$2 = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex$2(uint8a) {
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Uint8Array expected');
    let hex = '';
    for (const u of uint8a) {
        hex += hexes$2[u];
    }
    return hex;
}
function hexToBytes$2(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError(`hexToBytes: expected string, got ${typeof hex}`);
    }
    hex = without0x(hex);
    hex = hex.length % 2 ? `0${hex}` : hex;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
function utf8ToBytes$2(str) {
    return new TextEncoder().encode(str);
}
function bytesToUtf8(arr) {
    return new TextDecoder().decode(arr);
}
function asciiToBytes$1(str) {
    const byteArray = [];
    for (let i = 0; i < str.length; i++) {
        byteArray.push(str.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(byteArray);
}
function bytesToAscii(arr) {
    return String.fromCharCode.apply(null, arr);
}
function isNotOctet$1(octet) {
    return !Number.isInteger(octet) || octet < 0 || octet > 255;
}
function octetsToBytes$1(numbers) {
    if (numbers.some(isNotOctet$1))
        throw new Error('Some values are invalid bytes.');
    return new Uint8Array(numbers);
}
function concatBytes$2(...arrays) {
    if (!arrays.every(a => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function concatArray$1(elements) {
    return concatBytes$2(...elements.map(e => {
        if (typeof e === 'number')
            return octetsToBytes$1([e]);
        if (e instanceof Array)
            return octetsToBytes$1(e);
        return e;
    }));
}
function isInstance(object, clazz) {
    return object instanceof clazz || object?.constructor?.name?.toLowerCase() === clazz.name;
}

const HIRO_MAINNET_URL = 'https://api.mainnet.hiro.so';
const HIRO_TESTNET_URL = 'https://api.testnet.hiro.so';
const DEVNET_URL = 'http://localhost:3999';
const PRIVATE_KEY_BYTES_COMPRESSED = 33;

const COORDINATE_BYTES = 32;
function parseRecoverableSignatureVrs(signature) {
    if (signature.length < COORDINATE_BYTES * 2 * 2 + 1) {
        throw new Error('Invalid signature');
    }
    const recoveryIdHex = signature.slice(0, 2);
    const r = signature.slice(2, 2 + COORDINATE_BYTES * 2);
    const s = signature.slice(2 + COORDINATE_BYTES * 2);
    return {
        recoveryId: hexToInt(recoveryIdHex),
        r,
        s,
    };
}

function privateKeyToBytes(privateKey) {
    const privateKeyBuffer = typeof privateKey === 'string' ? hexToBytes$2(privateKey) : privateKey;
    if (privateKeyBuffer.length != 32 && privateKeyBuffer.length != 33) {
        throw new Error(`Improperly formatted private-key. Private-key byte length should be 32 or 33. Length provided: ${privateKeyBuffer.length}`);
    }
    if (privateKeyBuffer.length == 33 && privateKeyBuffer[32] !== 1) {
        throw new Error('Improperly formatted private-key. 33 bytes indicate compressed key, but the last byte must be == 01');
    }
    return privateKeyBuffer;
}

function readUInt16BE(source, offset) {
    return ((source[offset + 0] << 8) | source[offset + 1]) >>> 0;
}
function writeUInt16BE(destination, value, offset = 0) {
    destination[offset + 0] = value >>> 8;
    destination[offset + 1] = value >>> 0;
    return destination;
}
function readUInt8(source, offset) {
    return source[offset];
}
function writeUInt8(destination, value, offset = 0) {
    destination[offset] = value;
    return destination;
}
function readUInt32BE(source, offset) {
    return (source[offset] * 2 ** 24 +
        source[offset + 1] * 2 ** 16 +
        source[offset + 2] * 2 ** 8 +
        source[offset + 3]);
}
function writeUInt32BE$1(destination, value, offset = 0) {
    destination[offset + 3] = value;
    value >>>= 8;
    destination[offset + 2] = value;
    value >>>= 8;
    destination[offset + 1] = value;
    value >>>= 8;
    destination[offset] = value;
    return destination;
}

/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is Uint8Array. */
function abytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}
function isArrayOf(isString, arr) {
    if (!Array.isArray(arr))
        return false;
    if (arr.length === 0)
        return true;
    if (isString) {
        return arr.every((item) => typeof item === 'string');
    }
    else {
        return arr.every((item) => Number.isSafeInteger(item));
    }
}
function astr(label, input) {
    if (typeof input !== 'string')
        throw new Error(`${label}: string expected`);
    return true;
}
function anumber(n) {
    if (!Number.isSafeInteger(n))
        throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
    if (!Array.isArray(input))
        throw new Error('array expected');
}
function astrArr(label, input) {
    if (!isArrayOf(true, input))
        throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
    if (!isArrayOf(false, input))
        throw new Error(`${label}: array of numbers expected`);
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function chain(...args) {
    const id = (a) => a;
    // Wrap call in closure so JIT can inline calls
    const wrap = (a, b) => (c) => a(b(c));
    // Construct chain of args[-1].encode(args[-2].encode([...]))
    const encode = args.map((x) => x.encode).reduceRight(wrap, id);
    // Construct chain of args[0].decode(args[1].decode(...))
    const decode = args.map((x) => x.decode).reduce(wrap, id);
    return { encode, decode };
}
/**
 * Encodes integer radix representation to array of strings using alphabet and back.
 * Could also be array of strings.
 * @__NO_SIDE_EFFECTS__
 */
function alphabet(letters) {
    // mapping 1 to "b"
    const lettersA = typeof letters === 'string' ? letters.split('') : letters;
    const len = lettersA.length;
    astrArr('alphabet', lettersA);
    // mapping "b" to 1
    const indexes = new Map(lettersA.map((l, i) => [l, i]));
    return {
        encode: (digits) => {
            aArr(digits);
            return digits.map((i) => {
                if (!Number.isSafeInteger(i) || i < 0 || i >= len)
                    throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
                return lettersA[i];
            });
        },
        decode: (input) => {
            aArr(input);
            return input.map((letter) => {
                astr('alphabet.decode', letter);
                const i = indexes.get(letter);
                if (i === undefined)
                    throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
                return i;
            });
        },
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function join(separator = '') {
    astr('join', separator);
    return {
        encode: (from) => {
            astrArr('join.decode', from);
            return from.join(separator);
        },
        decode: (to) => {
            astr('join.decode', to);
            return to.split(separator);
        },
    };
}
/**
 * Pad strings array so it has integer number of bits
 * @__NO_SIDE_EFFECTS__
 */
function padding(bits, chr = '=') {
    anumber(bits);
    astr('padding', chr);
    return {
        encode(data) {
            astrArr('padding.encode', data);
            while ((data.length * bits) % 8)
                data.push(chr);
            return data;
        },
        decode(input) {
            astrArr('padding.decode', input);
            let end = input.length;
            if ((end * bits) % 8)
                throw new Error('padding: invalid, string should have whole number of bytes');
            for (; end > 0 && input[end - 1] === chr; end--) {
                const last = end - 1;
                const byte = last * bits;
                if (byte % 8 === 0)
                    throw new Error('padding: invalid, string has too much padding');
            }
            return input.slice(0, end);
        },
    };
}
const gcd = (a, b) => (b === 0 ? a : gcd(b, a % b));
const radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
const powers = /* @__PURE__ */ (() => {
    let res = [];
    for (let i = 0; i < 40; i++)
        res.push(2 ** i);
    return res;
})();
/**
 * Implemented with numbers, because BigInt is 5x slower
 */
function convertRadix2(data, from, to, padding) {
    aArr(data);
    if (from <= 0 || from > 32)
        throw new Error(`convertRadix2: wrong from=${from}`);
    if (to <= 0 || to > 32)
        throw new Error(`convertRadix2: wrong to=${to}`);
    if (radix2carry(from, to) > 32) {
        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
    }
    let carry = 0;
    let pos = 0; // bitwise position in current element
    const max = powers[from];
    const mask = powers[to] - 1;
    const res = [];
    for (const n of data) {
        anumber(n);
        if (n >= max)
            throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
        carry = (carry << from) | n;
        if (pos + from > 32)
            throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
        pos += from;
        for (; pos >= to; pos -= to)
            res.push(((carry >> (pos - to)) & mask) >>> 0);
        const pow = powers[pos];
        if (pow === undefined)
            throw new Error('invalid carry');
        carry &= pow - 1; // clean carry, otherwise it will cause overflow
    }
    carry = (carry << (to - pos)) & mask;
    if (!padding && pos >= from)
        throw new Error('Excess padding');
    if (!padding && carry > 0)
        throw new Error(`Non-zero padding: ${carry}`);
    if (padding && pos > 0)
        res.push(carry >>> 0);
    return res;
}
/**
 * If both bases are power of same number (like `2**8 <-> 2**64`),
 * there is a linear algorithm. For now we have implementation for power-of-two bases only.
 * @__NO_SIDE_EFFECTS__
 */
function radix2(bits, revPadding = false) {
    anumber(bits);
    if (bits <= 0 || bits > 32)
        throw new Error('radix2: bits should be in (0..32]');
    if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
        throw new Error('radix2: carry overflow');
    return {
        encode: (bytes) => {
            if (!isBytes(bytes))
                throw new Error('radix2.encode input should be Uint8Array');
            return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
        },
        decode: (digits) => {
            anumArr('radix2.decode', digits);
            return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
        },
    };
}
// Built-in base64 conversion https://caniuse.com/mdn-javascript_builtins_uint8array_frombase64
// prettier-ignore
const hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === 'function' &&
    typeof Uint8Array.fromBase64 === 'function')();
const decodeBase64Builtin = (s, isUrl) => {
    astr('base64', s);
    const re = /^[A-Za-z0-9=+/]+$/;
    const alphabet = 'base64';
    if (s.length > 0 && !re.test(s))
        throw new Error('invalid base64');
    return Uint8Array.fromBase64(s, { alphabet, lastChunkHandling: 'strict' });
};
/**
 * base64 from RFC 4648. Padded.
 * Use `base64nopad` for unpadded version.
 * Also check out `base64url`, `base64urlnopad`.
 * Falls back to built-in function, when available.
 * @example
 * ```js
 * base64.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'Eqs='
 * base64.decode('Eqs=');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
// prettier-ignore
const base64 = hasBase64Builtin ? {
    encode(b) { abytes(b); return b.toBase64(); },
    decode(s) { return decodeBase64Builtin(s); },
} : chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), padding(6), join(''));

const LOCAL_STORAGE_KEY = 'STX_PROVIDER';
const getSelectedProviderId = () => {
  if (typeof window === 'undefined')
    return null;
  return window.localStorage.getItem(LOCAL_STORAGE_KEY);
};
const setSelectedProviderId = (provider) => {
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(LOCAL_STORAGE_KEY, provider);
  }
};
const clearSelectedProviderId = () => {
  if (typeof window !== 'undefined') {
    window.localStorage.removeItem(LOCAL_STORAGE_KEY);
  }
};

// AUTO REGISTERED PROVIDERS
const getRegisteredProviders = () => {
  if (typeof window === 'undefined')
    return [];
  const legacyProviders = window.webbtc_stx_providers || [];
  const wbipProviders = window.wbip_providers || [];
  return [...legacyProviders, ...wbipProviders];
};
const getInstalledProviders = (defaultProviders = []) => {
  if (typeof window === 'undefined')
    return [];
  const registeredProviders = getRegisteredProviders();
  const additionalInstalledProviders = defaultProviders.filter(defaultProvider => {
    // already registered, don't add again
    if (registeredProviders.find(rp => rp.id === defaultProvider.id))
      return false;
    // check if default provider is installed (even if not registered)
    const provider = getProviderFromId(defaultProvider.id);
    return !!provider;
  });
  return registeredProviders.concat(additionalInstalledProviders);
};
/**
 * Check if a wallet provider was previously selected via Connect.
 * @returns `true` if a provider was selected, `false` otherwise.
 */
const isProviderSelected = () => {
  return !!getSelectedProviderId();
};
/**
 * Get the currently selected wallet provider.
 * Note that this will not return the default `window.StacksProvider` object.
 * @returns The wallet provider object, or null if no provider is selected.
 */
const getProvider = () => {
  const providerId = getSelectedProviderId();
  return getProviderFromId(providerId);
};
const getProviderFromId = (id) => {
  return id === null || id === void 0 ? void 0 : id.split('.').reduce((acc, part) => acc === null || acc === void 0 ? void 0 : acc[part], window);
};

const NAMESPACE = 'connect-ui';

/**
 * Virtual DOM patching algorithm based on Snabbdom by
 * Simon Friis Vindum (@paldepind)
 * Licensed under the MIT License
 * https://github.com/snabbdom/snabbdom/blob/master/LICENSE
 *
 * Modified for Stencil's renderer and slot projection
 */
let scopeId;
let hostTagName;
let isSvgMode = false;
let queuePending = false;
const createTime = (fnName, tagName = '') => {
    {
        return () => {
            return;
        };
    }
};
const uniqueTime = (key, measureText) => {
    {
        return () => {
            return;
        };
    }
};
const HYDRATED_CSS = '{visibility:hidden}.hydrated{visibility:inherit}';
/**
 * Default style mode id
 */
/**
 * Reusable empty obj/array
 * Don't add values to these!!
 */
const EMPTY_OBJ = {};
/**
 * Namespaces
 */
const SVG_NS = 'http://www.w3.org/2000/svg';
const HTML_NS = 'http://www.w3.org/1999/xhtml';
const isDef = (v) => v != null;
const isComplexType = (o) => {
    // https://jsperf.com/typeof-fn-object/5
    o = typeof o;
    return o === 'object' || o === 'function';
};
/**
 * Helper method for querying a `meta` tag that contains a nonce value
 * out of a DOM's head.
 *
 * @param doc The DOM containing the `head` to query against
 * @returns The content of the meta tag representing the nonce value, or `undefined` if no tag
 * exists or the tag has no content.
 */
function queryNonceMetaTagContent(doc) {
    var _a, _b, _c;
    return (_c = (_b = (_a = doc.head) === null || _a === void 0 ? void 0 : _a.querySelector('meta[name="csp-nonce"]')) === null || _b === void 0 ? void 0 : _b.getAttribute('content')) !== null && _c !== void 0 ? _c : undefined;
}
/**
 * Production h() function based on Preact by
 * Jason Miller (@developit)
 * Licensed under the MIT License
 * https://github.com/developit/preact/blob/master/LICENSE
 *
 * Modified for Stencil's compiler and vdom
 */
// export function h(nodeName: string | d.FunctionalComponent, vnodeData: d.PropsType, child?: d.ChildType): d.VNode;
// export function h(nodeName: string | d.FunctionalComponent, vnodeData: d.PropsType, ...children: d.ChildType[]): d.VNode;
const h$1 = (nodeName, vnodeData, ...children) => {
    let child = null;
    let simple = false;
    let lastSimple = false;
    const vNodeChildren = [];
    const walk = (c) => {
        for (let i = 0; i < c.length; i++) {
            child = c[i];
            if (Array.isArray(child)) {
                walk(child);
            }
            else if (child != null && typeof child !== 'boolean') {
                if ((simple = typeof nodeName !== 'function' && !isComplexType(child))) {
                    child = String(child);
                }
                if (simple && lastSimple) {
                    // If the previous child was simple (string), we merge both
                    vNodeChildren[vNodeChildren.length - 1].$text$ += child;
                }
                else {
                    // Append a new vNode, if it's text, we create a text vNode
                    vNodeChildren.push(simple ? newVNode(null, child) : child);
                }
                lastSimple = simple;
            }
        }
    };
    walk(children);
    if (vnodeData) {
        {
            const classData = vnodeData.className || vnodeData.class;
            if (classData) {
                vnodeData.class =
                    typeof classData !== 'object'
                        ? classData
                        : Object.keys(classData)
                            .filter((k) => classData[k])
                            .join(' ');
            }
        }
    }
    const vnode = newVNode(nodeName, null);
    vnode.$attrs$ = vnodeData;
    if (vNodeChildren.length > 0) {
        vnode.$children$ = vNodeChildren;
    }
    return vnode;
};
/**
 * A utility function for creating a virtual DOM node from a tag and some
 * possible text content.
 *
 * @param tag the tag for this element
 * @param text possible text content for the node
 * @returns a newly-minted virtual DOM node
 */
const newVNode = (tag, text) => {
    const vnode = {
        $flags$: 0,
        $tag$: tag,
        $text$: text,
        $elm$: null,
        $children$: null,
    };
    {
        vnode.$attrs$ = null;
    }
    return vnode;
};
const Host = {};
/**
 * Check whether a given node is a Host node or not
 *
 * @param node the virtual DOM node to check
 * @returns whether it's a Host node or not
 */
const isHost = (node) => node && node.$tag$ === Host;
/**
 * Parse a new property value for a given property type.
 *
 * While the prop value can reasonably be expected to be of `any` type as far as TypeScript's type checker is concerned,
 * it is not safe to assume that the string returned by evaluating `typeof propValue` matches:
 *   1. `any`, the type given to `propValue` in the function signature
 *   2. the type stored from `propType`.
 *
 * This function provides the capability to parse/coerce a property's value to potentially any other JavaScript type.
 *
 * Property values represented in TSX preserve their type information. In the example below, the number 0 is passed to
 * a component. This `propValue` will preserve its type information (`typeof propValue === 'number'`). Note that is
 * based on the type of the value being passed in, not the type declared of the class member decorated with `@Prop`.
 * ```tsx
 * <my-cmp prop-val={0}></my-cmp>
 * ```
 *
 * HTML prop values on the other hand, will always a string
 *
 * @param propValue the new value to coerce to some type
 * @param propType the type of the prop, expressed as a binary number
 * @returns the parsed/coerced value
 */
const parsePropertyValue = (propValue, propType) => {
    // ensure this value is of the correct prop type
    if (propValue != null && !isComplexType(propValue)) {
        // redundant return here for better minification
        return propValue;
    }
    // not sure exactly what type we want
    // so no need to change to a different type
    return propValue;
};
const getElement = (ref) => (getHostRef(ref).$hostElement$ );
/**
 * Helper function to create & dispatch a custom Event on a provided target
 * @param elm the target of the Event
 * @param name the name to give the custom Event
 * @param opts options for configuring a custom Event
 * @returns the custom Event
 */
const emitEvent = (elm, name, opts) => {
    const ev = plt.ce(name, opts);
    elm.dispatchEvent(ev);
    return ev;
};
const rootAppliedStyles = /*@__PURE__*/ new WeakMap();
const registerStyle = (scopeId, cssText, allowCS) => {
    let style = styles.get(scopeId);
    if (supportsConstructableStylesheets && allowCS) {
        style = (style || new CSSStyleSheet());
        if (typeof style === 'string') {
            style = cssText;
        }
        else {
            style.replaceSync(cssText);
        }
    }
    else {
        style = cssText;
    }
    styles.set(scopeId, style);
};
const addStyle = (styleContainerNode, cmpMeta, mode, hostElm) => {
    var _a;
    let scopeId = getScopeId(cmpMeta);
    const style = styles.get(scopeId);
    // if an element is NOT connected then getRootNode() will return the wrong root node
    // so the fallback is to always use the document for the root node in those cases
    styleContainerNode = styleContainerNode.nodeType === 11 /* NODE_TYPE.DocumentFragment */ ? styleContainerNode : doc;
    if (style) {
        if (typeof style === 'string') {
            styleContainerNode = styleContainerNode.head || styleContainerNode;
            let appliedStyles = rootAppliedStyles.get(styleContainerNode);
            let styleElm;
            if (!appliedStyles) {
                rootAppliedStyles.set(styleContainerNode, (appliedStyles = new Set()));
            }
            if (!appliedStyles.has(scopeId)) {
                {
                    {
                        styleElm = doc.createElement('style');
                        styleElm.innerHTML = style;
                    }
                    // Apply CSP nonce to the style tag if it exists
                    const nonce = (_a = plt.$nonce$) !== null && _a !== void 0 ? _a : queryNonceMetaTagContent(doc);
                    if (nonce != null) {
                        styleElm.setAttribute('nonce', nonce);
                    }
                    styleContainerNode.insertBefore(styleElm, styleContainerNode.querySelector('link'));
                }
                if (appliedStyles) {
                    appliedStyles.add(scopeId);
                }
            }
        }
        else if (!styleContainerNode.adoptedStyleSheets.includes(style)) {
            styleContainerNode.adoptedStyleSheets = [...styleContainerNode.adoptedStyleSheets, style];
        }
    }
    return scopeId;
};
const attachStyles = (hostRef) => {
    const cmpMeta = hostRef.$cmpMeta$;
    const elm = hostRef.$hostElement$;
    const flags = cmpMeta.$flags$;
    const endAttachStyles = createTime('attachStyles', cmpMeta.$tagName$);
    const scopeId = addStyle(elm.shadowRoot ? elm.shadowRoot : elm.getRootNode(), cmpMeta);
    if (flags & 10 /* CMP_FLAGS.needsScopedEncapsulation */) {
        // only required when we're NOT using native shadow dom (slot)
        // or this browser doesn't support native shadow dom
        // and this host element was NOT created with SSR
        // let's pick out the inner content for slot projection
        // create a node to represent where the original
        // content was first placed, which is useful later on
        // DOM WRITE!!
        elm['s-sc'] = scopeId;
        elm.classList.add(scopeId + '-h');
    }
    endAttachStyles();
};
const getScopeId = (cmp, mode) => 'sc-' + (cmp.$tagName$);
/**
 * Production setAccessor() function based on Preact by
 * Jason Miller (@developit)
 * Licensed under the MIT License
 * https://github.com/developit/preact/blob/master/LICENSE
 *
 * Modified for Stencil's compiler and vdom
 */
const setAccessor = (elm, memberName, oldValue, newValue, isSvg, flags) => {
    if (oldValue !== newValue) {
        let isProp = isMemberInElement(elm, memberName);
        let ln = memberName.toLowerCase();
        if (memberName === 'class') {
            const classList = elm.classList;
            const oldClasses = parseClassList(oldValue);
            const newClasses = parseClassList(newValue);
            classList.remove(...oldClasses.filter((c) => c && !newClasses.includes(c)));
            classList.add(...newClasses.filter((c) => c && !oldClasses.includes(c)));
        }
        else if ((!isProp ) &&
            memberName[0] === 'o' &&
            memberName[1] === 'n') {
            // Event Handlers
            // so if the member name starts with "on" and the 3rd characters is
            // a capital letter, and it's not already a member on the element,
            // then we're assuming it's an event listener
            if (memberName[2] === '-') {
                // on- prefixed events
                // allows to be explicit about the dom event to listen without any magic
                // under the hood:
                // <my-cmp on-click> // listens for "click"
                // <my-cmp on-Click> // listens for "Click"
                // <my-cmp on-ionChange> // listens for "ionChange"
                // <my-cmp on-EVENTS> // listens for "EVENTS"
                memberName = memberName.slice(3);
            }
            else if (isMemberInElement(win, ln)) {
                // standard event
                // the JSX attribute could have been "onMouseOver" and the
                // member name "onmouseover" is on the window's prototype
                // so let's add the listener "mouseover", which is all lowercased
                memberName = ln.slice(2);
            }
            else {
                // custom event
                // the JSX attribute could have been "onMyCustomEvent"
                // so let's trim off the "on" prefix and lowercase the first character
                // and add the listener "myCustomEvent"
                // except for the first character, we keep the event name case
                memberName = ln[2] + memberName.slice(3);
            }
            if (oldValue) {
                plt.rel(elm, memberName, oldValue, false);
            }
            if (newValue) {
                plt.ael(elm, memberName, newValue, false);
            }
        }
        else {
            // Set property if it exists and it's not a SVG
            const isComplex = isComplexType(newValue);
            if ((isProp || (isComplex && newValue !== null)) && !isSvg) {
                try {
                    if (!elm.tagName.includes('-')) {
                        const n = newValue == null ? '' : newValue;
                        // Workaround for Safari, moving the <input> caret when re-assigning the same valued
                        if (memberName === 'list') {
                            isProp = false;
                        }
                        else if (oldValue == null || elm[memberName] != n) {
                            elm[memberName] = n;
                        }
                    }
                    else {
                        elm[memberName] = newValue;
                    }
                }
                catch (e) { }
            }
            if (newValue == null || newValue === false) {
                if (newValue !== false || elm.getAttribute(memberName) === '') {
                    {
                        elm.removeAttribute(memberName);
                    }
                }
            }
            else if ((!isProp || flags & 4 /* VNODE_FLAGS.isHost */ || isSvg) && !isComplex) {
                newValue = newValue === true ? '' : newValue;
                {
                    elm.setAttribute(memberName, newValue);
                }
            }
        }
    }
};
const parseClassListRegex = /\s/;
const parseClassList = (value) => (!value ? [] : value.split(parseClassListRegex));
const updateElement = (oldVnode, newVnode, isSvgMode, memberName) => {
    // if the element passed in is a shadow root, which is a document fragment
    // then we want to be adding attrs/props to the shadow root's "host" element
    // if it's not a shadow root, then we add attrs/props to the same element
    const elm = newVnode.$elm$.nodeType === 11 /* NODE_TYPE.DocumentFragment */ && newVnode.$elm$.host
        ? newVnode.$elm$.host
        : newVnode.$elm$;
    const oldVnodeAttrs = (oldVnode && oldVnode.$attrs$) || EMPTY_OBJ;
    const newVnodeAttrs = newVnode.$attrs$ || EMPTY_OBJ;
    {
        // remove attributes no longer present on the vnode by setting them to undefined
        for (memberName in oldVnodeAttrs) {
            if (!(memberName in newVnodeAttrs)) {
                setAccessor(elm, memberName, oldVnodeAttrs[memberName], undefined, isSvgMode, newVnode.$flags$);
            }
        }
    }
    // add new & update changed attributes
    for (memberName in newVnodeAttrs) {
        setAccessor(elm, memberName, oldVnodeAttrs[memberName], newVnodeAttrs[memberName], isSvgMode, newVnode.$flags$);
    }
};
/**
 * Create a DOM Node corresponding to one of the children of a given VNode.
 *
 * @param oldParentVNode the parent VNode from the previous render
 * @param newParentVNode the parent VNode from the current render
 * @param childIndex the index of the VNode, in the _new_ parent node's
 * children, for which we will create a new DOM node
 * @param parentElm the parent DOM node which our new node will be a child of
 * @returns the newly created node
 */
const createElm = (oldParentVNode, newParentVNode, childIndex, parentElm) => {
    // tslint:disable-next-line: prefer-const
    const newVNode = newParentVNode.$children$[childIndex];
    let i = 0;
    let elm;
    let childNode;
    if (newVNode.$text$ !== null) {
        // create text node
        elm = newVNode.$elm$ = doc.createTextNode(newVNode.$text$);
    }
    else {
        if (!isSvgMode) {
            isSvgMode = newVNode.$tag$ === 'svg';
        }
        // create element
        elm = newVNode.$elm$ = (doc.createElementNS(isSvgMode ? SVG_NS : HTML_NS, newVNode.$tag$)
            );
        if (isSvgMode && newVNode.$tag$ === 'foreignObject') {
            isSvgMode = false;
        }
        // add css classes, attrs, props, listeners, etc.
        {
            updateElement(null, newVNode, isSvgMode);
        }
        if (isDef(scopeId) && elm['s-si'] !== scopeId) {
            // if there is a scopeId and this is the initial render
            // then let's add the scopeId as a css class
            elm.classList.add((elm['s-si'] = scopeId));
        }
        if (newVNode.$children$) {
            for (i = 0; i < newVNode.$children$.length; ++i) {
                // create the node
                childNode = createElm(oldParentVNode, newVNode, i);
                // return node could have been null
                if (childNode) {
                    // append our new node
                    elm.appendChild(childNode);
                }
            }
        }
        {
            if (newVNode.$tag$ === 'svg') {
                // Only reset the SVG context when we're exiting <svg> element
                isSvgMode = false;
            }
            else if (elm.tagName === 'foreignObject') {
                // Reenter SVG context when we're exiting <foreignObject> element
                isSvgMode = true;
            }
        }
    }
    return elm;
};
/**
 * Create DOM nodes corresponding to a list of {@link d.Vnode} objects and
 * add them to the DOM in the appropriate place.
 *
 * @param parentElm the DOM node which should be used as a parent for the new
 * DOM nodes
 * @param before a child of the `parentElm` which the new children should be
 * inserted before (optional)
 * @param parentVNode the parent virtual DOM node
 * @param vnodes the new child virtual DOM nodes to produce DOM nodes for
 * @param startIdx the index in the child virtual DOM nodes at which to start
 * creating DOM nodes (inclusive)
 * @param endIdx the index in the child virtual DOM nodes at which to stop
 * creating DOM nodes (inclusive)
 */
const addVnodes = (parentElm, before, parentVNode, vnodes, startIdx, endIdx) => {
    let containerElm = (parentElm);
    let childNode;
    if (containerElm.shadowRoot && containerElm.tagName === hostTagName) {
        containerElm = containerElm.shadowRoot;
    }
    for (; startIdx <= endIdx; ++startIdx) {
        if (vnodes[startIdx]) {
            childNode = createElm(null, parentVNode, startIdx);
            if (childNode) {
                vnodes[startIdx].$elm$ = childNode;
                containerElm.insertBefore(childNode, before);
            }
        }
    }
};
/**
 * Remove the DOM elements corresponding to a list of {@link d.VNode} objects.
 * This can be used to, for instance, clean up after a list of children which
 * should no longer be shown.
 *
 * This function also handles some of Stencil's slot relocation logic.
 *
 * @param vnodes a list of virtual DOM nodes to remove
 * @param startIdx the index at which to start removing nodes (inclusive)
 * @param endIdx the index at which to stop removing nodes (inclusive)
 * @param vnode a VNode
 * @param elm an element
 */
const removeVnodes = (vnodes, startIdx, endIdx, vnode, elm) => {
    for (; startIdx <= endIdx; ++startIdx) {
        if ((vnode = vnodes[startIdx])) {
            elm = vnode.$elm$;
            // remove the vnode's element from the dom
            elm.remove();
        }
    }
};
/**
 * Reconcile the children of a new VNode with the children of an old VNode by
 * traversing the two collections of children, identifying nodes that are
 * conserved or changed, calling out to `patch` to make any necessary
 * updates to the DOM, and rearranging DOM nodes as needed.
 *
 * The algorithm for reconciling children works by analyzing two 'windows' onto
 * the two arrays of children (`oldCh` and `newCh`). We keep track of the
 * 'windows' by storing start and end indices and references to the
 * corresponding array entries. Initially the two 'windows' are basically equal
 * to the entire array, but we progressively narrow the windows until there are
 * no children left to update by doing the following:
 *
 * 1. Skip any `null` entries at the beginning or end of the two arrays, so
 *    that if we have an initial array like the following we'll end up dealing
 *    only with a window bounded by the highlighted elements:
 *
 *    [null, null, VNode1 , ... , VNode2, null, null]
 *                 ^^^^^^         ^^^^^^
 *
 * 2. Check to see if the elements at the head and tail positions are equal
 *    across the windows. This will basically detect elements which haven't
 *    been added, removed, or changed position, i.e. if you had the following
 *    VNode elements (represented as HTML):
 *
 *    oldVNode: `<div><p><span>HEY</span></p></div>`
 *    newVNode: `<div><p><span>THERE</span></p></div>`
 *
 *    Then when comparing the children of the `<div>` tag we check the equality
 *    of the VNodes corresponding to the `<p>` tags and, since they are the
 *    same tag in the same position, we'd be able to avoid completely
 *    re-rendering the subtree under them with a new DOM element and would just
 *    call out to `patch` to handle reconciling their children and so on.
 *
 * 3. Check, for both windows, to see if the element at the beginning of the
 *    window corresponds to the element at the end of the other window. This is
 *    a heuristic which will let us identify _some_ situations in which
 *    elements have changed position, for instance it _should_ detect that the
 *    children nodes themselves have not changed but merely moved in the
 *    following example:
 *
 *    oldVNode: `<div><element-one /><element-two /></div>`
 *    newVNode: `<div><element-two /><element-one /></div>`
 *
 *    If we find cases like this then we also need to move the concrete DOM
 *    elements corresponding to the moved children to write the re-order to the
 *    DOM.
 *
 * 4. Finally, if VNodes have the `key` attribute set on them we check for any
 *    nodes in the old children which have the same key as the first element in
 *    our window on the new children. If we find such a node we handle calling
 *    out to `patch`, moving relevant DOM nodes, and so on, in accordance with
 *    what we find.
 *
 * Finally, once we've narrowed our 'windows' to the point that either of them
 * collapse (i.e. they have length 0) we then handle any remaining VNode
 * insertion or deletion that needs to happen to get a DOM state that correctly
 * reflects the new child VNodes. If, for instance, after our window on the old
 * children has collapsed we still have more nodes on the new children that
 * we haven't dealt with yet then we need to add them, or if the new children
 * collapse but we still have unhandled _old_ children then we need to make
 * sure the corresponding DOM nodes are removed.
 *
 * @param parentElm the node into which the parent VNode is rendered
 * @param oldCh the old children of the parent node
 * @param newVNode the new VNode which will replace the parent
 * @param newCh the new children of the parent node
 */
const updateChildren = (parentElm, oldCh, newVNode, newCh) => {
    let oldStartIdx = 0;
    let newStartIdx = 0;
    let oldEndIdx = oldCh.length - 1;
    let oldStartVnode = oldCh[0];
    let oldEndVnode = oldCh[oldEndIdx];
    let newEndIdx = newCh.length - 1;
    let newStartVnode = newCh[0];
    let newEndVnode = newCh[newEndIdx];
    let node;
    while (oldStartIdx <= oldEndIdx && newStartIdx <= newEndIdx) {
        if (oldStartVnode == null) {
            // VNode might have been moved left
            oldStartVnode = oldCh[++oldStartIdx];
        }
        else if (oldEndVnode == null) {
            oldEndVnode = oldCh[--oldEndIdx];
        }
        else if (newStartVnode == null) {
            newStartVnode = newCh[++newStartIdx];
        }
        else if (newEndVnode == null) {
            newEndVnode = newCh[--newEndIdx];
        }
        else if (isSameVnode(oldStartVnode, newStartVnode)) {
            // if the start nodes are the same then we should patch the new VNode
            // onto the old one, and increment our `newStartIdx` and `oldStartIdx`
            // indices to reflect that. We don't need to move any DOM Nodes around
            // since things are matched up in order.
            patch(oldStartVnode, newStartVnode);
            oldStartVnode = oldCh[++oldStartIdx];
            newStartVnode = newCh[++newStartIdx];
        }
        else if (isSameVnode(oldEndVnode, newEndVnode)) {
            // likewise, if the end nodes are the same we patch new onto old and
            // decrement our end indices, and also likewise in this case we don't
            // need to move any DOM Nodes.
            patch(oldEndVnode, newEndVnode);
            oldEndVnode = oldCh[--oldEndIdx];
            newEndVnode = newCh[--newEndIdx];
        }
        else if (isSameVnode(oldStartVnode, newEndVnode)) {
            patch(oldStartVnode, newEndVnode);
            // We need to move the element for `oldStartVnode` into a position which
            // will be appropriate for `newEndVnode`. For this we can use
            // `.insertBefore` and `oldEndVnode.$elm$.nextSibling`. If there is a
            // sibling for `oldEndVnode.$elm$` then we want to move the DOM node for
            // `oldStartVnode` between `oldEndVnode` and it's sibling, like so:
            //
            // <old-start-node />
            // <some-intervening-node />
            // <old-end-node />
            // <!-- ->              <-- `oldStartVnode.$elm$` should be inserted here
            // <next-sibling />
            //
            // If instead `oldEndVnode.$elm$` has no sibling then we just want to put
            // the node for `oldStartVnode` at the end of the children of
            // `parentElm`. Luckily, `Node.nextSibling` will return `null` if there
            // aren't any siblings, and passing `null` to `Node.insertBefore` will
            // append it to the children of the parent element.
            parentElm.insertBefore(oldStartVnode.$elm$, oldEndVnode.$elm$.nextSibling);
            oldStartVnode = oldCh[++oldStartIdx];
            newEndVnode = newCh[--newEndIdx];
        }
        else if (isSameVnode(oldEndVnode, newStartVnode)) {
            patch(oldEndVnode, newStartVnode);
            // We've already checked above if `oldStartVnode` and `newStartVnode` are
            // the same node, so since we're here we know that they are not. Thus we
            // can move the element for `oldEndVnode` _before_ the element for
            // `oldStartVnode`, leaving `oldStartVnode` to be reconciled in the
            // future.
            parentElm.insertBefore(oldEndVnode.$elm$, oldStartVnode.$elm$);
            oldEndVnode = oldCh[--oldEndIdx];
            newStartVnode = newCh[++newStartIdx];
        }
        else {
            {
                // We either didn't find an element in the old children that matches
                // the key of the first new child OR the build is not using `key`
                // attributes at all. In either case we need to create a new element
                // for the new node.
                node = createElm(oldCh && oldCh[newStartIdx], newVNode, newStartIdx);
                newStartVnode = newCh[++newStartIdx];
            }
            if (node) {
                // if we created a new node then handle inserting it to the DOM
                {
                    oldStartVnode.$elm$.parentNode.insertBefore(node, oldStartVnode.$elm$);
                }
            }
        }
    }
    if (oldStartIdx > oldEndIdx) {
        // we have some more new nodes to add which don't match up with old nodes
        addVnodes(parentElm, newCh[newEndIdx + 1] == null ? null : newCh[newEndIdx + 1].$elm$, newVNode, newCh, newStartIdx, newEndIdx);
    }
    else if (newStartIdx > newEndIdx) {
        // there are nodes in the `oldCh` array which no longer correspond to nodes
        // in the new array, so lets remove them (which entails cleaning up the
        // relevant DOM nodes)
        removeVnodes(oldCh, oldStartIdx, oldEndIdx);
    }
};
/**
 * Compare two VNodes to determine if they are the same
 *
 * **NB**: This function is an equality _heuristic_ based on the available
 * information set on the two VNodes and can be misleading under certain
 * circumstances. In particular, if the two nodes do not have `key` attrs
 * (available under `$key$` on VNodes) then the function falls back on merely
 * checking that they have the same tag.
 *
 * So, in other words, if `key` attrs are not set on VNodes which may be
 * changing order within a `children` array or something along those lines then
 * we could obtain a false negative and then have to do needless re-rendering
 * (i.e. we'd say two VNodes aren't equal when in fact they should be).
 *
 * @param leftVNode the first VNode to check
 * @param rightVNode the second VNode to check
 * @returns whether they're equal or not
 */
const isSameVnode = (leftVNode, rightVNode) => {
    // compare if two vnode to see if they're "technically" the same
    // need to have the same element tag, and same key to be the same
    if (leftVNode.$tag$ === rightVNode.$tag$) {
        return true;
    }
    return false;
};
/**
 * Handle reconciling an outdated VNode with a new one which corresponds to
 * it. This function handles flushing updates to the DOM and reconciling the
 * children of the two nodes (if any).
 *
 * @param oldVNode an old VNode whose DOM element and children we want to update
 * @param newVNode a new VNode representing an updated version of the old one
 */
const patch = (oldVNode, newVNode) => {
    const elm = (newVNode.$elm$ = oldVNode.$elm$);
    const oldChildren = oldVNode.$children$;
    const newChildren = newVNode.$children$;
    const tag = newVNode.$tag$;
    const text = newVNode.$text$;
    if (text === null) {
        {
            // test if we're rendering an svg element, or still rendering nodes inside of one
            // only add this to the when the compiler sees we're using an svg somewhere
            isSvgMode = tag === 'svg' ? true : tag === 'foreignObject' ? false : isSvgMode;
        }
        {
            {
                // either this is the first render of an element OR it's an update
                // AND we already know it's possible it could have changed
                // this updates the element's css classes, attrs, props, listeners, etc.
                updateElement(oldVNode, newVNode, isSvgMode);
            }
        }
        if (oldChildren !== null && newChildren !== null) {
            // looks like there's child vnodes for both the old and new vnodes
            // so we need to call `updateChildren` to reconcile them
            updateChildren(elm, oldChildren, newVNode, newChildren);
        }
        else if (newChildren !== null) {
            // no old child vnodes, but there are new child vnodes to add
            if (oldVNode.$text$ !== null) {
                // the old vnode was text, so be sure to clear it out
                elm.textContent = '';
            }
            // add the new vnode children
            addVnodes(elm, null, newVNode, newChildren, 0, newChildren.length - 1);
        }
        else if (oldChildren !== null) {
            // no new child vnodes, but there are old child vnodes to remove
            removeVnodes(oldChildren, 0, oldChildren.length - 1);
        }
        if (isSvgMode && tag === 'svg') {
            isSvgMode = false;
        }
    }
    else if (oldVNode.$text$ !== text) {
        // update the text content for the text only vnode
        // and also only if the text is different than before
        elm.data = text;
    }
};
/**
 * The main entry point for Stencil's virtual DOM-based rendering engine
 *
 * Given a {@link d.HostRef} container and some virtual DOM nodes, this
 * function will handle creating a virtual DOM tree with a single root, patching
 * the current virtual DOM tree onto an old one (if any), dealing with slot
 * relocation, and reflecting attributes.
 *
 * @param hostRef data needed to root and render the virtual DOM tree, such as
 * the DOM node into which it should be rendered.
 * @param renderFnResults the virtual DOM nodes to be rendered
 */
const renderVdom = (hostRef, renderFnResults) => {
    const hostElm = hostRef.$hostElement$;
    const oldVNode = hostRef.$vnode$ || newVNode(null, null);
    const rootVnode = isHost(renderFnResults) ? renderFnResults : h$1(null, null, renderFnResults);
    hostTagName = hostElm.tagName;
    rootVnode.$tag$ = null;
    rootVnode.$flags$ |= 4 /* VNODE_FLAGS.isHost */;
    hostRef.$vnode$ = rootVnode;
    rootVnode.$elm$ = oldVNode.$elm$ = (hostElm.shadowRoot || hostElm );
    {
        scopeId = hostElm['s-sc'];
    }
    // synchronous patch
    patch(oldVNode, rootVnode);
};
const attachToAncestor = (hostRef, ancestorComponent) => {
    if (ancestorComponent && !hostRef.$onRenderResolve$ && ancestorComponent['s-p']) {
        ancestorComponent['s-p'].push(new Promise((r) => (hostRef.$onRenderResolve$ = r)));
    }
};
const scheduleUpdate = (hostRef, isInitialLoad) => {
    {
        hostRef.$flags$ |= 16 /* HOST_FLAGS.isQueuedForUpdate */;
    }
    if (hostRef.$flags$ & 4 /* HOST_FLAGS.isWaitingForChildren */) {
        hostRef.$flags$ |= 512 /* HOST_FLAGS.needsRerender */;
        return;
    }
    attachToAncestor(hostRef, hostRef.$ancestorComponent$);
    // there is no ancestor component or the ancestor component
    // has already fired off its lifecycle update then
    // fire off the initial update
    const dispatch = () => dispatchHooks(hostRef, isInitialLoad);
    return writeTask(dispatch) ;
};
const dispatchHooks = (hostRef, isInitialLoad) => {
    const endSchedule = createTime('scheduleUpdate', hostRef.$cmpMeta$.$tagName$);
    const instance = hostRef.$lazyInstance$ ;
    let promise;
    endSchedule();
    return then(promise, () => updateComponent(hostRef, instance, isInitialLoad));
};
const updateComponent = async (hostRef, instance, isInitialLoad) => {
    // updateComponent
    const elm = hostRef.$hostElement$;
    const endUpdate = createTime('update', hostRef.$cmpMeta$.$tagName$);
    const rc = elm['s-rc'];
    if (isInitialLoad) {
        // DOM WRITE!
        attachStyles(hostRef);
    }
    const endRender = createTime('render', hostRef.$cmpMeta$.$tagName$);
    {
        callRender(hostRef, instance);
    }
    if (rc) {
        // ok, so turns out there are some child host elements
        // waiting on this parent element to load
        // let's fire off all update callbacks waiting
        rc.map((cb) => cb());
        elm['s-rc'] = undefined;
    }
    endRender();
    endUpdate();
    {
        const childrenPromises = elm['s-p'];
        const postUpdate = () => postUpdateComponent(hostRef);
        if (childrenPromises.length === 0) {
            postUpdate();
        }
        else {
            Promise.all(childrenPromises).then(postUpdate);
            hostRef.$flags$ |= 4 /* HOST_FLAGS.isWaitingForChildren */;
            childrenPromises.length = 0;
        }
    }
};
const callRender = (hostRef, instance, elm) => {
    try {
        instance = instance.render() ;
        {
            hostRef.$flags$ &= ~16 /* HOST_FLAGS.isQueuedForUpdate */;
        }
        {
            hostRef.$flags$ |= 2 /* HOST_FLAGS.hasRendered */;
        }
        {
            {
                // looks like we've got child nodes to render into this host element
                // or we need to update the css class/attrs on the host element
                // DOM WRITE!
                {
                    renderVdom(hostRef, instance);
                }
            }
        }
    }
    catch (e) {
        consoleError(e, hostRef.$hostElement$);
    }
    return null;
};
const postUpdateComponent = (hostRef) => {
    const tagName = hostRef.$cmpMeta$.$tagName$;
    const elm = hostRef.$hostElement$;
    const endPostUpdate = createTime('postUpdate', tagName);
    const ancestorComponent = hostRef.$ancestorComponent$;
    if (!(hostRef.$flags$ & 64 /* HOST_FLAGS.hasLoadedComponent */)) {
        hostRef.$flags$ |= 64 /* HOST_FLAGS.hasLoadedComponent */;
        {
            // DOM WRITE!
            addHydratedFlag(elm);
        }
        endPostUpdate();
        {
            hostRef.$onReadyResolve$(elm);
            if (!ancestorComponent) {
                appDidLoad();
            }
        }
    }
    else {
        endPostUpdate();
    }
    // load events fire from bottom to top
    // the deepest elements load first then bubbles up
    {
        if (hostRef.$onRenderResolve$) {
            hostRef.$onRenderResolve$();
            hostRef.$onRenderResolve$ = undefined;
        }
        if (hostRef.$flags$ & 512 /* HOST_FLAGS.needsRerender */) {
            nextTick(() => scheduleUpdate(hostRef, false));
        }
        hostRef.$flags$ &= -517;
    }
    // ( •_•)
    // ( •_•)>⌐■-■
    // (⌐■_■)
};
const appDidLoad = (who) => {
    // on appload
    // we have finish the first big initial render
    {
        addHydratedFlag(doc.documentElement);
    }
    nextTick(() => emitEvent(win, 'appload', { detail: { namespace: NAMESPACE } }));
};
const then = (promise, thenFn) => {
    return promise && promise.then ? promise.then(thenFn) : thenFn();
};
const addHydratedFlag = (elm) => elm.classList.add('hydrated')
    ;
const getValue = (ref, propName) => getHostRef(ref).$instanceValues$.get(propName);
const setValue = (ref, propName, newVal, cmpMeta) => {
    // check our new property value against our internal value
    const hostRef = getHostRef(ref);
    const oldVal = hostRef.$instanceValues$.get(propName);
    const flags = hostRef.$flags$;
    const instance = hostRef.$lazyInstance$ ;
    newVal = parsePropertyValue(newVal);
    // explicitly check for NaN on both sides, as `NaN === NaN` is always false
    const areBothNaN = Number.isNaN(oldVal) && Number.isNaN(newVal);
    const didValueChange = newVal !== oldVal && !areBothNaN;
    if ((!(flags & 8 /* HOST_FLAGS.isConstructingInstance */) || oldVal === undefined) && didValueChange) {
        // gadzooks! the property's value has changed!!
        // set our new value!
        hostRef.$instanceValues$.set(propName, newVal);
        if (instance) {
            if ((flags & (2 /* HOST_FLAGS.hasRendered */ | 16 /* HOST_FLAGS.isQueuedForUpdate */)) === 2 /* HOST_FLAGS.hasRendered */) {
                // looks like this value actually changed, so we've got work to do!
                // but only if we've already rendered, otherwise just chill out
                // queue that we need to do an update, but don't worry about queuing
                // up millions cuz this function ensures it only runs once
                scheduleUpdate(hostRef, false);
            }
        }
    }
};
/**
 * Attach a series of runtime constructs to a compiled Stencil component
 * constructor, including getters and setters for the `@Prop` and `@State`
 * decorators, callbacks for when attributes change, and so on.
 *
 * @param Cstr the constructor for a component that we need to process
 * @param cmpMeta metadata collected previously about the component
 * @param flags a number used to store a series of bit flags
 * @returns a reference to the same constructor passed in (but now mutated)
 */
const proxyComponent = (Cstr, cmpMeta, flags) => {
    if (cmpMeta.$members$) {
        // It's better to have a const than two Object.entries()
        const members = Object.entries(cmpMeta.$members$);
        const prototype = Cstr.prototype;
        members.map(([memberName, [memberFlags]]) => {
            if ((memberFlags & 31 /* MEMBER_FLAGS.Prop */ ||
                    ((flags & 2 /* PROXY_FLAGS.proxyState */) && memberFlags & 32 /* MEMBER_FLAGS.State */))) {
                // proxyComponent - prop
                Object.defineProperty(prototype, memberName, {
                    get() {
                        // proxyComponent, get value
                        return getValue(this, memberName);
                    },
                    set(newValue) {
                        // proxyComponent, set value
                        setValue(this, memberName, newValue);
                    },
                    configurable: true,
                    enumerable: true,
                });
            }
        });
    }
    return Cstr;
};
const initializeComponent = async (elm, hostRef, cmpMeta, hmrVersionId, Cstr) => {
    // initializeComponent
    if ((hostRef.$flags$ & 32 /* HOST_FLAGS.hasInitializedComponent */) === 0) {
        {
            // we haven't initialized this element yet
            hostRef.$flags$ |= 32 /* HOST_FLAGS.hasInitializedComponent */;
            // lazy loaded components
            // request the component's implementation to be
            // wired up with the host element
            Cstr = loadModule(cmpMeta);
            if (Cstr.then) {
                // Await creates a micro-task avoid if possible
                const endLoad = uniqueTime();
                Cstr = await Cstr;
                endLoad();
            }
            if (!Cstr.isProxied) {
                proxyComponent(Cstr, cmpMeta, 2 /* PROXY_FLAGS.proxyState */);
                Cstr.isProxied = true;
            }
            const endNewInstance = createTime('createInstance', cmpMeta.$tagName$);
            // ok, time to construct the instance
            // but let's keep track of when we start and stop
            // so that the getters/setters don't incorrectly step on data
            {
                hostRef.$flags$ |= 8 /* HOST_FLAGS.isConstructingInstance */;
            }
            // construct the lazy-loaded component implementation
            // passing the hostRef is very important during
            // construction in order to directly wire together the
            // host element and the lazy-loaded instance
            try {
                new Cstr(hostRef);
            }
            catch (e) {
                consoleError(e);
            }
            {
                hostRef.$flags$ &= -9 /* HOST_FLAGS.isConstructingInstance */;
            }
            endNewInstance();
        }
        if (Cstr.style) {
            // this component has styles but we haven't registered them yet
            let style = Cstr.style;
            const scopeId = getScopeId(cmpMeta);
            if (!styles.has(scopeId)) {
                const endRegisterStyles = createTime('registerStyles', cmpMeta.$tagName$);
                registerStyle(scopeId, style, !!(cmpMeta.$flags$ & 1 /* CMP_FLAGS.shadowDomEncapsulation */));
                endRegisterStyles();
            }
        }
    }
    // we've successfully created a lazy instance
    const ancestorComponent = hostRef.$ancestorComponent$;
    const schedule = () => scheduleUpdate(hostRef, true);
    if (ancestorComponent && ancestorComponent['s-rc']) {
        // this is the initial load and this component it has an ancestor component
        // but the ancestor component has NOT fired its will update lifecycle yet
        // so let's just cool our jets and wait for the ancestor to continue first
        // this will get fired off when the ancestor component
        // finally gets around to rendering its lazy self
        // fire off the initial update
        ancestorComponent['s-rc'].push(schedule);
    }
    else {
        schedule();
    }
};
const connectedCallback = (elm) => {
    if ((plt.$flags$ & 1 /* PLATFORM_FLAGS.isTmpDisconnected */) === 0) {
        const hostRef = getHostRef(elm);
        const cmpMeta = hostRef.$cmpMeta$;
        const endConnected = createTime('connectedCallback', cmpMeta.$tagName$);
        if (!(hostRef.$flags$ & 1 /* HOST_FLAGS.hasConnected */)) {
            // first time this component has connected
            hostRef.$flags$ |= 1 /* HOST_FLAGS.hasConnected */;
            {
                // find the first ancestor component (if there is one) and register
                // this component as one of the actively loading child components for its ancestor
                let ancestorComponent = elm;
                while ((ancestorComponent = ancestorComponent.parentNode || ancestorComponent.host)) {
                    // climb up the ancestors looking for the first
                    // component that hasn't finished its lifecycle update yet
                    if (ancestorComponent['s-p']) {
                        // we found this components first ancestor component
                        // keep a reference to this component's ancestor component
                        attachToAncestor(hostRef, (hostRef.$ancestorComponent$ = ancestorComponent));
                        break;
                    }
                }
            }
            // Lazy properties
            // https://developers.google.com/web/fundamentals/web-components/best-practices#lazy-properties
            if (cmpMeta.$members$) {
                Object.entries(cmpMeta.$members$).map(([memberName, [memberFlags]]) => {
                    if (memberFlags & 31 /* MEMBER_FLAGS.Prop */ && elm.hasOwnProperty(memberName)) {
                        const value = elm[memberName];
                        delete elm[memberName];
                        elm[memberName] = value;
                    }
                });
            }
            {
                initializeComponent(elm, hostRef, cmpMeta);
            }
        }
        endConnected();
    }
};
const disconnectedCallback = (elm) => {
    if ((plt.$flags$ & 1 /* PLATFORM_FLAGS.isTmpDisconnected */) === 0) {
        getHostRef(elm);
    }
};
const bootstrapLazy = (lazyBundles, options = {}) => {
    var _a;
    const endBootstrap = createTime();
    const cmpTags = [];
    const exclude = options.exclude || [];
    const customElements = win.customElements;
    const head = doc.head;
    const metaCharset = /*@__PURE__*/ head.querySelector('meta[charset]');
    const visibilityStyle = /*@__PURE__*/ doc.createElement('style');
    const deferredConnectedCallbacks = [];
    let appLoadFallback;
    let isBootstrapping = true;
    Object.assign(plt, options);
    plt.$resourcesUrl$ = new URL(options.resourcesUrl || './', doc.baseURI).href;
    lazyBundles.map((lazyBundle) => {
        lazyBundle[1].map((compactMeta) => {
            const cmpMeta = {
                $flags$: compactMeta[0],
                $tagName$: compactMeta[1],
                $members$: compactMeta[2],
                $listeners$: compactMeta[3],
            };
            {
                cmpMeta.$members$ = compactMeta[2];
            }
            const tagName = cmpMeta.$tagName$;
            const HostElement = class extends HTMLElement {
                // StencilLazyHost
                constructor(self) {
                    // @ts-ignore
                    super(self);
                    self = this;
                    registerHost(self, cmpMeta);
                    if (cmpMeta.$flags$ & 1 /* CMP_FLAGS.shadowDomEncapsulation */) {
                        // this component is using shadow dom
                        // and this browser supports shadow dom
                        // add the read-only property "shadowRoot" to the host element
                        // adding the shadow root build conditionals to minimize runtime
                        {
                            {
                                self.attachShadow({ mode: 'open' });
                            }
                        }
                    }
                }
                connectedCallback() {
                    if (appLoadFallback) {
                        clearTimeout(appLoadFallback);
                        appLoadFallback = null;
                    }
                    if (isBootstrapping) {
                        // connectedCallback will be processed once all components have been registered
                        deferredConnectedCallbacks.push(this);
                    }
                    else {
                        plt.jmp(() => connectedCallback(this));
                    }
                }
                disconnectedCallback() {
                    plt.jmp(() => disconnectedCallback(this));
                }
                componentOnReady() {
                    return getHostRef(this).$onReadyPromise$;
                }
            };
            cmpMeta.$lazyBundleId$ = lazyBundle[0];
            if (!exclude.includes(tagName) && !customElements.get(tagName)) {
                cmpTags.push(tagName);
                customElements.define(tagName, proxyComponent(HostElement, cmpMeta, 1 /* PROXY_FLAGS.isElementConstructor */));
            }
        });
    });
    {
        visibilityStyle.innerHTML = cmpTags + HYDRATED_CSS;
        visibilityStyle.setAttribute('data-styles', '');
        // Apply CSP nonce to the style tag if it exists
        const nonce = (_a = plt.$nonce$) !== null && _a !== void 0 ? _a : queryNonceMetaTagContent(doc);
        if (nonce != null) {
            visibilityStyle.setAttribute('nonce', nonce);
        }
        head.insertBefore(visibilityStyle, metaCharset ? metaCharset.nextSibling : head.firstChild);
    }
    // Process deferred connectedCallbacks now all components have been registered
    isBootstrapping = false;
    if (deferredConnectedCallbacks.length) {
        deferredConnectedCallbacks.map((host) => host.connectedCallback());
    }
    else {
        {
            plt.jmp(() => (appLoadFallback = setTimeout(appDidLoad, 30)));
        }
    }
    // Fallback appLoad event
    endBootstrap();
};
const hostRefs = /*@__PURE__*/ new WeakMap();
const getHostRef = (ref) => hostRefs.get(ref);
const registerInstance = (lazyInstance, hostRef) => hostRefs.set((hostRef.$lazyInstance$ = lazyInstance), hostRef);
const registerHost = (elm, cmpMeta) => {
    const hostRef = {
        $flags$: 0,
        $hostElement$: elm,
        $cmpMeta$: cmpMeta,
        $instanceValues$: new Map(),
    };
    {
        hostRef.$onReadyPromise$ = new Promise((r) => (hostRef.$onReadyResolve$ = r));
        elm['s-p'] = [];
        elm['s-rc'] = [];
    }
    return hostRefs.set(elm, hostRef);
};
const isMemberInElement = (elm, memberName) => memberName in elm;
const consoleError = (e, el) => (0, console.error)(e, el);
const cmpModules = /*@__PURE__*/ new Map();
const loadModule = (cmpMeta, hostRef, hmrVersionId) => {
    // loadModuleImport
    const exportName = cmpMeta.$tagName$.replace(/-/g, '_');
    const bundleId = cmpMeta.$lazyBundleId$;
    const module = cmpModules.get(bundleId) ;
    if (module) {
        return module[exportName];
    }
    
    {
      const processMod = importedModule => {
        cmpModules.set(bundleId, importedModule);
        return importedModule[exportName];
      };
      switch(bundleId) {
        
        case 'connect-modal':
          return Promise.resolve().then(function () { return connectModal_entry; }).then(processMod, consoleError);
      }
    }
    return import(
    /* @vite-ignore */
    /* webpackInclude: /\.entry\.js$/ */
    /* webpackExclude: /\.system\.entry\.js$/ */
    /* webpackMode: "lazy" */
    `./${bundleId}.entry.js${''}`).then((importedModule) => {
        {
            cmpModules.set(bundleId, importedModule);
        }
        return importedModule[exportName];
    }, consoleError);
};
const styles = /*@__PURE__*/ new Map();
const win = typeof window !== 'undefined' ? window : {};
const doc = win.document || { head: {} };
const plt = {
    $flags$: 0,
    $resourcesUrl$: '',
    jmp: (h) => h(),
    raf: (h) => requestAnimationFrame(h),
    ael: (el, eventName, listener, opts) => el.addEventListener(eventName, listener, opts),
    rel: (el, eventName, listener, opts) => el.removeEventListener(eventName, listener, opts),
    ce: (eventName, opts) => new CustomEvent(eventName, opts),
};
const promiseResolve = (v) => Promise.resolve(v);
const supportsConstructableStylesheets = /*@__PURE__*/ (() => {
        try {
            new CSSStyleSheet();
            return typeof new CSSStyleSheet().replaceSync === 'function';
        }
        catch (e) { }
        return false;
    })()
    ;
const queueDomReads = [];
const queueDomWrites = [];
const queueTask = (queue, write) => (cb) => {
    queue.push(cb);
    if (!queuePending) {
        queuePending = true;
        if (plt.$flags$ & 4 /* PLATFORM_FLAGS.queueSync */) {
            nextTick(flush);
        }
        else {
            plt.raf(flush);
        }
    }
};
const consume = (queue) => {
    for (let i = 0; i < queue.length; i++) {
        try {
            queue[i](performance.now());
        }
        catch (e) {
            consoleError(e);
        }
    }
    queue.length = 0;
};
const flush = () => {
    // always force a bunch of medium callbacks to run, but still have
    // a throttle on how many can run in a certain time
    // DOM READS!!!
    consume(queueDomReads);
    // DOM WRITES!!!
    {
        consume(queueDomWrites);
        if ((queuePending = queueDomReads.length > 0)) {
            // still more to do yet, but we've run out of time
            // let's let this thing cool off and try again in the next tick
            plt.raf(flush);
        }
    }
};
const nextTick =  (cb) => promiseResolve().then(cb);
const writeTask = /*@__PURE__*/ queueTask(queueDomWrites);

/*
 Stencil Client Patch Esm v2.22.3 | MIT Licensed | https://stenciljs.com
 */
const patchEsm = () => {
    return promiseResolve();
};

const defineCustomElements = (win, options) => {
  if (typeof window === 'undefined') return Promise.resolve();
  return patchEsm().then(() => {
  return bootstrapLazy([["connect-modal",[[1,"connect-modal",{"defaultProviders":[16],"installedProviders":[16],"callback":[16],"cancelCallback":[16]}]]]], options);
  });
};

(function(){if("undefined"!==typeof window&&void 0!==window.Reflect&&void 0!==window.customElements){var a=HTMLElement;window.HTMLElement=function(){return Reflect.construct(a,[],this.constructor)};HTMLElement.prototype=a.prototype;HTMLElement.prototype.constructor=HTMLElement;Object.setPrototypeOf(HTMLElement,a);}})();

function createEnumChecker(enumVariable) {
    const enumValues = Object.values(enumVariable).filter(v => typeof v === 'number');
    const enumValueSet = new Set(enumValues);
    return (value) => enumValueSet.has(value);
}
const enumCheckFunctions = new Map();
function isEnum(enumVariable, value) {
    const checker = enumCheckFunctions.get(enumVariable);
    if (checker !== undefined) {
        return checker(value);
    }
    const newChecker = createEnumChecker(enumVariable);
    enumCheckFunctions.set(enumVariable, newChecker);
    return isEnum(enumVariable, value);
}
class BytesReader {
    constructor(bytes) {
        this.consumed = 0;
        this.source = typeof bytes === 'string' ? hexToBytes$2(bytes) : bytes;
    }
    readBytes(length) {
        const view = this.source.subarray(this.consumed, this.consumed + length);
        this.consumed += length;
        return view;
    }
    readUInt32BE() {
        return readUInt32BE(this.readBytes(4), 0);
    }
    readUInt8() {
        return readUInt8(this.readBytes(1), 0);
    }
    readUInt16BE() {
        return readUInt16BE(this.readBytes(2), 0);
    }
    readBigUIntLE(length) {
        const bytes = this.readBytes(length).slice().reverse();
        const hex = bytesToHex$2(bytes);
        return BigInt(`0x${hex}`);
    }
    readBigUIntBE(length) {
        const bytes = this.readBytes(length);
        const hex = bytesToHex$2(bytes);
        return BigInt(`0x${hex}`);
    }
    get readOffset() {
        return this.consumed;
    }
    set readOffset(val) {
        this.consumed = val;
    }
    get internalBytes() {
        return this.source;
    }
    readUInt8Enum(enumVariable, invalidEnumErrorFormatter) {
        const num = this.readUInt8();
        if (isEnum(enumVariable, num)) {
            return num;
        }
        throw invalidEnumErrorFormatter(num);
    }
}

var ChainId;
(function (ChainId) {
    ChainId[ChainId["Mainnet"] = 1] = "Mainnet";
    ChainId[ChainId["Testnet"] = 2147483648] = "Testnet";
})(ChainId || (ChainId = {}));
var PeerNetworkId;
(function (PeerNetworkId) {
    PeerNetworkId[PeerNetworkId["Mainnet"] = 385875968] = "Mainnet";
    PeerNetworkId[PeerNetworkId["Testnet"] = 4278190080] = "Testnet";
})(PeerNetworkId || (PeerNetworkId = {}));
ChainId.Mainnet;
var TransactionVersion$2;
(function (TransactionVersion) {
    TransactionVersion[TransactionVersion["Mainnet"] = 0] = "Mainnet";
    TransactionVersion[TransactionVersion["Testnet"] = 128] = "Testnet";
})(TransactionVersion$2 || (TransactionVersion$2 = {}));
var AddressVersion$1;
(function (AddressVersion) {
    AddressVersion[AddressVersion["MainnetSingleSig"] = 22] = "MainnetSingleSig";
    AddressVersion[AddressVersion["MainnetMultiSig"] = 20] = "MainnetMultiSig";
    AddressVersion[AddressVersion["TestnetSingleSig"] = 26] = "TestnetSingleSig";
    AddressVersion[AddressVersion["TestnetMultiSig"] = 21] = "TestnetMultiSig";
})(AddressVersion$1 || (AddressVersion$1 = {}));
TransactionVersion$2.Mainnet;

const STACKS_MAINNET = {
    chainId: ChainId.Mainnet,
    transactionVersion: TransactionVersion$2.Mainnet,
    peerNetworkId: PeerNetworkId.Mainnet,
    magicBytes: 'X2',
    bootAddress: 'SP000000000000000000002Q6VF78',
    addressVersion: {
        singleSig: AddressVersion$1.MainnetSingleSig,
        multiSig: AddressVersion$1.MainnetMultiSig,
    },
    client: { baseUrl: HIRO_MAINNET_URL },
};
const STACKS_TESTNET = {
    chainId: ChainId.Testnet,
    transactionVersion: TransactionVersion$2.Testnet,
    peerNetworkId: PeerNetworkId.Testnet,
    magicBytes: 'T2',
    bootAddress: 'ST000000000000000000002AMW42H',
    addressVersion: {
        singleSig: AddressVersion$1.TestnetSingleSig,
        multiSig: AddressVersion$1.TestnetMultiSig,
    },
    client: { baseUrl: HIRO_TESTNET_URL },
};
const STACKS_DEVNET = {
    ...STACKS_TESTNET,
    addressVersion: { ...STACKS_TESTNET.addressVersion },
    magicBytes: 'id',
    client: { baseUrl: DEVNET_URL },
};
const STACKS_MOCKNET = {
    ...STACKS_DEVNET,
    addressVersion: { ...STACKS_DEVNET.addressVersion },
    client: { ...STACKS_DEVNET.client },
};
function networkFromName(name) {
    switch (name) {
        case 'mainnet':
            return STACKS_MAINNET;
        case 'testnet':
            return STACKS_TESTNET;
        case 'devnet':
            return STACKS_DEVNET;
        case 'mocknet':
            return STACKS_MOCKNET;
        default:
            throw new Error(`Unknown network name: ${name}`);
    }
}
function networkFrom(network) {
    if (typeof network === 'string')
        return networkFromName(network);
    return network;
}

const MAX_STRING_LENGTH_BYTES$1 = 128;
const CLARITY_INT_SIZE$1 = 128;
const CLARITY_INT_BYTE_SIZE$1 = 16;
const COINBASE_BYTES_LENGTH = 32;
const VRF_PROOF_BYTES_LENGTH = 80;
const RECOVERABLE_ECDSA_SIG_LENGTH_BYTES = 65;
const COMPRESSED_PUBKEY_LENGTH_BYTES = 32;
const UNCOMPRESSED_PUBKEY_LENGTH_BYTES = 64;
const MEMO_MAX_LENGTH_BYTES = 34;
const MAX_PAYLOAD_LEN = 1 + 16 * 1024 * 1024;
const PREAMBLE_ENCODED_SIZE = 165;
const MAX_RELAYERS_LEN = 16;
const PEER_ADDRESS_ENCODED_SIZE = 16;
const HASH160_ENCODED_SIZE = 20;
const NEIGHBOR_ADDRESS_ENCODED_SIZE = PEER_ADDRESS_ENCODED_SIZE + 2 + HASH160_ENCODED_SIZE;
const RELAY_DATA_ENCODED_SIZE = NEIGHBOR_ADDRESS_ENCODED_SIZE + 4;
const STRING_MAX_LENGTH = MAX_PAYLOAD_LEN + (PREAMBLE_ENCODED_SIZE + MAX_RELAYERS_LEN * RELAY_DATA_ENCODED_SIZE);
var PayloadType$1;
(function (PayloadType) {
    PayloadType[PayloadType["TokenTransfer"] = 0] = "TokenTransfer";
    PayloadType[PayloadType["SmartContract"] = 1] = "SmartContract";
    PayloadType[PayloadType["VersionedSmartContract"] = 6] = "VersionedSmartContract";
    PayloadType[PayloadType["ContractCall"] = 2] = "ContractCall";
    PayloadType[PayloadType["PoisonMicroblock"] = 3] = "PoisonMicroblock";
    PayloadType[PayloadType["Coinbase"] = 4] = "Coinbase";
    PayloadType[PayloadType["CoinbaseToAltRecipient"] = 5] = "CoinbaseToAltRecipient";
    PayloadType[PayloadType["TenureChange"] = 7] = "TenureChange";
    PayloadType[PayloadType["NakamotoCoinbase"] = 8] = "NakamotoCoinbase";
})(PayloadType$1 || (PayloadType$1 = {}));
var ClarityVersion$1;
(function (ClarityVersion) {
    ClarityVersion[ClarityVersion["Clarity1"] = 1] = "Clarity1";
    ClarityVersion[ClarityVersion["Clarity2"] = 2] = "Clarity2";
    ClarityVersion[ClarityVersion["Clarity3"] = 3] = "Clarity3";
})(ClarityVersion$1 || (ClarityVersion$1 = {}));
var AnchorMode$1;
(function (AnchorMode) {
    AnchorMode[AnchorMode["OnChainOnly"] = 1] = "OnChainOnly";
    AnchorMode[AnchorMode["OffChainOnly"] = 2] = "OffChainOnly";
    AnchorMode[AnchorMode["Any"] = 3] = "Any";
})(AnchorMode$1 || (AnchorMode$1 = {}));
const AnchorModeNames$1 = ['onChainOnly', 'offChainOnly', 'any'];
({
    [AnchorModeNames$1[0]]: AnchorMode$1.OnChainOnly,
    [AnchorModeNames$1[1]]: AnchorMode$1.OffChainOnly,
    [AnchorModeNames$1[2]]: AnchorMode$1.Any,
    [AnchorMode$1.OnChainOnly]: AnchorMode$1.OnChainOnly,
    [AnchorMode$1.OffChainOnly]: AnchorMode$1.OffChainOnly,
    [AnchorMode$1.Any]: AnchorMode$1.Any,
});
var PostConditionMode$1;
(function (PostConditionMode) {
    PostConditionMode[PostConditionMode["Allow"] = 1] = "Allow";
    PostConditionMode[PostConditionMode["Deny"] = 2] = "Deny";
})(PostConditionMode$1 || (PostConditionMode$1 = {}));
var PostConditionType$1;
(function (PostConditionType) {
    PostConditionType[PostConditionType["STX"] = 0] = "STX";
    PostConditionType[PostConditionType["Fungible"] = 1] = "Fungible";
    PostConditionType[PostConditionType["NonFungible"] = 2] = "NonFungible";
})(PostConditionType$1 || (PostConditionType$1 = {}));
var AuthType$1;
(function (AuthType) {
    AuthType[AuthType["Standard"] = 4] = "Standard";
    AuthType[AuthType["Sponsored"] = 5] = "Sponsored";
})(AuthType$1 || (AuthType$1 = {}));
var AddressHashMode$1;
(function (AddressHashMode) {
    AddressHashMode[AddressHashMode["P2PKH"] = 0] = "P2PKH";
    AddressHashMode[AddressHashMode["P2SH"] = 1] = "P2SH";
    AddressHashMode[AddressHashMode["P2WPKH"] = 2] = "P2WPKH";
    AddressHashMode[AddressHashMode["P2WSH"] = 3] = "P2WSH";
    AddressHashMode[AddressHashMode["P2SHNonSequential"] = 5] = "P2SHNonSequential";
    AddressHashMode[AddressHashMode["P2WSHNonSequential"] = 7] = "P2WSHNonSequential";
})(AddressHashMode$1 || (AddressHashMode$1 = {}));
var PubKeyEncoding$1;
(function (PubKeyEncoding) {
    PubKeyEncoding[PubKeyEncoding["Compressed"] = 0] = "Compressed";
    PubKeyEncoding[PubKeyEncoding["Uncompressed"] = 1] = "Uncompressed";
})(PubKeyEncoding$1 || (PubKeyEncoding$1 = {}));
var FungibleConditionCode$1;
(function (FungibleConditionCode) {
    FungibleConditionCode[FungibleConditionCode["Equal"] = 1] = "Equal";
    FungibleConditionCode[FungibleConditionCode["Greater"] = 2] = "Greater";
    FungibleConditionCode[FungibleConditionCode["GreaterEqual"] = 3] = "GreaterEqual";
    FungibleConditionCode[FungibleConditionCode["Less"] = 4] = "Less";
    FungibleConditionCode[FungibleConditionCode["LessEqual"] = 5] = "LessEqual";
})(FungibleConditionCode$1 || (FungibleConditionCode$1 = {}));
var NonFungibleConditionCode$1;
(function (NonFungibleConditionCode) {
    NonFungibleConditionCode[NonFungibleConditionCode["Sends"] = 16] = "Sends";
    NonFungibleConditionCode[NonFungibleConditionCode["DoesNotSend"] = 17] = "DoesNotSend";
})(NonFungibleConditionCode$1 || (NonFungibleConditionCode$1 = {}));
var PostConditionPrincipalId;
(function (PostConditionPrincipalId) {
    PostConditionPrincipalId[PostConditionPrincipalId["Origin"] = 1] = "Origin";
    PostConditionPrincipalId[PostConditionPrincipalId["Standard"] = 2] = "Standard";
    PostConditionPrincipalId[PostConditionPrincipalId["Contract"] = 3] = "Contract";
})(PostConditionPrincipalId || (PostConditionPrincipalId = {}));
var AssetType$1;
(function (AssetType) {
    AssetType[AssetType["STX"] = 0] = "STX";
    AssetType[AssetType["Fungible"] = 1] = "Fungible";
    AssetType[AssetType["NonFungible"] = 2] = "NonFungible";
})(AssetType$1 || (AssetType$1 = {}));
var TenureChangeCause;
(function (TenureChangeCause) {
    TenureChangeCause[TenureChangeCause["BlockFound"] = 0] = "BlockFound";
    TenureChangeCause[TenureChangeCause["Extended"] = 1] = "Extended";
})(TenureChangeCause || (TenureChangeCause = {}));
var AuthFieldType;
(function (AuthFieldType) {
    AuthFieldType[AuthFieldType["PublicKeyCompressed"] = 0] = "PublicKeyCompressed";
    AuthFieldType[AuthFieldType["PublicKeyUncompressed"] = 1] = "PublicKeyUncompressed";
    AuthFieldType[AuthFieldType["SignatureCompressed"] = 2] = "SignatureCompressed";
    AuthFieldType[AuthFieldType["SignatureUncompressed"] = 3] = "SignatureUncompressed";
})(AuthFieldType || (AuthFieldType = {}));
var TxRejectedReason$1;
(function (TxRejectedReason) {
    TxRejectedReason["Serialization"] = "Serialization";
    TxRejectedReason["Deserialization"] = "Deserialization";
    TxRejectedReason["SignatureValidation"] = "SignatureValidation";
    TxRejectedReason["FeeTooLow"] = "FeeTooLow";
    TxRejectedReason["BadNonce"] = "BadNonce";
    TxRejectedReason["NotEnoughFunds"] = "NotEnoughFunds";
    TxRejectedReason["NoSuchContract"] = "NoSuchContract";
    TxRejectedReason["NoSuchPublicFunction"] = "NoSuchPublicFunction";
    TxRejectedReason["BadFunctionArgument"] = "BadFunctionArgument";
    TxRejectedReason["ContractAlreadyExists"] = "ContractAlreadyExists";
    TxRejectedReason["PoisonMicroblocksDoNotConflict"] = "PoisonMicroblocksDoNotConflict";
    TxRejectedReason["PoisonMicroblockHasUnknownPubKeyHash"] = "PoisonMicroblockHasUnknownPubKeyHash";
    TxRejectedReason["PoisonMicroblockIsInvalid"] = "PoisonMicroblockIsInvalid";
    TxRejectedReason["BadAddressVersionByte"] = "BadAddressVersionByte";
    TxRejectedReason["NoCoinbaseViaMempool"] = "NoCoinbaseViaMempool";
    TxRejectedReason["ServerFailureNoSuchChainTip"] = "ServerFailureNoSuchChainTip";
    TxRejectedReason["ServerFailureDatabase"] = "ServerFailureDatabase";
    TxRejectedReason["ServerFailureOther"] = "ServerFailureOther";
})(TxRejectedReason$1 || (TxRejectedReason$1 = {}));

let TransactionError$1 = class TransactionError extends Error {
    constructor(message) {
        super(message);
        this.message = message;
        this.name = this.constructor.name;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
};
let SerializationError$1 = class SerializationError extends TransactionError$1 {
    constructor(message) {
        super(message);
    }
};
class DeserializationError extends TransactionError$1 {
    constructor(message) {
        super(message);
    }
}
class SigningError extends TransactionError$1 {
    constructor(message) {
        super(message);
    }
}
class VerificationError extends TransactionError$1 {
    constructor(message) {
        super(message);
    }
}

function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
function bool$1(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
const assert = {
    number,
    bool: bool$1,
    bytes,
    hash,
    exists,
    output,
};

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// The import here is via the package name. This is to ensure
// that exports mapping/resolution does fall into place.
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
// So, just to be sure not to corrupt anything.
if (!isLE)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function utf8ToBytes$1(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes$1(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
function wrapConstructor(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}

// HMAC (RFC 2104)
class HMAC extends Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        assert.hash(hash);
        const key = toBytes(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new TypeError('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        assert.exists(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        assert.exists(this);
        assert.bytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        assert.exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        assert.exists(this);
        assert.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}

// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = new Uint32Array(64);
class SHA256 extends SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA224 extends SHA256 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$1 = wrapConstructor(() => new SHA256());
wrapConstructor(() => new SHA224());

var empty = {};

var nodeCrypto = /*#__PURE__*/Object.freeze({
    __proto__: null,
    default: empty
});

/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);
const CURVE = Object.freeze({
    a: _0n,
    b: BigInt(7),
    P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
    n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
    h: _1n,
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
});
const divNearest = (a, b) => (a + b / _2n) / b;
const endo = {
    beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
    splitScalar(k) {
        const { n } = CURVE;
        const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
        const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
        const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
        const b2 = a1;
        const POW_2_128 = BigInt('0x100000000000000000000000000000000');
        const c1 = divNearest(b2 * k, n);
        const c2 = divNearest(-b1 * k, n);
        let k1 = mod(k - c1 * a1 - c2 * a2, n);
        let k2 = mod(-c1 * b1 - c2 * b2, n);
        const k1neg = k1 > POW_2_128;
        const k2neg = k2 > POW_2_128;
        if (k1neg)
            k1 = n - k1;
        if (k2neg)
            k2 = n - k2;
        if (k1 > POW_2_128 || k2 > POW_2_128) {
            throw new Error('splitScalarEndo: Endomorphism failed, k=' + k);
        }
        return { k1neg, k1, k2neg, k2 };
    },
};
const fieldLen = 32;
const groupLen = 32;
const hashLen = 32;
const compressedLen = fieldLen + 1;
const uncompressedLen = 2 * fieldLen + 1;
function weierstrass(x) {
    const { a, b } = CURVE;
    const x2 = mod(x * x);
    const x3 = mod(x2 * x);
    return mod(x3 + a * x + b);
}
const USE_ENDOMORPHISM = CURVE.a === _0n;
class ShaError extends Error {
    constructor(message) {
        super(message);
    }
}
function assertJacPoint(other) {
    if (!(other instanceof JacobianPoint))
        throw new TypeError('JacobianPoint expected');
}
class JacobianPoint {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromAffine(p) {
        if (!(p instanceof Point)) {
            throw new TypeError('JacobianPoint#fromAffine: expected Point');
        }
        if (p.equals(Point.ZERO))
            return JacobianPoint.ZERO;
        return new JacobianPoint(p.x, p.y, _1n);
    }
    static toAffineBatch(points) {
        const toInv = invertBatch(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(points) {
        return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
    }
    equals(other) {
        assertJacPoint(other);
        const { x: X1, y: Y1, z: Z1 } = this;
        const { x: X2, y: Y2, z: Z2 } = other;
        const Z1Z1 = mod(Z1 * Z1);
        const Z2Z2 = mod(Z2 * Z2);
        const U1 = mod(X1 * Z2Z2);
        const U2 = mod(X2 * Z1Z1);
        const S1 = mod(mod(Y1 * Z2) * Z2Z2);
        const S2 = mod(mod(Y2 * Z1) * Z1Z1);
        return U1 === U2 && S1 === S2;
    }
    negate() {
        return new JacobianPoint(this.x, mod(-this.y), this.z);
    }
    double() {
        const { x: X1, y: Y1, z: Z1 } = this;
        const A = mod(X1 * X1);
        const B = mod(Y1 * Y1);
        const C = mod(B * B);
        const x1b = X1 + B;
        const D = mod(_2n * (mod(x1b * x1b) - A - C));
        const E = mod(_3n * A);
        const F = mod(E * E);
        const X3 = mod(F - _2n * D);
        const Y3 = mod(E * (D - X3) - _8n * C);
        const Z3 = mod(_2n * Y1 * Z1);
        return new JacobianPoint(X3, Y3, Z3);
    }
    add(other) {
        assertJacPoint(other);
        const { x: X1, y: Y1, z: Z1 } = this;
        const { x: X2, y: Y2, z: Z2 } = other;
        if (X2 === _0n || Y2 === _0n)
            return this;
        if (X1 === _0n || Y1 === _0n)
            return other;
        const Z1Z1 = mod(Z1 * Z1);
        const Z2Z2 = mod(Z2 * Z2);
        const U1 = mod(X1 * Z2Z2);
        const U2 = mod(X2 * Z1Z1);
        const S1 = mod(mod(Y1 * Z2) * Z2Z2);
        const S2 = mod(mod(Y2 * Z1) * Z1Z1);
        const H = mod(U2 - U1);
        const r = mod(S2 - S1);
        if (H === _0n) {
            if (r === _0n) {
                return this.double();
            }
            else {
                return JacobianPoint.ZERO;
            }
        }
        const HH = mod(H * H);
        const HHH = mod(H * HH);
        const V = mod(U1 * HH);
        const X3 = mod(r * r - HHH - _2n * V);
        const Y3 = mod(r * (V - X3) - S1 * HHH);
        const Z3 = mod(Z1 * Z2 * H);
        return new JacobianPoint(X3, Y3, Z3);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiplyUnsafe(scalar) {
        const P0 = JacobianPoint.ZERO;
        if (typeof scalar === 'bigint' && scalar === _0n)
            return P0;
        let n = normalizeScalar(scalar);
        if (n === _1n)
            return this;
        if (!USE_ENDOMORPHISM) {
            let p = P0;
            let d = this;
            while (n > _0n) {
                if (n & _1n)
                    p = p.add(d);
                d = d.double();
                n >>= _1n;
            }
            return p;
        }
        let { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
        let k1p = P0;
        let k2p = P0;
        let d = this;
        while (k1 > _0n || k2 > _0n) {
            if (k1 & _1n)
                k1p = k1p.add(d);
            if (k2 & _1n)
                k2p = k2p.add(d);
            d = d.double();
            k1 >>= _1n;
            k2 >>= _1n;
        }
        if (k1neg)
            k1p = k1p.negate();
        if (k2neg)
            k2p = k2p.negate();
        k2p = new JacobianPoint(mod(k2p.x * endo.beta), k2p.y, k2p.z);
        return k1p.add(k2p);
    }
    precomputeWindow(W) {
        const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
        const points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < 2 ** (W - 1); i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    wNAF(n, affinePoint) {
        if (!affinePoint && this.equals(JacobianPoint.BASE))
            affinePoint = Point.BASE;
        const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
        if (256 % W) {
            throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
        }
        let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
        if (!precomputes) {
            precomputes = this.precomputeWindow(W);
            if (affinePoint && W !== 1) {
                precomputes = JacobianPoint.normalizeZ(precomputes);
                pointPrecomputes.set(affinePoint, precomputes);
            }
        }
        let p = JacobianPoint.ZERO;
        let f = JacobianPoint.BASE;
        const windows = 1 + (USE_ENDOMORPHISM ? 128 / W : 256 / W);
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += _1n;
            }
            const offset1 = offset;
            const offset2 = offset + Math.abs(wbits) - 1;
            const cond1 = window % 2 !== 0;
            const cond2 = wbits < 0;
            if (wbits === 0) {
                f = f.add(constTimeNegate(cond1, precomputes[offset1]));
            }
            else {
                p = p.add(constTimeNegate(cond2, precomputes[offset2]));
            }
        }
        return { p, f };
    }
    multiply(scalar, affinePoint) {
        let n = normalizeScalar(scalar);
        let point;
        let fake;
        if (USE_ENDOMORPHISM) {
            const { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
            let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
            let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
            k1p = constTimeNegate(k1neg, k1p);
            k2p = constTimeNegate(k2neg, k2p);
            k2p = new JacobianPoint(mod(k2p.x * endo.beta), k2p.y, k2p.z);
            point = k1p.add(k2p);
            fake = f1p.add(f2p);
        }
        else {
            const { p, f } = this.wNAF(n, affinePoint);
            point = p;
            fake = f;
        }
        return JacobianPoint.normalizeZ([point, fake])[0];
    }
    toAffine(invZ) {
        const { x, y, z } = this;
        const is0 = this.equals(JacobianPoint.ZERO);
        if (invZ == null)
            invZ = is0 ? _8n : invert(z);
        const iz1 = invZ;
        const iz2 = mod(iz1 * iz1);
        const iz3 = mod(iz2 * iz1);
        const ax = mod(x * iz2);
        const ay = mod(y * iz3);
        const zz = mod(z * iz1);
        if (is0)
            return Point.ZERO;
        if (zz !== _1n)
            throw new Error('invZ was invalid');
        return new Point(ax, ay);
    }
}
JacobianPoint.BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
JacobianPoint.ZERO = new JacobianPoint(_0n, _1n, _0n);
function constTimeNegate(condition, item) {
    const neg = item.negate();
    return condition ? neg : item;
}
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this._WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    hasEvenY() {
        return this.y % _2n === _0n;
    }
    static fromCompressedHex(bytes) {
        const isShort = bytes.length === 32;
        const x = bytesToNumber(isShort ? bytes : bytes.subarray(1));
        if (!isValidFieldElement(x))
            throw new Error('Point is not on curve');
        const y2 = weierstrass(x);
        let y = sqrtMod(y2);
        const isYOdd = (y & _1n) === _1n;
        if (isShort) {
            if (isYOdd)
                y = mod(-y);
        }
        else {
            const isFirstByteOdd = (bytes[0] & 1) === 1;
            if (isFirstByteOdd !== isYOdd)
                y = mod(-y);
        }
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromUncompressedHex(bytes) {
        const x = bytesToNumber(bytes.subarray(1, fieldLen + 1));
        const y = bytesToNumber(bytes.subarray(fieldLen + 1, fieldLen * 2 + 1));
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromHex(hex) {
        const bytes = ensureBytes(hex);
        const len = bytes.length;
        const header = bytes[0];
        if (len === fieldLen)
            return this.fromCompressedHex(bytes);
        if (len === compressedLen && (header === 0x02 || header === 0x03)) {
            return this.fromCompressedHex(bytes);
        }
        if (len === uncompressedLen && header === 0x04)
            return this.fromUncompressedHex(bytes);
        throw new Error(`Point.fromHex: received invalid point. Expected 32-${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes, not ${len}`);
    }
    static fromPrivateKey(privateKey) {
        return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }
    static fromSignature(msgHash, signature, recovery) {
        const { r, s } = normalizeSignature(signature);
        if (![0, 1, 2, 3].includes(recovery))
            throw new Error('Cannot recover: invalid recovery bit');
        const h = truncateHash(ensureBytes(msgHash));
        const { n } = CURVE;
        const radj = recovery === 2 || recovery === 3 ? r + n : r;
        const rinv = invert(radj, n);
        const u1 = mod(-h * rinv, n);
        const u2 = mod(s * rinv, n);
        const prefix = recovery & 1 ? '03' : '02';
        const R = Point.fromHex(prefix + numTo32bStr(radj));
        const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
        if (!Q)
            throw new Error('Cannot recover signature: point at infinify');
        Q.assertValidity();
        return Q;
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes$1(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        const x = numTo32bStr(this.x);
        if (isCompressed) {
            const prefix = this.hasEvenY() ? '02' : '03';
            return `${prefix}${x}`;
        }
        else {
            return `04${x}${numTo32bStr(this.y)}`;
        }
    }
    toHexX() {
        return this.toHex(true).slice(2);
    }
    toRawX() {
        return this.toRawBytes(true).slice(1);
    }
    assertValidity() {
        const msg = 'Point is not on elliptic curve';
        const { x, y } = this;
        if (!isValidFieldElement(x) || !isValidFieldElement(y))
            throw new Error(msg);
        const left = mod(y * y);
        const right = weierstrass(x);
        if (mod(left - right) !== _0n)
            throw new Error(msg);
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(this.x, mod(-this.y));
    }
    double() {
        return JacobianPoint.fromAffine(this).double().toAffine();
    }
    add(other) {
        return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
    multiplyAndAddUnsafe(Q, a, b) {
        const P = JacobianPoint.fromAffine(this);
        const aP = a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
        const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
        const sum = aP.add(bQ);
        return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
    }
}
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(_0n, _0n);
function sliceDER(s) {
    return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}
function parseDERInt(data) {
    if (data.length < 2 || data[0] !== 0x02) {
        throw new Error(`Invalid signature integer tag: ${bytesToHex$1(data)}`);
    }
    const len = data[1];
    const res = data.subarray(2, len + 2);
    if (!len || res.length !== len) {
        throw new Error(`Invalid signature integer: wrong length`);
    }
    if (res[0] === 0x00 && res[1] <= 0x7f) {
        throw new Error('Invalid signature integer: trailing length');
    }
    return { data: bytesToNumber(res), left: data.subarray(len + 2) };
}
function parseDERSignature(data) {
    if (data.length < 2 || data[0] != 0x30) {
        throw new Error(`Invalid signature tag: ${bytesToHex$1(data)}`);
    }
    if (data[1] !== data.length - 2) {
        throw new Error('Invalid signature: incorrect length');
    }
    const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
    const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
    if (rBytesLeft.length) {
        throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex$1(rBytesLeft)}`);
    }
    return { r, s };
}
class Signature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
        this.assertValidity();
    }
    static fromCompact(hex) {
        const arr = hex instanceof Uint8Array;
        const name = 'Signature.fromCompact';
        if (typeof hex !== 'string' && !arr)
            throw new TypeError(`${name}: Expected string or Uint8Array`);
        const str = arr ? bytesToHex$1(hex) : hex;
        if (str.length !== 128)
            throw new Error(`${name}: Expected 64-byte hex`);
        return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
    }
    static fromDER(hex) {
        const arr = hex instanceof Uint8Array;
        if (typeof hex !== 'string' && !arr)
            throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
        const { r, s } = parseDERSignature(arr ? hex : hexToBytes$1(hex));
        return new Signature(r, s);
    }
    static fromHex(hex) {
        return this.fromDER(hex);
    }
    assertValidity() {
        const { r, s } = this;
        if (!isWithinCurveOrder(r))
            throw new Error('Invalid Signature: r must be 0 < r < n');
        if (!isWithinCurveOrder(s))
            throw new Error('Invalid Signature: s must be 0 < s < n');
    }
    hasHighS() {
        const HALF = CURVE.n >> _1n;
        return this.s > HALF;
    }
    normalizeS() {
        return this.hasHighS() ? new Signature(this.r, mod(-this.s, CURVE.n)) : this;
    }
    toDERRawBytes() {
        return hexToBytes$1(this.toDERHex());
    }
    toDERHex() {
        const sHex = sliceDER(numberToHexUnpadded(this.s));
        const rHex = sliceDER(numberToHexUnpadded(this.r));
        const sHexL = sHex.length / 2;
        const rHexL = rHex.length / 2;
        const sLen = numberToHexUnpadded(sHexL);
        const rLen = numberToHexUnpadded(rHexL);
        const length = numberToHexUnpadded(rHexL + sHexL + 4);
        return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }
    toRawBytes() {
        return this.toDERRawBytes();
    }
    toHex() {
        return this.toDERHex();
    }
    toCompactRawBytes() {
        return hexToBytes$1(this.toCompactHex());
    }
    toCompactHex() {
        return numTo32bStr(this.r) + numTo32bStr(this.s);
    }
}
function concatBytes$1(...arrays) {
    if (!arrays.every((b) => b instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
const hexes$1 = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex$1(uint8a) {
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Expected Uint8Array');
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes$1[uint8a[i]];
    }
    return hex;
}
const POW_2_256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
function numTo32bStr(num) {
    if (typeof num !== 'bigint')
        throw new Error('Expected bigint');
    if (!(_0n <= num && num < POW_2_256))
        throw new Error('Expected number 0 <= n < 2^256');
    return num.toString(16).padStart(64, '0');
}
function numTo32b(num) {
    const b = hexToBytes$1(numTo32bStr(num));
    if (b.length !== 32)
        throw new Error('Error: expected 32 bytes');
    return b;
}
function numberToHexUnpadded(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
    }
    return BigInt(`0x${hex}`);
}
function hexToBytes$1(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
function bytesToNumber(bytes) {
    return hexToNumber(bytesToHex$1(bytes));
}
function ensureBytes(hex) {
    return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes$1(hex);
}
function normalizeScalar(num) {
    if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0)
        return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num))
        return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}
function mod(a, b = CURVE.P) {
    const result = a % b;
    return result >= _0n ? result : b + result;
}
function pow2(x, power) {
    const { P } = CURVE;
    let res = x;
    while (power-- > _0n) {
        res *= res;
        res %= P;
    }
    return res;
}
function sqrtMod(x) {
    const { P } = CURVE;
    const _6n = BigInt(6);
    const _11n = BigInt(11);
    const _22n = BigInt(22);
    const _23n = BigInt(23);
    const _44n = BigInt(44);
    const _88n = BigInt(88);
    const b2 = (x * x * x) % P;
    const b3 = (b2 * b2 * x) % P;
    const b6 = (pow2(b3, _3n) * b3) % P;
    const b9 = (pow2(b6, _3n) * b3) % P;
    const b11 = (pow2(b9, _2n) * b2) % P;
    const b22 = (pow2(b11, _11n) * b11) % P;
    const b44 = (pow2(b22, _22n) * b22) % P;
    const b88 = (pow2(b44, _44n) * b44) % P;
    const b176 = (pow2(b88, _88n) * b88) % P;
    const b220 = (pow2(b176, _44n) * b44) % P;
    const b223 = (pow2(b220, _3n) * b3) % P;
    const t1 = (pow2(b223, _23n) * b22) % P;
    const t2 = (pow2(t1, _6n) * b2) % P;
    const rt = pow2(t2, _2n);
    const xc = (rt * rt) % P;
    if (xc !== x)
        throw new Error('Cannot find square root');
    return rt;
}
function invert(number, modulo = CURVE.P) {
    if (number === _0n || modulo <= _0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    let x = _0n, u = _1n;
    while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== _1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
function invertBatch(nums, p = CURVE.P) {
    const scratch = new Array(nums.length);
    const lastMultiplied = nums.reduce((acc, num, i) => {
        if (num === _0n)
            return acc;
        scratch[i] = acc;
        return mod(acc * num, p);
    }, _1n);
    const inverted = invert(lastMultiplied, p);
    nums.reduceRight((acc, num, i) => {
        if (num === _0n)
            return acc;
        scratch[i] = mod(acc * scratch[i], p);
        return mod(acc * num, p);
    }, inverted);
    return scratch;
}
function bits2int_2(bytes) {
    const delta = bytes.length * 8 - groupLen * 8;
    const num = bytesToNumber(bytes);
    return delta > 0 ? num >> BigInt(delta) : num;
}
function truncateHash(hash, truncateOnly = false) {
    const h = bits2int_2(hash);
    if (truncateOnly)
        return h;
    const { n } = CURVE;
    return h >= n ? h - n : h;
}
let _sha256Sync;
let _hmacSha256Sync;
class HmacDrbg {
    constructor(hashLen, qByteLen) {
        this.hashLen = hashLen;
        this.qByteLen = qByteLen;
        if (typeof hashLen !== 'number' || hashLen < 2)
            throw new Error('hashLen must be a number');
        if (typeof qByteLen !== 'number' || qByteLen < 2)
            throw new Error('qByteLen must be a number');
        this.v = new Uint8Array(hashLen).fill(1);
        this.k = new Uint8Array(hashLen).fill(0);
        this.counter = 0;
    }
    hmac(...values) {
        return utils$1.hmacSha256(this.k, ...values);
    }
    hmacSync(...values) {
        return _hmacSha256Sync(this.k, ...values);
    }
    checkSync() {
        if (typeof _hmacSha256Sync !== 'function')
            throw new ShaError('hmacSha256Sync needs to be set');
    }
    incr() {
        if (this.counter >= 1000)
            throw new Error('Tried 1,000 k values for sign(), all were invalid');
        this.counter += 1;
    }
    async reseed(seed = new Uint8Array()) {
        this.k = await this.hmac(this.v, Uint8Array.from([0x00]), seed);
        this.v = await this.hmac(this.v);
        if (seed.length === 0)
            return;
        this.k = await this.hmac(this.v, Uint8Array.from([0x01]), seed);
        this.v = await this.hmac(this.v);
    }
    reseedSync(seed = new Uint8Array()) {
        this.checkSync();
        this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
        this.v = this.hmacSync(this.v);
        if (seed.length === 0)
            return;
        this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
        this.v = this.hmacSync(this.v);
    }
    async generate() {
        this.incr();
        let len = 0;
        const out = [];
        while (len < this.qByteLen) {
            this.v = await this.hmac(this.v);
            const sl = this.v.slice();
            out.push(sl);
            len += this.v.length;
        }
        return concatBytes$1(...out);
    }
    generateSync() {
        this.checkSync();
        this.incr();
        let len = 0;
        const out = [];
        while (len < this.qByteLen) {
            this.v = this.hmacSync(this.v);
            const sl = this.v.slice();
            out.push(sl);
            len += this.v.length;
        }
        return concatBytes$1(...out);
    }
}
function isWithinCurveOrder(num) {
    return _0n < num && num < CURVE.n;
}
function isValidFieldElement(num) {
    return _0n < num && num < CURVE.P;
}
function kmdToSig(kBytes, m, d, lowS = true) {
    const { n } = CURVE;
    const k = truncateHash(kBytes, true);
    if (!isWithinCurveOrder(k))
        return;
    const kinv = invert(k, n);
    const q = Point.BASE.multiply(k);
    const r = mod(q.x, n);
    if (r === _0n)
        return;
    const s = mod(kinv * mod(m + d * r, n), n);
    if (s === _0n)
        return;
    let sig = new Signature(r, s);
    let recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & _1n);
    if (lowS && sig.hasHighS()) {
        sig = sig.normalizeS();
        recovery ^= 1;
    }
    return { sig, recovery };
}
function normalizePrivateKey(key) {
    let num;
    if (typeof key === 'bigint') {
        num = key;
    }
    else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
        num = BigInt(key);
    }
    else if (typeof key === 'string') {
        if (key.length !== 2 * groupLen)
            throw new Error('Expected 32 bytes of private key');
        num = hexToNumber(key);
    }
    else if (key instanceof Uint8Array) {
        if (key.length !== groupLen)
            throw new Error('Expected 32 bytes of private key');
        num = bytesToNumber(key);
    }
    else {
        throw new TypeError('Expected valid private key');
    }
    if (!isWithinCurveOrder(num))
        throw new Error('Expected private key: 0 < key < n');
    return num;
}
function normalizeSignature(signature) {
    if (signature instanceof Signature) {
        signature.assertValidity();
        return signature;
    }
    try {
        return Signature.fromDER(signature);
    }
    catch (error) {
        return Signature.fromCompact(signature);
    }
}
function getPublicKey(privateKey, isCompressed = false) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
}
function bits2int(bytes) {
    const slice = bytes.length > fieldLen ? bytes.slice(0, fieldLen) : bytes;
    return bytesToNumber(slice);
}
function bits2octets(bytes) {
    const z1 = bits2int(bytes);
    const z2 = mod(z1, CURVE.n);
    return int2octets(z2 < _0n ? z1 : z2);
}
function int2octets(num) {
    return numTo32b(num);
}
function initSigArgs(msgHash, privateKey, extraEntropy) {
    if (msgHash == null)
        throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
    const h1 = ensureBytes(msgHash);
    const d = normalizePrivateKey(privateKey);
    const seedArgs = [int2octets(d), bits2octets(h1)];
    if (extraEntropy != null) {
        if (extraEntropy === true)
            extraEntropy = utils$1.randomBytes(fieldLen);
        const e = ensureBytes(extraEntropy);
        if (e.length !== fieldLen)
            throw new Error(`sign: Expected ${fieldLen} bytes of extra data`);
        seedArgs.push(e);
    }
    const seed = concatBytes$1(...seedArgs);
    const m = bits2int(h1);
    return { seed, m, d };
}
function finalizeSig(recSig, opts) {
    const { sig, recovery } = recSig;
    const { der, recovered } = Object.assign({ canonical: true, der: true }, opts);
    const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
    return recovered ? [hashed, recovery] : hashed;
}
function signSync(msgHash, privKey, opts = {}) {
    const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
    const drbg = new HmacDrbg(hashLen, groupLen);
    drbg.reseedSync(seed);
    let sig;
    while (!(sig = kmdToSig(drbg.generateSync(), m, d, opts.canonical)))
        drbg.reseedSync();
    return finalizeSig(sig, opts);
}
Point.BASE._setWindowSize(8);
const crypto = {
    node: nodeCrypto,
    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
const TAGGED_HASH_PREFIXES = {};
const utils$1 = {
    bytesToHex: bytesToHex$1,
    hexToBytes: hexToBytes$1,
    concatBytes: concatBytes$1,
    mod,
    invert,
    isValidPrivateKey(privateKey) {
        try {
            normalizePrivateKey(privateKey);
            return true;
        }
        catch (error) {
            return false;
        }
    },
    _bigintTo32Bytes: numTo32b,
    _normalizePrivateKey: normalizePrivateKey,
    hashToPrivateKey: (hash) => {
        hash = ensureBytes(hash);
        const minLen = groupLen + 8;
        if (hash.length < minLen || hash.length > 1024) {
            throw new Error(`Expected valid bytes of private key as per FIPS 186`);
        }
        const num = mod(bytesToNumber(hash), CURVE.n - _1n) + _1n;
        return numTo32b(num);
    },
    randomBytes: (bytesLength = 32) => {
        if (crypto.web) {
            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (crypto.node) {
            const { randomBytes } = crypto.node;
            return Uint8Array.from(randomBytes(bytesLength));
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    randomPrivateKey: () => utils$1.hashToPrivateKey(utils$1.randomBytes(groupLen + 8)),
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point === Point.BASE ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(_3n);
        return cached;
    },
    sha256: async (...messages) => {
        if (crypto.web) {
            const buffer = await crypto.web.subtle.digest('SHA-256', concatBytes$1(...messages));
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHash } = crypto.node;
            const hash = createHash('sha256');
            messages.forEach((m) => hash.update(m));
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have sha256 function");
        }
    },
    hmacSha256: async (key, ...messages) => {
        if (crypto.web) {
            const ckey = await crypto.web.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
            const message = concatBytes$1(...messages);
            const buffer = await crypto.web.subtle.sign('HMAC', ckey, message);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHmac } = crypto.node;
            const hash = createHmac('sha256', key);
            messages.forEach((m) => hash.update(m));
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have hmac-sha256 function");
        }
    },
    sha256Sync: undefined,
    hmacSha256Sync: undefined,
    taggedHash: async (tag, ...messages) => {
        let tagP = TAGGED_HASH_PREFIXES[tag];
        if (tagP === undefined) {
            const tagH = await utils$1.sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
            tagP = concatBytes$1(tagH, tagH);
            TAGGED_HASH_PREFIXES[tag] = tagP;
        }
        return utils$1.sha256(tagP, ...messages);
    },
    taggedHashSync: (tag, ...messages) => {
        if (typeof _sha256Sync !== 'function')
            throw new ShaError('sha256Sync is undefined, you need to set it');
        let tagP = TAGGED_HASH_PREFIXES[tag];
        if (tagP === undefined) {
            const tagH = _sha256Sync(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
            tagP = concatBytes$1(tagH, tagH);
            TAGGED_HASH_PREFIXES[tag] = tagP;
        }
        return _sha256Sync(tagP, ...messages);
    },
    _JacobianPoint: JacobianPoint,
};
Object.defineProperties(utils$1, {
    sha256Sync: {
        configurable: false,
        get() {
            return _sha256Sync;
        },
        set(val) {
            if (!_sha256Sync)
                _sha256Sync = val;
        },
    },
    hmacSha256Sync: {
        configurable: false,
        get() {
            return _hmacSha256Sync;
        },
        set(val) {
            if (!_hmacSha256Sync)
                _hmacSha256Sync = val;
        },
    },
});

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function getDefaultExportFromCjs (x) {
	return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
}

var lib = {};

var encoding = {};

var utils = {};

var cryptoBrowser = {};

var hasRequiredCryptoBrowser;

function requireCryptoBrowser () {
	if (hasRequiredCryptoBrowser) return cryptoBrowser;
	hasRequiredCryptoBrowser = 1;
	Object.defineProperty(cryptoBrowser, "__esModule", { value: true });
	cryptoBrowser.crypto = void 0;
	cryptoBrowser.crypto = {
	    node: undefined,
	    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
	};
	return cryptoBrowser;
}

var hasRequiredUtils;

function requireUtils () {
	if (hasRequiredUtils) return utils;
	hasRequiredUtils = 1;
	(function (exports) {
		/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
		// The import here is via the package name. This is to ensure
		// that exports mapping/resolution does fall into place.
		const crypto_1 = requireCryptoBrowser();
		// Cast array to different type
		const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
		exports.u8 = u8;
		const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
		exports.u32 = u32;
		// Cast array to view
		const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
		exports.createView = createView;
		// The rotate right (circular right shift) operation for uint32
		const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
		exports.rotr = rotr;
		exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
		// There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
		// So, just to be sure not to corrupt anything.
		if (!exports.isLE)
		    throw new Error('Non little-endian hardware is not supported');
		const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
		/**
		 * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
		 */
		function bytesToHex(uint8a) {
		    // pre-caching improves the speed 6x
		    if (!(uint8a instanceof Uint8Array))
		        throw new Error('Uint8Array expected');
		    let hex = '';
		    for (let i = 0; i < uint8a.length; i++) {
		        hex += hexes[uint8a[i]];
		    }
		    return hex;
		}
		exports.bytesToHex = bytesToHex;
		/**
		 * @example hexToBytes('deadbeef')
		 */
		function hexToBytes(hex) {
		    if (typeof hex !== 'string') {
		        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
		    }
		    if (hex.length % 2)
		        throw new Error('hexToBytes: received invalid unpadded hex');
		    const array = new Uint8Array(hex.length / 2);
		    for (let i = 0; i < array.length; i++) {
		        const j = i * 2;
		        const hexByte = hex.slice(j, j + 2);
		        const byte = Number.parseInt(hexByte, 16);
		        if (Number.isNaN(byte) || byte < 0)
		            throw new Error('Invalid byte sequence');
		        array[i] = byte;
		    }
		    return array;
		}
		exports.hexToBytes = hexToBytes;
		// There is no setImmediate in browser and setTimeout is slow. However, call to async function will return Promise
		// which will be fullfiled only on next scheduler queue processing step and this is exactly what we need.
		const nextTick = async () => { };
		exports.nextTick = nextTick;
		// Returns control to thread each 'tick' ms to avoid blocking
		async function asyncLoop(iters, tick, cb) {
		    let ts = Date.now();
		    for (let i = 0; i < iters; i++) {
		        cb(i);
		        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
		        const diff = Date.now() - ts;
		        if (diff >= 0 && diff < tick)
		            continue;
		        await (0, exports.nextTick)();
		        ts += diff;
		    }
		}
		exports.asyncLoop = asyncLoop;
		function utf8ToBytes(str) {
		    if (typeof str !== 'string') {
		        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
		    }
		    return new TextEncoder().encode(str);
		}
		exports.utf8ToBytes = utf8ToBytes;
		function toBytes(data) {
		    if (typeof data === 'string')
		        data = utf8ToBytes(data);
		    if (!(data instanceof Uint8Array))
		        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
		    return data;
		}
		exports.toBytes = toBytes;
		/**
		 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
		 * @example concatBytes(buf1, buf2)
		 */
		function concatBytes(...arrays) {
		    if (!arrays.every((a) => a instanceof Uint8Array))
		        throw new Error('Uint8Array list expected');
		    if (arrays.length === 1)
		        return arrays[0];
		    const length = arrays.reduce((a, arr) => a + arr.length, 0);
		    const result = new Uint8Array(length);
		    for (let i = 0, pad = 0; i < arrays.length; i++) {
		        const arr = arrays[i];
		        result.set(arr, pad);
		        pad += arr.length;
		    }
		    return result;
		}
		exports.concatBytes = concatBytes;
		// For runtime check if class implements interface
		class Hash {
		    // Safe version that clones internal state
		    clone() {
		        return this._cloneInto();
		    }
		}
		exports.Hash = Hash;
		// Check if object doens't have custom constructor (like Uint8Array/Array)
		const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
		function checkOpts(defaults, opts) {
		    if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
		        throw new TypeError('Options should be object or undefined');
		    const merged = Object.assign(defaults, opts);
		    return merged;
		}
		exports.checkOpts = checkOpts;
		function wrapConstructor(hashConstructor) {
		    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
		    const tmp = hashConstructor();
		    hashC.outputLen = tmp.outputLen;
		    hashC.blockLen = tmp.blockLen;
		    hashC.create = () => hashConstructor();
		    return hashC;
		}
		exports.wrapConstructor = wrapConstructor;
		function wrapConstructorWithOpts(hashCons) {
		    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
		    const tmp = hashCons({});
		    hashC.outputLen = tmp.outputLen;
		    hashC.blockLen = tmp.blockLen;
		    hashC.create = (opts) => hashCons(opts);
		    return hashC;
		}
		exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
		/**
		 * Secure PRNG
		 */
		function randomBytes(bytesLength = 32) {
		    if (crypto_1.crypto.web) {
		        return crypto_1.crypto.web.getRandomValues(new Uint8Array(bytesLength));
		    }
		    else if (crypto_1.crypto.node) {
		        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
		    }
		    else {
		        throw new Error("The environment doesn't have randomBytes function");
		    }
		}
		exports.randomBytes = randomBytes; 
	} (utils));
	return utils;
}

var hasRequiredEncoding;

function requireEncoding () {
	if (hasRequiredEncoding) return encoding;
	hasRequiredEncoding = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.c32decode = exports.c32normalize = exports.c32encode = exports.c32 = void 0;
		const utils_1 = requireUtils();
		exports.c32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
		const hex = '0123456789abcdef';
		/**
		 * Encode a hex string as a c32 string.  Note that the hex string is assumed
		 * to be big-endian (and the resulting c32 string will be as well).
		 * @param {string} inputHex - the input to encode
		 * @param {number} minLength - the minimum length of the c32 string
		 * @returns {string} the c32check-encoded representation of the data, as a string
		 */
		function c32encode(inputHex, minLength) {
		    // must be hex
		    if (!inputHex.match(/^[0-9a-fA-F]*$/)) {
		        throw new Error('Not a hex-encoded string');
		    }
		    if (inputHex.length % 2 !== 0) {
		        inputHex = `0${inputHex}`;
		    }
		    inputHex = inputHex.toLowerCase();
		    let res = [];
		    let carry = 0;
		    for (let i = inputHex.length - 1; i >= 0; i--) {
		        if (carry < 4) {
		            const currentCode = hex.indexOf(inputHex[i]) >> carry;
		            let nextCode = 0;
		            if (i !== 0) {
		                nextCode = hex.indexOf(inputHex[i - 1]);
		            }
		            // carry = 0, nextBits is 1, carry = 1, nextBits is 2
		            const nextBits = 1 + carry;
		            const nextLowBits = nextCode % (1 << nextBits) << (5 - nextBits);
		            const curC32Digit = exports.c32[currentCode + nextLowBits];
		            carry = nextBits;
		            res.unshift(curC32Digit);
		        }
		        else {
		            carry = 0;
		        }
		    }
		    let C32leadingZeros = 0;
		    for (let i = 0; i < res.length; i++) {
		        if (res[i] !== '0') {
		            break;
		        }
		        else {
		            C32leadingZeros++;
		        }
		    }
		    res = res.slice(C32leadingZeros);
		    const zeroPrefix = new TextDecoder().decode((0, utils_1.hexToBytes)(inputHex)).match(/^\u0000*/);
		    const numLeadingZeroBytesInHex = zeroPrefix ? zeroPrefix[0].length : 0;
		    for (let i = 0; i < numLeadingZeroBytesInHex; i++) {
		        res.unshift(exports.c32[0]);
		    }
		    if (minLength) {
		        const count = minLength - res.length;
		        for (let i = 0; i < count; i++) {
		            res.unshift(exports.c32[0]);
		        }
		    }
		    return res.join('');
		}
		exports.c32encode = c32encode;
		/*
		 * Normalize a c32 string
		 * @param {string} c32input - the c32-encoded input string
		 * @returns {string} the canonical representation of the c32 input string
		 */
		function c32normalize(c32input) {
		    // must be upper-case
		    // replace all O's with 0's
		    // replace all I's and L's with 1's
		    return c32input.toUpperCase().replace(/O/g, '0').replace(/L|I/g, '1');
		}
		exports.c32normalize = c32normalize;
		/*
		 * Decode a c32 string back into a hex string.  Note that the c32 input
		 * string is assumed to be big-endian (and the resulting hex string will
		 * be as well).
		 * @param {string} c32input - the c32-encoded input to decode
		 * @param {number} minLength - the minimum length of the output hex string (in bytes)
		 * @returns {string} the hex-encoded representation of the data, as a string
		 */
		function c32decode(c32input, minLength) {
		    c32input = c32normalize(c32input);
		    // must result in a c32 string
		    if (!c32input.match(`^[${exports.c32}]*$`)) {
		        throw new Error('Not a c32-encoded string');
		    }
		    const zeroPrefix = c32input.match(`^${exports.c32[0]}*`);
		    const numLeadingZeroBytes = zeroPrefix ? zeroPrefix[0].length : 0;
		    let res = [];
		    let carry = 0;
		    let carryBits = 0;
		    for (let i = c32input.length - 1; i >= 0; i--) {
		        if (carryBits === 4) {
		            res.unshift(hex[carry]);
		            carryBits = 0;
		            carry = 0;
		        }
		        const currentCode = exports.c32.indexOf(c32input[i]) << carryBits;
		        const currentValue = currentCode + carry;
		        const currentHexDigit = hex[currentValue % 16];
		        carryBits += 1;
		        carry = currentValue >> 4;
		        if (carry > 1 << carryBits) {
		            throw new Error('Panic error in decoding.');
		        }
		        res.unshift(currentHexDigit);
		    }
		    // one last carry
		    res.unshift(hex[carry]);
		    if (res.length % 2 === 1) {
		        res.unshift('0');
		    }
		    let hexLeadingZeros = 0;
		    for (let i = 0; i < res.length; i++) {
		        if (res[i] !== '0') {
		            break;
		        }
		        else {
		            hexLeadingZeros++;
		        }
		    }
		    res = res.slice(hexLeadingZeros - (hexLeadingZeros % 2));
		    let hexStr = res.join('');
		    for (let i = 0; i < numLeadingZeroBytes; i++) {
		        hexStr = `00${hexStr}`;
		    }
		    if (minLength) {
		        const count = minLength * 2 - hexStr.length;
		        for (let i = 0; i < count; i += 2) {
		            hexStr = `00${hexStr}`;
		        }
		    }
		    return hexStr;
		}
		exports.c32decode = c32decode; 
	} (encoding));
	return encoding;
}

var checksum = {};

var sha256 = {};

var _sha2 = {};

var _assert = {};

var hasRequired_assert;

function require_assert () {
	if (hasRequired_assert) return _assert;
	hasRequired_assert = 1;
	Object.defineProperty(_assert, "__esModule", { value: true });
	_assert.output = _assert.exists = _assert.hash = _assert.bytes = _assert.bool = _assert.number = void 0;
	function number(n) {
	    if (!Number.isSafeInteger(n) || n < 0)
	        throw new Error(`Wrong positive integer: ${n}`);
	}
	_assert.number = number;
	function bool(b) {
	    if (typeof b !== 'boolean')
	        throw new Error(`Expected boolean, not ${b}`);
	}
	_assert.bool = bool;
	function bytes(b, ...lengths) {
	    if (!(b instanceof Uint8Array))
	        throw new TypeError('Expected Uint8Array');
	    if (lengths.length > 0 && !lengths.includes(b.length))
	        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
	}
	_assert.bytes = bytes;
	function hash(hash) {
	    if (typeof hash !== 'function' || typeof hash.create !== 'function')
	        throw new Error('Hash should be wrapped by utils.wrapConstructor');
	    number(hash.outputLen);
	    number(hash.blockLen);
	}
	_assert.hash = hash;
	function exists(instance, checkFinished = true) {
	    if (instance.destroyed)
	        throw new Error('Hash instance has been destroyed');
	    if (checkFinished && instance.finished)
	        throw new Error('Hash#digest() has already been called');
	}
	_assert.exists = exists;
	function output(out, instance) {
	    bytes(out);
	    const min = instance.outputLen;
	    if (out.length < min) {
	        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
	    }
	}
	_assert.output = output;
	const assert = {
	    number,
	    bool,
	    bytes,
	    hash,
	    exists,
	    output,
	};
	_assert.default = assert;
	return _assert;
}

var hasRequired_sha2;

function require_sha2 () {
	if (hasRequired_sha2) return _sha2;
	hasRequired_sha2 = 1;
	Object.defineProperty(_sha2, "__esModule", { value: true });
	_sha2.SHA2 = void 0;
	const _assert_js_1 = require_assert();
	const utils_js_1 = requireUtils();
	// Polyfill for Safari 14
	function setBigUint64(view, byteOffset, value, isLE) {
	    if (typeof view.setBigUint64 === 'function')
	        return view.setBigUint64(byteOffset, value, isLE);
	    const _32n = BigInt(32);
	    const _u32_max = BigInt(0xffffffff);
	    const wh = Number((value >> _32n) & _u32_max);
	    const wl = Number(value & _u32_max);
	    const h = isLE ? 4 : 0;
	    const l = isLE ? 0 : 4;
	    view.setUint32(byteOffset + h, wh, isLE);
	    view.setUint32(byteOffset + l, wl, isLE);
	}
	// Base SHA2 class (RFC 6234)
	class SHA2 extends utils_js_1.Hash {
	    constructor(blockLen, outputLen, padOffset, isLE) {
	        super();
	        this.blockLen = blockLen;
	        this.outputLen = outputLen;
	        this.padOffset = padOffset;
	        this.isLE = isLE;
	        this.finished = false;
	        this.length = 0;
	        this.pos = 0;
	        this.destroyed = false;
	        this.buffer = new Uint8Array(blockLen);
	        this.view = (0, utils_js_1.createView)(this.buffer);
	    }
	    update(data) {
	        _assert_js_1.default.exists(this);
	        const { view, buffer, blockLen } = this;
	        data = (0, utils_js_1.toBytes)(data);
	        const len = data.length;
	        for (let pos = 0; pos < len;) {
	            const take = Math.min(blockLen - this.pos, len - pos);
	            // Fast path: we have at least one block in input, cast it to view and process
	            if (take === blockLen) {
	                const dataView = (0, utils_js_1.createView)(data);
	                for (; blockLen <= len - pos; pos += blockLen)
	                    this.process(dataView, pos);
	                continue;
	            }
	            buffer.set(data.subarray(pos, pos + take), this.pos);
	            this.pos += take;
	            pos += take;
	            if (this.pos === blockLen) {
	                this.process(view, 0);
	                this.pos = 0;
	            }
	        }
	        this.length += data.length;
	        this.roundClean();
	        return this;
	    }
	    digestInto(out) {
	        _assert_js_1.default.exists(this);
	        _assert_js_1.default.output(out, this);
	        this.finished = true;
	        // Padding
	        // We can avoid allocation of buffer for padding completely if it
	        // was previously not allocated here. But it won't change performance.
	        const { buffer, view, blockLen, isLE } = this;
	        let { pos } = this;
	        // append the bit '1' to the message
	        buffer[pos++] = 0b10000000;
	        this.buffer.subarray(pos).fill(0);
	        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
	        if (this.padOffset > blockLen - pos) {
	            this.process(view, 0);
	            pos = 0;
	        }
	        // Pad until full block byte with zeros
	        for (let i = pos; i < blockLen; i++)
	            buffer[i] = 0;
	        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
	        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
	        // So we just write lowest 64 bits of that value.
	        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
	        this.process(view, 0);
	        const oview = (0, utils_js_1.createView)(out);
	        const len = this.outputLen;
	        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
	        if (len % 4)
	            throw new Error('_sha2: outputLen should be aligned to 32bit');
	        const outLen = len / 4;
	        const state = this.get();
	        if (outLen > state.length)
	            throw new Error('_sha2: outputLen bigger than state');
	        for (let i = 0; i < outLen; i++)
	            oview.setUint32(4 * i, state[i], isLE);
	    }
	    digest() {
	        const { buffer, outputLen } = this;
	        this.digestInto(buffer);
	        const res = buffer.slice(0, outputLen);
	        this.destroy();
	        return res;
	    }
	    _cloneInto(to) {
	        to || (to = new this.constructor());
	        to.set(...this.get());
	        const { blockLen, buffer, length, finished, destroyed, pos } = this;
	        to.length = length;
	        to.pos = pos;
	        to.finished = finished;
	        to.destroyed = destroyed;
	        if (length % blockLen)
	            to.buffer.set(buffer);
	        return to;
	    }
	}
	_sha2.SHA2 = SHA2;
	return _sha2;
}

var hasRequiredSha256;

function requireSha256 () {
	if (hasRequiredSha256) return sha256;
	hasRequiredSha256 = 1;
	Object.defineProperty(sha256, "__esModule", { value: true });
	sha256.sha224 = sha256.sha256 = void 0;
	const _sha2_js_1 = require_sha2();
	const utils_js_1 = requireUtils();
	// Choice: a ? b : c
	const Chi = (a, b, c) => (a & b) ^ (~a & c);
	// Majority function, true if any two inpust is true
	const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
	// Round constants:
	// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
	// prettier-ignore
	const SHA256_K = new Uint32Array([
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]);
	// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	// prettier-ignore
	const IV = new Uint32Array([
	    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	]);
	// Temporary buffer, not used to store anything between runs
	// Named this way because it matches specification.
	const SHA256_W = new Uint32Array(64);
	class SHA256 extends _sha2_js_1.SHA2 {
	    constructor() {
	        super(64, 32, 8, false);
	        // We cannot use array here since array allows indexing by variable
	        // which means optimizer/compiler cannot use registers.
	        this.A = IV[0] | 0;
	        this.B = IV[1] | 0;
	        this.C = IV[2] | 0;
	        this.D = IV[3] | 0;
	        this.E = IV[4] | 0;
	        this.F = IV[5] | 0;
	        this.G = IV[6] | 0;
	        this.H = IV[7] | 0;
	    }
	    get() {
	        const { A, B, C, D, E, F, G, H } = this;
	        return [A, B, C, D, E, F, G, H];
	    }
	    // prettier-ignore
	    set(A, B, C, D, E, F, G, H) {
	        this.A = A | 0;
	        this.B = B | 0;
	        this.C = C | 0;
	        this.D = D | 0;
	        this.E = E | 0;
	        this.F = F | 0;
	        this.G = G | 0;
	        this.H = H | 0;
	    }
	    process(view, offset) {
	        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
	        for (let i = 0; i < 16; i++, offset += 4)
	            SHA256_W[i] = view.getUint32(offset, false);
	        for (let i = 16; i < 64; i++) {
	            const W15 = SHA256_W[i - 15];
	            const W2 = SHA256_W[i - 2];
	            const s0 = (0, utils_js_1.rotr)(W15, 7) ^ (0, utils_js_1.rotr)(W15, 18) ^ (W15 >>> 3);
	            const s1 = (0, utils_js_1.rotr)(W2, 17) ^ (0, utils_js_1.rotr)(W2, 19) ^ (W2 >>> 10);
	            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
	        }
	        // Compression function main loop, 64 rounds
	        let { A, B, C, D, E, F, G, H } = this;
	        for (let i = 0; i < 64; i++) {
	            const sigma1 = (0, utils_js_1.rotr)(E, 6) ^ (0, utils_js_1.rotr)(E, 11) ^ (0, utils_js_1.rotr)(E, 25);
	            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
	            const sigma0 = (0, utils_js_1.rotr)(A, 2) ^ (0, utils_js_1.rotr)(A, 13) ^ (0, utils_js_1.rotr)(A, 22);
	            const T2 = (sigma0 + Maj(A, B, C)) | 0;
	            H = G;
	            G = F;
	            F = E;
	            E = (D + T1) | 0;
	            D = C;
	            C = B;
	            B = A;
	            A = (T1 + T2) | 0;
	        }
	        // Add the compressed chunk to the current hash value
	        A = (A + this.A) | 0;
	        B = (B + this.B) | 0;
	        C = (C + this.C) | 0;
	        D = (D + this.D) | 0;
	        E = (E + this.E) | 0;
	        F = (F + this.F) | 0;
	        G = (G + this.G) | 0;
	        H = (H + this.H) | 0;
	        this.set(A, B, C, D, E, F, G, H);
	    }
	    roundClean() {
	        SHA256_W.fill(0);
	    }
	    destroy() {
	        this.set(0, 0, 0, 0, 0, 0, 0, 0);
	        this.buffer.fill(0);
	    }
	}
	// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
	class SHA224 extends SHA256 {
	    constructor() {
	        super();
	        this.A = 0xc1059ed8 | 0;
	        this.B = 0x367cd507 | 0;
	        this.C = 0x3070dd17 | 0;
	        this.D = 0xf70e5939 | 0;
	        this.E = 0xffc00b31 | 0;
	        this.F = 0x68581511 | 0;
	        this.G = 0x64f98fa7 | 0;
	        this.H = 0xbefa4fa4 | 0;
	        this.outputLen = 28;
	    }
	}
	/**
	 * SHA2-256 hash function
	 * @param message - data that would be hashed
	 */
	sha256.sha256 = (0, utils_js_1.wrapConstructor)(() => new SHA256());
	sha256.sha224 = (0, utils_js_1.wrapConstructor)(() => new SHA224());
	return sha256;
}

var hasRequiredChecksum;

function requireChecksum () {
	if (hasRequiredChecksum) return checksum;
	hasRequiredChecksum = 1;
	Object.defineProperty(checksum, "__esModule", { value: true });
	checksum.c32checkDecode = checksum.c32checkEncode = void 0;
	const sha256_1 = requireSha256();
	const utils_1 = requireUtils();
	const encoding_1 = requireEncoding();
	/**
	 * Get the c32check checksum of a hex-encoded string
	 * @param {string} dataHex - the hex string
	 * @returns {string} the c32 checksum, as a bin-encoded string
	 */
	function c32checksum(dataHex) {
	    const dataHash = (0, sha256_1.sha256)((0, sha256_1.sha256)((0, utils_1.hexToBytes)(dataHex)));
	    const checksum = (0, utils_1.bytesToHex)(dataHash.slice(0, 4));
	    return checksum;
	}
	/**
	 * Encode a hex string as a c32check string.  This is a lot like how
	 * base58check works in Bitcoin-land, but this algorithm uses the
	 * z-base-32 alphabet instead of the base58 alphabet.  The algorithm
	 * is as follows:
	 * * calculate the c32checksum of version + data
	 * * c32encode version + data + c32checksum
	 * @param {number} version - the version string (between 0 and 31)
	 * @param {string} data - the data to encode
	 * @returns {string} the c32check representation
	 */
	function c32checkEncode(version, data) {
	    if (version < 0 || version >= 32) {
	        throw new Error('Invalid version (must be between 0 and 31)');
	    }
	    if (!data.match(/^[0-9a-fA-F]*$/)) {
	        throw new Error('Invalid data (not a hex string)');
	    }
	    data = data.toLowerCase();
	    if (data.length % 2 !== 0) {
	        data = `0${data}`;
	    }
	    let versionHex = version.toString(16);
	    if (versionHex.length === 1) {
	        versionHex = `0${versionHex}`;
	    }
	    const checksumHex = c32checksum(`${versionHex}${data}`);
	    const c32str = (0, encoding_1.c32encode)(`${data}${checksumHex}`);
	    return `${encoding_1.c32[version]}${c32str}`;
	}
	checksum.c32checkEncode = c32checkEncode;
	/*
	 * Decode a c32check string back into its version and data payload.  This is
	 * a lot like how base58check works in Bitcoin-land, but this algorithm uses
	 * the z-base-32 alphabet instead of the base58 alphabet.  The algorithm
	 * is as follows:
	 * * extract the version, data, and checksum
	 * * verify the checksum matches c32checksum(version + data)
	 * * return data
	 * @param {string} c32data - the c32check-encoded string
	 * @returns {array} [version (number), data (string)].  The returned data
	 * will be a hex string.  Throws an exception if the checksum does not match.
	 */
	function c32checkDecode(c32data) {
	    c32data = (0, encoding_1.c32normalize)(c32data);
	    const dataHex = (0, encoding_1.c32decode)(c32data.slice(1));
	    const versionChar = c32data[0];
	    const version = encoding_1.c32.indexOf(versionChar);
	    const checksum = dataHex.slice(-8);
	    let versionHex = version.toString(16);
	    if (versionHex.length === 1) {
	        versionHex = `0${versionHex}`;
	    }
	    if (c32checksum(`${versionHex}${dataHex.substring(0, dataHex.length - 8)}`) !== checksum) {
	        throw new Error('Invalid c32check string: checksum mismatch');
	    }
	    return [version, dataHex.substring(0, dataHex.length - 8)];
	}
	checksum.c32checkDecode = c32checkDecode;
	return checksum;
}

var address = {};

var base58check = {};

var src;
var hasRequiredSrc;

function requireSrc () {
	if (hasRequiredSrc) return src;
	hasRequiredSrc = 1;
	// base-x encoding / decoding
	// Copyright (c) 2018 base-x contributors
	// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
	// Distributed under the MIT software license, see the accompanying
	// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
	function base (ALPHABET) {
	  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
	  var BASE_MAP = new Uint8Array(256);
	  for (var j = 0; j < BASE_MAP.length; j++) {
	    BASE_MAP[j] = 255;
	  }
	  for (var i = 0; i < ALPHABET.length; i++) {
	    var x = ALPHABET.charAt(i);
	    var xc = x.charCodeAt(0);
	    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
	    BASE_MAP[xc] = i;
	  }
	  var BASE = ALPHABET.length;
	  var LEADER = ALPHABET.charAt(0);
	  var FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up
	  var iFACTOR = Math.log(256) / Math.log(BASE); // log(256) / log(BASE), rounded up
	  function encode (source) {
	    if (source instanceof Uint8Array) ; else if (ArrayBuffer.isView(source)) {
	      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
	    } else if (Array.isArray(source)) {
	      source = Uint8Array.from(source);
	    }
	    if (!(source instanceof Uint8Array)) { throw new TypeError('Expected Uint8Array') }
	    if (source.length === 0) { return '' }
	        // Skip & count leading zeroes.
	    var zeroes = 0;
	    var length = 0;
	    var pbegin = 0;
	    var pend = source.length;
	    while (pbegin !== pend && source[pbegin] === 0) {
	      pbegin++;
	      zeroes++;
	    }
	        // Allocate enough space in big-endian base58 representation.
	    var size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
	    var b58 = new Uint8Array(size);
	        // Process the bytes.
	    while (pbegin !== pend) {
	      var carry = source[pbegin];
	            // Apply "b58 = b58 * 256 + ch".
	      var i = 0;
	      for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
	        carry += (256 * b58[it1]) >>> 0;
	        b58[it1] = (carry % BASE) >>> 0;
	        carry = (carry / BASE) >>> 0;
	      }
	      if (carry !== 0) { throw new Error('Non-zero carry') }
	      length = i;
	      pbegin++;
	    }
	        // Skip leading zeroes in base58 result.
	    var it2 = size - length;
	    while (it2 !== size && b58[it2] === 0) {
	      it2++;
	    }
	        // Translate the result into a string.
	    var str = LEADER.repeat(zeroes);
	    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]); }
	    return str
	  }
	  function decodeUnsafe (source) {
	    if (typeof source !== 'string') { throw new TypeError('Expected String') }
	    if (source.length === 0) { return new Uint8Array() }
	    var psz = 0;
	        // Skip and count leading '1's.
	    var zeroes = 0;
	    var length = 0;
	    while (source[psz] === LEADER) {
	      zeroes++;
	      psz++;
	    }
	        // Allocate enough space in big-endian base256 representation.
	    var size = (((source.length - psz) * FACTOR) + 1) >>> 0; // log(58) / log(256), rounded up.
	    var b256 = new Uint8Array(size);
	        // Process the characters.
	    while (source[psz]) {
	            // Find code of next character
	      var charCode = source.charCodeAt(psz);
	            // Base map can not be indexed using char code
	      if (charCode > 255) { return }
	            // Decode character
	      var carry = BASE_MAP[charCode];
	            // Invalid character
	      if (carry === 255) { return }
	      var i = 0;
	      for (var it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
	        carry += (BASE * b256[it3]) >>> 0;
	        b256[it3] = (carry % 256) >>> 0;
	        carry = (carry / 256) >>> 0;
	      }
	      if (carry !== 0) { throw new Error('Non-zero carry') }
	      length = i;
	      psz++;
	    }
	        // Skip leading zeroes in b256.
	    var it4 = size - length;
	    while (it4 !== size && b256[it4] === 0) {
	      it4++;
	    }
	    var vch = new Uint8Array(zeroes + (size - it4));
	    var j = zeroes;
	    while (it4 !== size) {
	      vch[j++] = b256[it4++];
	    }
	    return vch
	  }
	  function decode (string) {
	    var buffer = decodeUnsafe(string);
	    if (buffer) { return buffer }
	    throw new Error('Non-base' + BASE + ' character')
	  }
	  return {
	    encode: encode,
	    decodeUnsafe: decodeUnsafe,
	    decode: decode
	  }
	}
	src = base;
	return src;
}

/*
 * From https://github.com/wzbg/base58check
 * @Author: zyc
 * @Date:   2016-09-11 23:36:05
 */

var hasRequiredBase58check;

function requireBase58check () {
	if (hasRequiredBase58check) return base58check;
	hasRequiredBase58check = 1;
	Object.defineProperty(base58check, "__esModule", { value: true });
	base58check.decode = base58check.encode = void 0;
	const sha256_1 = requireSha256();
	const utils_1 = requireUtils();
	const basex = requireSrc();
	const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	function encode(data, prefix = '00') {
	    const dataBytes = typeof data === 'string' ? (0, utils_1.hexToBytes)(data) : data;
	    const prefixBytes = typeof prefix === 'string' ? (0, utils_1.hexToBytes)(prefix) : data;
	    if (!(dataBytes instanceof Uint8Array) || !(prefixBytes instanceof Uint8Array)) {
	        throw new TypeError('Argument must be of type Uint8Array or string');
	    }
	    const checksum = (0, sha256_1.sha256)((0, sha256_1.sha256)(new Uint8Array([...prefixBytes, ...dataBytes])));
	    return basex(ALPHABET).encode([...prefixBytes, ...dataBytes, ...checksum.slice(0, 4)]);
	}
	base58check.encode = encode;
	function decode(string) {
	    const bytes = basex(ALPHABET).decode(string);
	    const prefixBytes = bytes.slice(0, 1);
	    const dataBytes = bytes.slice(1, -4);
	    // todo: for better performance replace spread with `concatBytes` method
	    const checksum = (0, sha256_1.sha256)((0, sha256_1.sha256)(new Uint8Array([...prefixBytes, ...dataBytes])));
	    bytes.slice(-4).forEach((check, index) => {
	        if (check !== checksum[index]) {
	            throw new Error('Invalid checksum');
	        }
	    });
	    return { prefix: prefixBytes, data: dataBytes };
	}
	base58check.decode = decode;
	return base58check;
}

var hasRequiredAddress;

function requireAddress () {
	if (hasRequiredAddress) return address;
	hasRequiredAddress = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.c32ToB58 = exports.b58ToC32 = exports.c32addressDecode = exports.c32address = exports.versions = void 0;
		const checksum_1 = requireChecksum();
		const base58check = requireBase58check();
		const utils_1 = requireUtils();
		exports.versions = {
		    mainnet: {
		        p2pkh: 22,
		        p2sh: 20, // 'M'
		    },
		    testnet: {
		        p2pkh: 26,
		        p2sh: 21, // 'N'
		    },
		};
		// address conversion : bitcoin to stacks
		const ADDR_BITCOIN_TO_STACKS = {};
		ADDR_BITCOIN_TO_STACKS[0] = exports.versions.mainnet.p2pkh;
		ADDR_BITCOIN_TO_STACKS[5] = exports.versions.mainnet.p2sh;
		ADDR_BITCOIN_TO_STACKS[111] = exports.versions.testnet.p2pkh;
		ADDR_BITCOIN_TO_STACKS[196] = exports.versions.testnet.p2sh;
		// address conversion : stacks to bitcoin
		const ADDR_STACKS_TO_BITCOIN = {};
		ADDR_STACKS_TO_BITCOIN[exports.versions.mainnet.p2pkh] = 0;
		ADDR_STACKS_TO_BITCOIN[exports.versions.mainnet.p2sh] = 5;
		ADDR_STACKS_TO_BITCOIN[exports.versions.testnet.p2pkh] = 111;
		ADDR_STACKS_TO_BITCOIN[exports.versions.testnet.p2sh] = 196;
		/**
		 * Make a c32check address with the given version and hash160
		 * The only difference between a c32check string and c32 address
		 * is that the letter 'S' is pre-pended.
		 * @param {number} version - the address version number
		 * @param {string} hash160hex - the hash160 to encode (must be a hash160)
		 * @returns {string} the address
		 */
		function c32address(version, hash160hex) {
		    if (!hash160hex.match(/^[0-9a-fA-F]{40}$/)) {
		        throw new Error('Invalid argument: not a hash160 hex string');
		    }
		    const c32string = (0, checksum_1.c32checkEncode)(version, hash160hex);
		    return `S${c32string}`;
		}
		exports.c32address = c32address;
		/**
		 * Decode a c32 address into its version and hash160
		 * @param {string} c32addr - the c32check-encoded address
		 * @returns {[number, string]} a tuple with the version and hash160
		 */
		function c32addressDecode(c32addr) {
		    if (c32addr.length <= 5) {
		        throw new Error('Invalid c32 address: invalid length');
		    }
		    if (c32addr[0] != 'S') {
		        throw new Error('Invalid c32 address: must start with "S"');
		    }
		    return (0, checksum_1.c32checkDecode)(c32addr.slice(1));
		}
		exports.c32addressDecode = c32addressDecode;
		/*
		 * Convert a base58check address to a c32check address.
		 * Try to convert the version number if one is not given.
		 * @param {string} b58check - the base58check encoded address
		 * @param {number} version - the version number, if not inferred from the address
		 * @returns {string} the c32 address with the given version number (or the
		 *   semantically-equivalent c32 version number, if not given)
		 */
		function b58ToC32(b58check, version = -1) {
		    const addrInfo = base58check.decode(b58check);
		    const hash160String = (0, utils_1.bytesToHex)(addrInfo.data);
		    const addrVersion = parseInt((0, utils_1.bytesToHex)(addrInfo.prefix), 16);
		    let stacksVersion;
		    if (version < 0) {
		        stacksVersion = addrVersion;
		        if (ADDR_BITCOIN_TO_STACKS[addrVersion] !== undefined) {
		            stacksVersion = ADDR_BITCOIN_TO_STACKS[addrVersion];
		        }
		    }
		    else {
		        stacksVersion = version;
		    }
		    return c32address(stacksVersion, hash160String);
		}
		exports.b58ToC32 = b58ToC32;
		/*
		 * Convert a c32check address to a base58check address.
		 * @param {string} c32string - the c32check address
		 * @param {number} version - the version number, if not inferred from the address
		 * @returns {string} the base58 address with the given version number (or the
		 *    semantically-equivalent bitcoin version number, if not given)
		 */
		function c32ToB58(c32string, version = -1) {
		    const addrInfo = c32addressDecode(c32string);
		    const stacksVersion = addrInfo[0];
		    const hash160String = addrInfo[1];
		    let bitcoinVersion;
		    if (version < 0) {
		        bitcoinVersion = stacksVersion;
		        if (ADDR_STACKS_TO_BITCOIN[stacksVersion] !== undefined) {
		            bitcoinVersion = ADDR_STACKS_TO_BITCOIN[stacksVersion];
		        }
		    }
		    else {
		        bitcoinVersion = version;
		    }
		    let prefix = bitcoinVersion.toString(16);
		    if (prefix.length === 1) {
		        prefix = `0${prefix}`;
		    }
		    return base58check.encode(hash160String, prefix);
		}
		exports.c32ToB58 = c32ToB58; 
	} (address));
	return address;
}

var hasRequiredLib;

function requireLib () {
	if (hasRequiredLib) return lib;
	hasRequiredLib = 1;
	(function (exports) {
		Object.defineProperty(exports, "__esModule", { value: true });
		exports.b58ToC32 = exports.c32ToB58 = exports.versions = exports.c32normalize = exports.c32addressDecode = exports.c32address = exports.c32checkDecode = exports.c32checkEncode = exports.c32decode = exports.c32encode = void 0;
		const encoding_1 = requireEncoding();
		Object.defineProperty(exports, "c32encode", { enumerable: true, get: function () { return encoding_1.c32encode; } });
		Object.defineProperty(exports, "c32decode", { enumerable: true, get: function () { return encoding_1.c32decode; } });
		Object.defineProperty(exports, "c32normalize", { enumerable: true, get: function () { return encoding_1.c32normalize; } });
		const checksum_1 = requireChecksum();
		Object.defineProperty(exports, "c32checkEncode", { enumerable: true, get: function () { return checksum_1.c32checkEncode; } });
		Object.defineProperty(exports, "c32checkDecode", { enumerable: true, get: function () { return checksum_1.c32checkDecode; } });
		const address_1 = requireAddress();
		Object.defineProperty(exports, "c32address", { enumerable: true, get: function () { return address_1.c32address; } });
		Object.defineProperty(exports, "c32addressDecode", { enumerable: true, get: function () { return address_1.c32addressDecode; } });
		Object.defineProperty(exports, "c32ToB58", { enumerable: true, get: function () { return address_1.c32ToB58; } });
		Object.defineProperty(exports, "b58ToC32", { enumerable: true, get: function () { return address_1.b58ToC32; } });
		Object.defineProperty(exports, "versions", { enumerable: true, get: function () { return address_1.versions; } }); 
	} (lib));
	return lib;
}

var libExports = requireLib();

// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
// https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
const Rho = new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
const Id = Uint8Array.from({ length: 16 }, (_, i) => i);
const Pi = Id.map((i) => (9 * i + 5) % 16);
let idxL = [Id];
let idxR = [Pi];
for (let i = 0; i < 4; i++)
    for (let j of [idxL, idxR])
        j.push(j[i].map((k) => Rho[k]));
const shifts = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => new Uint8Array(i));
const shiftsL = idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
const shiftsR = idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
const Kl = new Uint32Array([0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]);
const Kr = new Uint32Array([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]);
// The rotate left (circular left shift) operation for uint32
const rotl = (word, shift) => (word << shift) | (word >>> (32 - shift));
// It's called f() in spec.
function f(group, x, y, z) {
    if (group === 0)
        return x ^ y ^ z;
    else if (group === 1)
        return (x & y) | (~x & z);
    else if (group === 2)
        return (x | ~y) ^ z;
    else if (group === 3)
        return (x & z) | (y & ~z);
    else
        return x ^ (y | ~z);
}
// Temporary buffer, not used to store anything between runs
const BUF = new Uint32Array(16);
class RIPEMD160 extends SHA2 {
    constructor() {
        super(64, 20, 8, true);
        this.h0 = 0x67452301 | 0;
        this.h1 = 0xefcdab89 | 0;
        this.h2 = 0x98badcfe | 0;
        this.h3 = 0x10325476 | 0;
        this.h4 = 0xc3d2e1f0 | 0;
    }
    get() {
        const { h0, h1, h2, h3, h4 } = this;
        return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
        this.h0 = h0 | 0;
        this.h1 = h1 | 0;
        this.h2 = h2 | 0;
        this.h3 = h3 | 0;
        this.h4 = h4 | 0;
    }
    process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
            BUF[i] = view.getUint32(offset, true);
        // prettier-ignore
        let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
        // Instead of iterating 0 to 80, we split it into 5 groups
        // And use the groups in constants, functions, etc. Much simpler
        for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
            const rl = idxL[group], rr = idxR[group]; // prettier-ignore
            const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
            for (let i = 0; i < 16; i++) {
                const tl = (rotl(al + f(group, bl, cl, dl) + BUF[rl[i]] + hbl, sl[i]) + el) | 0;
                al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
            }
            // 2 loops are 10% faster
            for (let i = 0; i < 16; i++) {
                const tr = (rotl(ar + f(rGroup, br, cr, dr) + BUF[rr[i]] + hbr, sr[i]) + er) | 0;
                ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
            }
        }
        // Add the compressed chunk to the current hash value
        this.set((this.h1 + cl + dr) | 0, (this.h2 + dl + er) | 0, (this.h3 + el + ar) | 0, (this.h4 + al + br) | 0, (this.h0 + bl + cr) | 0);
    }
    roundClean() {
        BUF.fill(0);
    }
    destroy() {
        this.destroyed = true;
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0);
    }
}
/**
 * RIPEMD-160 - a hash function from 1990s.
 * @param message - msg that would be hashed
 */
const ripemd160 = wrapConstructor(() => new RIPEMD160());

const U32_MASK64 = BigInt(2 ** 32 - 1);
const _32n = BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
// for Shift in [0, 32)
const shrSH = (h, l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (h, l) => l;
const rotr32L = (h, l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
// Removing "export" has 5% perf penalty -_-
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore
const u64 = {
    fromBig, split, toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};

// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
// prettier-ignore
const [SHA512_Kh, SHA512_Kl] = u64.split([
    '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
    '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
    '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
    '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
    '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
    '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
    '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
    '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
    '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
    '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
    '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
    '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
    '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
    '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
    '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
    '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
    '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
    '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
    '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
    '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
].map(n => BigInt(n)));
// Temporary buffer, not used to store anything between runs
const SHA512_W_H = new Uint32Array(80);
const SHA512_W_L = new Uint32Array(80);
class SHA512 extends SHA2 {
    constructor() {
        super(128, 64, 16, false);
        // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
        // Also looks cleaner and easier to verify with spec.
        // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x6a09e667 | 0;
        this.Al = 0xf3bcc908 | 0;
        this.Bh = 0xbb67ae85 | 0;
        this.Bl = 0x84caa73b | 0;
        this.Ch = 0x3c6ef372 | 0;
        this.Cl = 0xfe94f82b | 0;
        this.Dh = 0xa54ff53a | 0;
        this.Dl = 0x5f1d36f1 | 0;
        this.Eh = 0x510e527f | 0;
        this.El = 0xade682d1 | 0;
        this.Fh = 0x9b05688c | 0;
        this.Fl = 0x2b3e6c1f | 0;
        this.Gh = 0x1f83d9ab | 0;
        this.Gl = 0xfb41bd6b | 0;
        this.Hh = 0x5be0cd19 | 0;
        this.Hl = 0x137e2179 | 0;
    }
    // prettier-ignore
    get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32((offset += 4));
        }
        for (let i = 16; i < 80; i++) {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
            const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
            const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
            // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
            const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        // Compression function main loop, 80 rounds
        for (let i = 0; i < 80; i++) {
            // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
            const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
            //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const CHIh = (Eh & Fh) ^ (~Eh & Gh);
            const CHIl = (El & Fl) ^ (~El & Gl);
            // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
            // prettier-ignore
            const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
            const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
            const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
            const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = u64.add3L(T1l, sigma0l, MAJl);
            Ah = u64.add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
        }
        // Add the compressed chunk to the current hash value
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
        SHA512_W_H.fill(0);
        SHA512_W_L.fill(0);
    }
    destroy() {
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
class SHA512_224 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x8c3d37c8 | 0;
        this.Al = 0x19544da2 | 0;
        this.Bh = 0x73e19966 | 0;
        this.Bl = 0x89dcd4d6 | 0;
        this.Ch = 0x1dfab7ae | 0;
        this.Cl = 0x32ff9c82 | 0;
        this.Dh = 0x679dd514 | 0;
        this.Dl = 0x582f9fcf | 0;
        this.Eh = 0x0f6d2b69 | 0;
        this.El = 0x7bd44da8 | 0;
        this.Fh = 0x77e36f73 | 0;
        this.Fl = 0x04c48942 | 0;
        this.Gh = 0x3f9d85a8 | 0;
        this.Gl = 0x6a1d36c8 | 0;
        this.Hh = 0x1112e6ad | 0;
        this.Hl = 0x91d692a1 | 0;
        this.outputLen = 28;
    }
}
class SHA512_256 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x22312194 | 0;
        this.Al = 0xfc2bf72c | 0;
        this.Bh = 0x9f555fa3 | 0;
        this.Bl = 0xc84c64c2 | 0;
        this.Ch = 0x2393b86b | 0;
        this.Cl = 0x6f53b151 | 0;
        this.Dh = 0x96387719 | 0;
        this.Dl = 0x5940eabd | 0;
        this.Eh = 0x96283ee2 | 0;
        this.El = 0xa88effe3 | 0;
        this.Fh = 0xbe5e1e25 | 0;
        this.Fl = 0x53863992 | 0;
        this.Gh = 0x2b0199fc | 0;
        this.Gl = 0x2c85b8aa | 0;
        this.Hh = 0x0eb72ddc | 0;
        this.Hl = 0x81c52ca2 | 0;
        this.outputLen = 32;
    }
}
class SHA384 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0xcbbb9d5d | 0;
        this.Al = 0xc1059ed8 | 0;
        this.Bh = 0x629a292a | 0;
        this.Bl = 0x367cd507 | 0;
        this.Ch = 0x9159015a | 0;
        this.Cl = 0x3070dd17 | 0;
        this.Dh = 0x152fecd8 | 0;
        this.Dl = 0xf70e5939 | 0;
        this.Eh = 0x67332667 | 0;
        this.El = 0xffc00b31 | 0;
        this.Fh = 0x8eb44a87 | 0;
        this.Fl = 0x68581511 | 0;
        this.Gh = 0xdb0c2e0d | 0;
        this.Gl = 0x64f98fa7 | 0;
        this.Hh = 0x47b5481d | 0;
        this.Hl = 0xbefa4fa4 | 0;
        this.outputLen = 48;
    }
}
wrapConstructor(() => new SHA512());
wrapConstructor(() => new SHA512_224());
const sha512_256 = wrapConstructor(() => new SHA512_256());
wrapConstructor(() => new SHA384());

var lodash_clonedeep = {exports: {}};

/**
 * lodash (Custom Build) <https://lodash.com/>
 * Build: `lodash modularize exports="npm" -o ./`
 * Copyright jQuery Foundation and other contributors <https://jquery.org/>
 * Released under MIT license <https://lodash.com/license>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 */
lodash_clonedeep.exports;

var hasRequiredLodash_clonedeep;

function requireLodash_clonedeep () {
	if (hasRequiredLodash_clonedeep) return lodash_clonedeep.exports;
	hasRequiredLodash_clonedeep = 1;
	(function (module, exports) {
		/** Used as the size to enable large array optimizations. */
		var LARGE_ARRAY_SIZE = 200;

		/** Used to stand-in for `undefined` hash values. */
		var HASH_UNDEFINED = '__lodash_hash_undefined__';

		/** Used as references for various `Number` constants. */
		var MAX_SAFE_INTEGER = 9007199254740991;

		/** `Object#toString` result references. */
		var argsTag = '[object Arguments]',
		    arrayTag = '[object Array]',
		    boolTag = '[object Boolean]',
		    dateTag = '[object Date]',
		    errorTag = '[object Error]',
		    funcTag = '[object Function]',
		    genTag = '[object GeneratorFunction]',
		    mapTag = '[object Map]',
		    numberTag = '[object Number]',
		    objectTag = '[object Object]',
		    promiseTag = '[object Promise]',
		    regexpTag = '[object RegExp]',
		    setTag = '[object Set]',
		    stringTag = '[object String]',
		    symbolTag = '[object Symbol]',
		    weakMapTag = '[object WeakMap]';

		var arrayBufferTag = '[object ArrayBuffer]',
		    dataViewTag = '[object DataView]',
		    float32Tag = '[object Float32Array]',
		    float64Tag = '[object Float64Array]',
		    int8Tag = '[object Int8Array]',
		    int16Tag = '[object Int16Array]',
		    int32Tag = '[object Int32Array]',
		    uint8Tag = '[object Uint8Array]',
		    uint8ClampedTag = '[object Uint8ClampedArray]',
		    uint16Tag = '[object Uint16Array]',
		    uint32Tag = '[object Uint32Array]';

		/**
		 * Used to match `RegExp`
		 * [syntax characters](http://ecma-international.org/ecma-262/7.0/#sec-patterns).
		 */
		var reRegExpChar = /[\\^$.*+?()[\]{}|]/g;

		/** Used to match `RegExp` flags from their coerced string values. */
		var reFlags = /\w*$/;

		/** Used to detect host constructors (Safari). */
		var reIsHostCtor = /^\[object .+?Constructor\]$/;

		/** Used to detect unsigned integer values. */
		var reIsUint = /^(?:0|[1-9]\d*)$/;

		/** Used to identify `toStringTag` values supported by `_.clone`. */
		var cloneableTags = {};
		cloneableTags[argsTag] = cloneableTags[arrayTag] =
		cloneableTags[arrayBufferTag] = cloneableTags[dataViewTag] =
		cloneableTags[boolTag] = cloneableTags[dateTag] =
		cloneableTags[float32Tag] = cloneableTags[float64Tag] =
		cloneableTags[int8Tag] = cloneableTags[int16Tag] =
		cloneableTags[int32Tag] = cloneableTags[mapTag] =
		cloneableTags[numberTag] = cloneableTags[objectTag] =
		cloneableTags[regexpTag] = cloneableTags[setTag] =
		cloneableTags[stringTag] = cloneableTags[symbolTag] =
		cloneableTags[uint8Tag] = cloneableTags[uint8ClampedTag] =
		cloneableTags[uint16Tag] = cloneableTags[uint32Tag] = true;
		cloneableTags[errorTag] = cloneableTags[funcTag] =
		cloneableTags[weakMapTag] = false;

		/** Detect free variable `global` from Node.js. */
		var freeGlobal = typeof commonjsGlobal == 'object' && commonjsGlobal && commonjsGlobal.Object === Object && commonjsGlobal;

		/** Detect free variable `self`. */
		var freeSelf = typeof self == 'object' && self && self.Object === Object && self;

		/** Used as a reference to the global object. */
		var root = freeGlobal || freeSelf || Function('return this')();

		/** Detect free variable `exports`. */
		var freeExports = exports && !exports.nodeType && exports;

		/** Detect free variable `module`. */
		var freeModule = freeExports && 'object' == 'object' && module && !module.nodeType && module;

		/** Detect the popular CommonJS extension `module.exports`. */
		var moduleExports = freeModule && freeModule.exports === freeExports;

		/**
		 * Adds the key-value `pair` to `map`.
		 *
		 * @private
		 * @param {Object} map The map to modify.
		 * @param {Array} pair The key-value pair to add.
		 * @returns {Object} Returns `map`.
		 */
		function addMapEntry(map, pair) {
		  // Don't return `map.set` because it's not chainable in IE 11.
		  map.set(pair[0], pair[1]);
		  return map;
		}

		/**
		 * Adds `value` to `set`.
		 *
		 * @private
		 * @param {Object} set The set to modify.
		 * @param {*} value The value to add.
		 * @returns {Object} Returns `set`.
		 */
		function addSetEntry(set, value) {
		  // Don't return `set.add` because it's not chainable in IE 11.
		  set.add(value);
		  return set;
		}

		/**
		 * A specialized version of `_.forEach` for arrays without support for
		 * iteratee shorthands.
		 *
		 * @private
		 * @param {Array} [array] The array to iterate over.
		 * @param {Function} iteratee The function invoked per iteration.
		 * @returns {Array} Returns `array`.
		 */
		function arrayEach(array, iteratee) {
		  var index = -1,
		      length = array ? array.length : 0;

		  while (++index < length) {
		    if (iteratee(array[index], index, array) === false) {
		      break;
		    }
		  }
		  return array;
		}

		/**
		 * Appends the elements of `values` to `array`.
		 *
		 * @private
		 * @param {Array} array The array to modify.
		 * @param {Array} values The values to append.
		 * @returns {Array} Returns `array`.
		 */
		function arrayPush(array, values) {
		  var index = -1,
		      length = values.length,
		      offset = array.length;

		  while (++index < length) {
		    array[offset + index] = values[index];
		  }
		  return array;
		}

		/**
		 * A specialized version of `_.reduce` for arrays without support for
		 * iteratee shorthands.
		 *
		 * @private
		 * @param {Array} [array] The array to iterate over.
		 * @param {Function} iteratee The function invoked per iteration.
		 * @param {*} [accumulator] The initial value.
		 * @param {boolean} [initAccum] Specify using the first element of `array` as
		 *  the initial value.
		 * @returns {*} Returns the accumulated value.
		 */
		function arrayReduce(array, iteratee, accumulator, initAccum) {
		  var index = -1,
		      length = array ? array.length : 0;
		  while (++index < length) {
		    accumulator = iteratee(accumulator, array[index], index, array);
		  }
		  return accumulator;
		}

		/**
		 * The base implementation of `_.times` without support for iteratee shorthands
		 * or max array length checks.
		 *
		 * @private
		 * @param {number} n The number of times to invoke `iteratee`.
		 * @param {Function} iteratee The function invoked per iteration.
		 * @returns {Array} Returns the array of results.
		 */
		function baseTimes(n, iteratee) {
		  var index = -1,
		      result = Array(n);

		  while (++index < n) {
		    result[index] = iteratee(index);
		  }
		  return result;
		}

		/**
		 * Gets the value at `key` of `object`.
		 *
		 * @private
		 * @param {Object} [object] The object to query.
		 * @param {string} key The key of the property to get.
		 * @returns {*} Returns the property value.
		 */
		function getValue(object, key) {
		  return object == null ? undefined : object[key];
		}

		/**
		 * Checks if `value` is a host object in IE < 9.
		 *
		 * @private
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a host object, else `false`.
		 */
		function isHostObject(value) {
		  // Many host objects are `Object` objects that can coerce to strings
		  // despite having improperly defined `toString` methods.
		  var result = false;
		  if (value != null && typeof value.toString != 'function') {
		    try {
		      result = !!(value + '');
		    } catch (e) {}
		  }
		  return result;
		}

		/**
		 * Converts `map` to its key-value pairs.
		 *
		 * @private
		 * @param {Object} map The map to convert.
		 * @returns {Array} Returns the key-value pairs.
		 */
		function mapToArray(map) {
		  var index = -1,
		      result = Array(map.size);

		  map.forEach(function(value, key) {
		    result[++index] = [key, value];
		  });
		  return result;
		}

		/**
		 * Creates a unary function that invokes `func` with its argument transformed.
		 *
		 * @private
		 * @param {Function} func The function to wrap.
		 * @param {Function} transform The argument transform.
		 * @returns {Function} Returns the new function.
		 */
		function overArg(func, transform) {
		  return function(arg) {
		    return func(transform(arg));
		  };
		}

		/**
		 * Converts `set` to an array of its values.
		 *
		 * @private
		 * @param {Object} set The set to convert.
		 * @returns {Array} Returns the values.
		 */
		function setToArray(set) {
		  var index = -1,
		      result = Array(set.size);

		  set.forEach(function(value) {
		    result[++index] = value;
		  });
		  return result;
		}

		/** Used for built-in method references. */
		var arrayProto = Array.prototype,
		    funcProto = Function.prototype,
		    objectProto = Object.prototype;

		/** Used to detect overreaching core-js shims. */
		var coreJsData = root['__core-js_shared__'];

		/** Used to detect methods masquerading as native. */
		var maskSrcKey = (function() {
		  var uid = /[^.]+$/.exec(coreJsData && coreJsData.keys && coreJsData.keys.IE_PROTO || '');
		  return uid ? ('Symbol(src)_1.' + uid) : '';
		}());

		/** Used to resolve the decompiled source of functions. */
		var funcToString = funcProto.toString;

		/** Used to check objects for own properties. */
		var hasOwnProperty = objectProto.hasOwnProperty;

		/**
		 * Used to resolve the
		 * [`toStringTag`](http://ecma-international.org/ecma-262/7.0/#sec-object.prototype.tostring)
		 * of values.
		 */
		var objectToString = objectProto.toString;

		/** Used to detect if a method is native. */
		var reIsNative = RegExp('^' +
		  funcToString.call(hasOwnProperty).replace(reRegExpChar, '\\$&')
		  .replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, '$1.*?') + '$'
		);

		/** Built-in value references. */
		var Buffer = moduleExports ? root.Buffer : undefined,
		    Symbol = root.Symbol,
		    Uint8Array = root.Uint8Array,
		    getPrototype = overArg(Object.getPrototypeOf, Object),
		    objectCreate = Object.create,
		    propertyIsEnumerable = objectProto.propertyIsEnumerable,
		    splice = arrayProto.splice;

		/* Built-in method references for those with the same name as other `lodash` methods. */
		var nativeGetSymbols = Object.getOwnPropertySymbols,
		    nativeIsBuffer = Buffer ? Buffer.isBuffer : undefined,
		    nativeKeys = overArg(Object.keys, Object);

		/* Built-in method references that are verified to be native. */
		var DataView = getNative(root, 'DataView'),
		    Map = getNative(root, 'Map'),
		    Promise = getNative(root, 'Promise'),
		    Set = getNative(root, 'Set'),
		    WeakMap = getNative(root, 'WeakMap'),
		    nativeCreate = getNative(Object, 'create');

		/** Used to detect maps, sets, and weakmaps. */
		var dataViewCtorString = toSource(DataView),
		    mapCtorString = toSource(Map),
		    promiseCtorString = toSource(Promise),
		    setCtorString = toSource(Set),
		    weakMapCtorString = toSource(WeakMap);

		/** Used to convert symbols to primitives and strings. */
		var symbolProto = Symbol ? Symbol.prototype : undefined,
		    symbolValueOf = symbolProto ? symbolProto.valueOf : undefined;

		/**
		 * Creates a hash object.
		 *
		 * @private
		 * @constructor
		 * @param {Array} [entries] The key-value pairs to cache.
		 */
		function Hash(entries) {
		  var index = -1,
		      length = entries ? entries.length : 0;

		  this.clear();
		  while (++index < length) {
		    var entry = entries[index];
		    this.set(entry[0], entry[1]);
		  }
		}

		/**
		 * Removes all key-value entries from the hash.
		 *
		 * @private
		 * @name clear
		 * @memberOf Hash
		 */
		function hashClear() {
		  this.__data__ = nativeCreate ? nativeCreate(null) : {};
		}

		/**
		 * Removes `key` and its value from the hash.
		 *
		 * @private
		 * @name delete
		 * @memberOf Hash
		 * @param {Object} hash The hash to modify.
		 * @param {string} key The key of the value to remove.
		 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
		 */
		function hashDelete(key) {
		  return this.has(key) && delete this.__data__[key];
		}

		/**
		 * Gets the hash value for `key`.
		 *
		 * @private
		 * @name get
		 * @memberOf Hash
		 * @param {string} key The key of the value to get.
		 * @returns {*} Returns the entry value.
		 */
		function hashGet(key) {
		  var data = this.__data__;
		  if (nativeCreate) {
		    var result = data[key];
		    return result === HASH_UNDEFINED ? undefined : result;
		  }
		  return hasOwnProperty.call(data, key) ? data[key] : undefined;
		}

		/**
		 * Checks if a hash value for `key` exists.
		 *
		 * @private
		 * @name has
		 * @memberOf Hash
		 * @param {string} key The key of the entry to check.
		 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
		 */
		function hashHas(key) {
		  var data = this.__data__;
		  return nativeCreate ? data[key] !== undefined : hasOwnProperty.call(data, key);
		}

		/**
		 * Sets the hash `key` to `value`.
		 *
		 * @private
		 * @name set
		 * @memberOf Hash
		 * @param {string} key The key of the value to set.
		 * @param {*} value The value to set.
		 * @returns {Object} Returns the hash instance.
		 */
		function hashSet(key, value) {
		  var data = this.__data__;
		  data[key] = (nativeCreate && value === undefined) ? HASH_UNDEFINED : value;
		  return this;
		}

		// Add methods to `Hash`.
		Hash.prototype.clear = hashClear;
		Hash.prototype['delete'] = hashDelete;
		Hash.prototype.get = hashGet;
		Hash.prototype.has = hashHas;
		Hash.prototype.set = hashSet;

		/**
		 * Creates an list cache object.
		 *
		 * @private
		 * @constructor
		 * @param {Array} [entries] The key-value pairs to cache.
		 */
		function ListCache(entries) {
		  var index = -1,
		      length = entries ? entries.length : 0;

		  this.clear();
		  while (++index < length) {
		    var entry = entries[index];
		    this.set(entry[0], entry[1]);
		  }
		}

		/**
		 * Removes all key-value entries from the list cache.
		 *
		 * @private
		 * @name clear
		 * @memberOf ListCache
		 */
		function listCacheClear() {
		  this.__data__ = [];
		}

		/**
		 * Removes `key` and its value from the list cache.
		 *
		 * @private
		 * @name delete
		 * @memberOf ListCache
		 * @param {string} key The key of the value to remove.
		 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
		 */
		function listCacheDelete(key) {
		  var data = this.__data__,
		      index = assocIndexOf(data, key);

		  if (index < 0) {
		    return false;
		  }
		  var lastIndex = data.length - 1;
		  if (index == lastIndex) {
		    data.pop();
		  } else {
		    splice.call(data, index, 1);
		  }
		  return true;
		}

		/**
		 * Gets the list cache value for `key`.
		 *
		 * @private
		 * @name get
		 * @memberOf ListCache
		 * @param {string} key The key of the value to get.
		 * @returns {*} Returns the entry value.
		 */
		function listCacheGet(key) {
		  var data = this.__data__,
		      index = assocIndexOf(data, key);

		  return index < 0 ? undefined : data[index][1];
		}

		/**
		 * Checks if a list cache value for `key` exists.
		 *
		 * @private
		 * @name has
		 * @memberOf ListCache
		 * @param {string} key The key of the entry to check.
		 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
		 */
		function listCacheHas(key) {
		  return assocIndexOf(this.__data__, key) > -1;
		}

		/**
		 * Sets the list cache `key` to `value`.
		 *
		 * @private
		 * @name set
		 * @memberOf ListCache
		 * @param {string} key The key of the value to set.
		 * @param {*} value The value to set.
		 * @returns {Object} Returns the list cache instance.
		 */
		function listCacheSet(key, value) {
		  var data = this.__data__,
		      index = assocIndexOf(data, key);

		  if (index < 0) {
		    data.push([key, value]);
		  } else {
		    data[index][1] = value;
		  }
		  return this;
		}

		// Add methods to `ListCache`.
		ListCache.prototype.clear = listCacheClear;
		ListCache.prototype['delete'] = listCacheDelete;
		ListCache.prototype.get = listCacheGet;
		ListCache.prototype.has = listCacheHas;
		ListCache.prototype.set = listCacheSet;

		/**
		 * Creates a map cache object to store key-value pairs.
		 *
		 * @private
		 * @constructor
		 * @param {Array} [entries] The key-value pairs to cache.
		 */
		function MapCache(entries) {
		  var index = -1,
		      length = entries ? entries.length : 0;

		  this.clear();
		  while (++index < length) {
		    var entry = entries[index];
		    this.set(entry[0], entry[1]);
		  }
		}

		/**
		 * Removes all key-value entries from the map.
		 *
		 * @private
		 * @name clear
		 * @memberOf MapCache
		 */
		function mapCacheClear() {
		  this.__data__ = {
		    'hash': new Hash,
		    'map': new (Map || ListCache),
		    'string': new Hash
		  };
		}

		/**
		 * Removes `key` and its value from the map.
		 *
		 * @private
		 * @name delete
		 * @memberOf MapCache
		 * @param {string} key The key of the value to remove.
		 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
		 */
		function mapCacheDelete(key) {
		  return getMapData(this, key)['delete'](key);
		}

		/**
		 * Gets the map value for `key`.
		 *
		 * @private
		 * @name get
		 * @memberOf MapCache
		 * @param {string} key The key of the value to get.
		 * @returns {*} Returns the entry value.
		 */
		function mapCacheGet(key) {
		  return getMapData(this, key).get(key);
		}

		/**
		 * Checks if a map value for `key` exists.
		 *
		 * @private
		 * @name has
		 * @memberOf MapCache
		 * @param {string} key The key of the entry to check.
		 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
		 */
		function mapCacheHas(key) {
		  return getMapData(this, key).has(key);
		}

		/**
		 * Sets the map `key` to `value`.
		 *
		 * @private
		 * @name set
		 * @memberOf MapCache
		 * @param {string} key The key of the value to set.
		 * @param {*} value The value to set.
		 * @returns {Object} Returns the map cache instance.
		 */
		function mapCacheSet(key, value) {
		  getMapData(this, key).set(key, value);
		  return this;
		}

		// Add methods to `MapCache`.
		MapCache.prototype.clear = mapCacheClear;
		MapCache.prototype['delete'] = mapCacheDelete;
		MapCache.prototype.get = mapCacheGet;
		MapCache.prototype.has = mapCacheHas;
		MapCache.prototype.set = mapCacheSet;

		/**
		 * Creates a stack cache object to store key-value pairs.
		 *
		 * @private
		 * @constructor
		 * @param {Array} [entries] The key-value pairs to cache.
		 */
		function Stack(entries) {
		  this.__data__ = new ListCache(entries);
		}

		/**
		 * Removes all key-value entries from the stack.
		 *
		 * @private
		 * @name clear
		 * @memberOf Stack
		 */
		function stackClear() {
		  this.__data__ = new ListCache;
		}

		/**
		 * Removes `key` and its value from the stack.
		 *
		 * @private
		 * @name delete
		 * @memberOf Stack
		 * @param {string} key The key of the value to remove.
		 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
		 */
		function stackDelete(key) {
		  return this.__data__['delete'](key);
		}

		/**
		 * Gets the stack value for `key`.
		 *
		 * @private
		 * @name get
		 * @memberOf Stack
		 * @param {string} key The key of the value to get.
		 * @returns {*} Returns the entry value.
		 */
		function stackGet(key) {
		  return this.__data__.get(key);
		}

		/**
		 * Checks if a stack value for `key` exists.
		 *
		 * @private
		 * @name has
		 * @memberOf Stack
		 * @param {string} key The key of the entry to check.
		 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
		 */
		function stackHas(key) {
		  return this.__data__.has(key);
		}

		/**
		 * Sets the stack `key` to `value`.
		 *
		 * @private
		 * @name set
		 * @memberOf Stack
		 * @param {string} key The key of the value to set.
		 * @param {*} value The value to set.
		 * @returns {Object} Returns the stack cache instance.
		 */
		function stackSet(key, value) {
		  var cache = this.__data__;
		  if (cache instanceof ListCache) {
		    var pairs = cache.__data__;
		    if (!Map || (pairs.length < LARGE_ARRAY_SIZE - 1)) {
		      pairs.push([key, value]);
		      return this;
		    }
		    cache = this.__data__ = new MapCache(pairs);
		  }
		  cache.set(key, value);
		  return this;
		}

		// Add methods to `Stack`.
		Stack.prototype.clear = stackClear;
		Stack.prototype['delete'] = stackDelete;
		Stack.prototype.get = stackGet;
		Stack.prototype.has = stackHas;
		Stack.prototype.set = stackSet;

		/**
		 * Creates an array of the enumerable property names of the array-like `value`.
		 *
		 * @private
		 * @param {*} value The value to query.
		 * @param {boolean} inherited Specify returning inherited property names.
		 * @returns {Array} Returns the array of property names.
		 */
		function arrayLikeKeys(value, inherited) {
		  // Safari 8.1 makes `arguments.callee` enumerable in strict mode.
		  // Safari 9 makes `arguments.length` enumerable in strict mode.
		  var result = (isArray(value) || isArguments(value))
		    ? baseTimes(value.length, String)
		    : [];

		  var length = result.length,
		      skipIndexes = !!length;

		  for (var key in value) {
		    if ((hasOwnProperty.call(value, key)) &&
		        !(skipIndexes && (key == 'length' || isIndex(key, length)))) {
		      result.push(key);
		    }
		  }
		  return result;
		}

		/**
		 * Assigns `value` to `key` of `object` if the existing value is not equivalent
		 * using [`SameValueZero`](http://ecma-international.org/ecma-262/7.0/#sec-samevaluezero)
		 * for equality comparisons.
		 *
		 * @private
		 * @param {Object} object The object to modify.
		 * @param {string} key The key of the property to assign.
		 * @param {*} value The value to assign.
		 */
		function assignValue(object, key, value) {
		  var objValue = object[key];
		  if (!(hasOwnProperty.call(object, key) && eq(objValue, value)) ||
		      (value === undefined && !(key in object))) {
		    object[key] = value;
		  }
		}

		/**
		 * Gets the index at which the `key` is found in `array` of key-value pairs.
		 *
		 * @private
		 * @param {Array} array The array to inspect.
		 * @param {*} key The key to search for.
		 * @returns {number} Returns the index of the matched value, else `-1`.
		 */
		function assocIndexOf(array, key) {
		  var length = array.length;
		  while (length--) {
		    if (eq(array[length][0], key)) {
		      return length;
		    }
		  }
		  return -1;
		}

		/**
		 * The base implementation of `_.assign` without support for multiple sources
		 * or `customizer` functions.
		 *
		 * @private
		 * @param {Object} object The destination object.
		 * @param {Object} source The source object.
		 * @returns {Object} Returns `object`.
		 */
		function baseAssign(object, source) {
		  return object && copyObject(source, keys(source), object);
		}

		/**
		 * The base implementation of `_.clone` and `_.cloneDeep` which tracks
		 * traversed objects.
		 *
		 * @private
		 * @param {*} value The value to clone.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @param {boolean} [isFull] Specify a clone including symbols.
		 * @param {Function} [customizer] The function to customize cloning.
		 * @param {string} [key] The key of `value`.
		 * @param {Object} [object] The parent object of `value`.
		 * @param {Object} [stack] Tracks traversed objects and their clone counterparts.
		 * @returns {*} Returns the cloned value.
		 */
		function baseClone(value, isDeep, isFull, customizer, key, object, stack) {
		  var result;
		  if (customizer) {
		    result = object ? customizer(value, key, object, stack) : customizer(value);
		  }
		  if (result !== undefined) {
		    return result;
		  }
		  if (!isObject(value)) {
		    return value;
		  }
		  var isArr = isArray(value);
		  if (isArr) {
		    result = initCloneArray(value);
		    if (!isDeep) {
		      return copyArray(value, result);
		    }
		  } else {
		    var tag = getTag(value),
		        isFunc = tag == funcTag || tag == genTag;

		    if (isBuffer(value)) {
		      return cloneBuffer(value, isDeep);
		    }
		    if (tag == objectTag || tag == argsTag || (isFunc && !object)) {
		      if (isHostObject(value)) {
		        return object ? value : {};
		      }
		      result = initCloneObject(isFunc ? {} : value);
		      if (!isDeep) {
		        return copySymbols(value, baseAssign(result, value));
		      }
		    } else {
		      if (!cloneableTags[tag]) {
		        return object ? value : {};
		      }
		      result = initCloneByTag(value, tag, baseClone, isDeep);
		    }
		  }
		  // Check for circular references and return its corresponding clone.
		  stack || (stack = new Stack);
		  var stacked = stack.get(value);
		  if (stacked) {
		    return stacked;
		  }
		  stack.set(value, result);

		  if (!isArr) {
		    var props = isFull ? getAllKeys(value) : keys(value);
		  }
		  arrayEach(props || value, function(subValue, key) {
		    if (props) {
		      key = subValue;
		      subValue = value[key];
		    }
		    // Recursively populate clone (susceptible to call stack limits).
		    assignValue(result, key, baseClone(subValue, isDeep, isFull, customizer, key, value, stack));
		  });
		  return result;
		}

		/**
		 * The base implementation of `_.create` without support for assigning
		 * properties to the created object.
		 *
		 * @private
		 * @param {Object} prototype The object to inherit from.
		 * @returns {Object} Returns the new object.
		 */
		function baseCreate(proto) {
		  return isObject(proto) ? objectCreate(proto) : {};
		}

		/**
		 * The base implementation of `getAllKeys` and `getAllKeysIn` which uses
		 * `keysFunc` and `symbolsFunc` to get the enumerable property names and
		 * symbols of `object`.
		 *
		 * @private
		 * @param {Object} object The object to query.
		 * @param {Function} keysFunc The function to get the keys of `object`.
		 * @param {Function} symbolsFunc The function to get the symbols of `object`.
		 * @returns {Array} Returns the array of property names and symbols.
		 */
		function baseGetAllKeys(object, keysFunc, symbolsFunc) {
		  var result = keysFunc(object);
		  return isArray(object) ? result : arrayPush(result, symbolsFunc(object));
		}

		/**
		 * The base implementation of `getTag`.
		 *
		 * @private
		 * @param {*} value The value to query.
		 * @returns {string} Returns the `toStringTag`.
		 */
		function baseGetTag(value) {
		  return objectToString.call(value);
		}

		/**
		 * The base implementation of `_.isNative` without bad shim checks.
		 *
		 * @private
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a native function,
		 *  else `false`.
		 */
		function baseIsNative(value) {
		  if (!isObject(value) || isMasked(value)) {
		    return false;
		  }
		  var pattern = (isFunction(value) || isHostObject(value)) ? reIsNative : reIsHostCtor;
		  return pattern.test(toSource(value));
		}

		/**
		 * The base implementation of `_.keys` which doesn't treat sparse arrays as dense.
		 *
		 * @private
		 * @param {Object} object The object to query.
		 * @returns {Array} Returns the array of property names.
		 */
		function baseKeys(object) {
		  if (!isPrototype(object)) {
		    return nativeKeys(object);
		  }
		  var result = [];
		  for (var key in Object(object)) {
		    if (hasOwnProperty.call(object, key) && key != 'constructor') {
		      result.push(key);
		    }
		  }
		  return result;
		}

		/**
		 * Creates a clone of  `buffer`.
		 *
		 * @private
		 * @param {Buffer} buffer The buffer to clone.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Buffer} Returns the cloned buffer.
		 */
		function cloneBuffer(buffer, isDeep) {
		  if (isDeep) {
		    return buffer.slice();
		  }
		  var result = new buffer.constructor(buffer.length);
		  buffer.copy(result);
		  return result;
		}

		/**
		 * Creates a clone of `arrayBuffer`.
		 *
		 * @private
		 * @param {ArrayBuffer} arrayBuffer The array buffer to clone.
		 * @returns {ArrayBuffer} Returns the cloned array buffer.
		 */
		function cloneArrayBuffer(arrayBuffer) {
		  var result = new arrayBuffer.constructor(arrayBuffer.byteLength);
		  new Uint8Array(result).set(new Uint8Array(arrayBuffer));
		  return result;
		}

		/**
		 * Creates a clone of `dataView`.
		 *
		 * @private
		 * @param {Object} dataView The data view to clone.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Object} Returns the cloned data view.
		 */
		function cloneDataView(dataView, isDeep) {
		  var buffer = isDeep ? cloneArrayBuffer(dataView.buffer) : dataView.buffer;
		  return new dataView.constructor(buffer, dataView.byteOffset, dataView.byteLength);
		}

		/**
		 * Creates a clone of `map`.
		 *
		 * @private
		 * @param {Object} map The map to clone.
		 * @param {Function} cloneFunc The function to clone values.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Object} Returns the cloned map.
		 */
		function cloneMap(map, isDeep, cloneFunc) {
		  var array = isDeep ? cloneFunc(mapToArray(map), true) : mapToArray(map);
		  return arrayReduce(array, addMapEntry, new map.constructor);
		}

		/**
		 * Creates a clone of `regexp`.
		 *
		 * @private
		 * @param {Object} regexp The regexp to clone.
		 * @returns {Object} Returns the cloned regexp.
		 */
		function cloneRegExp(regexp) {
		  var result = new regexp.constructor(regexp.source, reFlags.exec(regexp));
		  result.lastIndex = regexp.lastIndex;
		  return result;
		}

		/**
		 * Creates a clone of `set`.
		 *
		 * @private
		 * @param {Object} set The set to clone.
		 * @param {Function} cloneFunc The function to clone values.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Object} Returns the cloned set.
		 */
		function cloneSet(set, isDeep, cloneFunc) {
		  var array = isDeep ? cloneFunc(setToArray(set), true) : setToArray(set);
		  return arrayReduce(array, addSetEntry, new set.constructor);
		}

		/**
		 * Creates a clone of the `symbol` object.
		 *
		 * @private
		 * @param {Object} symbol The symbol object to clone.
		 * @returns {Object} Returns the cloned symbol object.
		 */
		function cloneSymbol(symbol) {
		  return symbolValueOf ? Object(symbolValueOf.call(symbol)) : {};
		}

		/**
		 * Creates a clone of `typedArray`.
		 *
		 * @private
		 * @param {Object} typedArray The typed array to clone.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Object} Returns the cloned typed array.
		 */
		function cloneTypedArray(typedArray, isDeep) {
		  var buffer = isDeep ? cloneArrayBuffer(typedArray.buffer) : typedArray.buffer;
		  return new typedArray.constructor(buffer, typedArray.byteOffset, typedArray.length);
		}

		/**
		 * Copies the values of `source` to `array`.
		 *
		 * @private
		 * @param {Array} source The array to copy values from.
		 * @param {Array} [array=[]] The array to copy values to.
		 * @returns {Array} Returns `array`.
		 */
		function copyArray(source, array) {
		  var index = -1,
		      length = source.length;

		  array || (array = Array(length));
		  while (++index < length) {
		    array[index] = source[index];
		  }
		  return array;
		}

		/**
		 * Copies properties of `source` to `object`.
		 *
		 * @private
		 * @param {Object} source The object to copy properties from.
		 * @param {Array} props The property identifiers to copy.
		 * @param {Object} [object={}] The object to copy properties to.
		 * @param {Function} [customizer] The function to customize copied values.
		 * @returns {Object} Returns `object`.
		 */
		function copyObject(source, props, object, customizer) {
		  object || (object = {});

		  var index = -1,
		      length = props.length;

		  while (++index < length) {
		    var key = props[index];

		    var newValue = undefined;

		    assignValue(object, key, newValue === undefined ? source[key] : newValue);
		  }
		  return object;
		}

		/**
		 * Copies own symbol properties of `source` to `object`.
		 *
		 * @private
		 * @param {Object} source The object to copy symbols from.
		 * @param {Object} [object={}] The object to copy symbols to.
		 * @returns {Object} Returns `object`.
		 */
		function copySymbols(source, object) {
		  return copyObject(source, getSymbols(source), object);
		}

		/**
		 * Creates an array of own enumerable property names and symbols of `object`.
		 *
		 * @private
		 * @param {Object} object The object to query.
		 * @returns {Array} Returns the array of property names and symbols.
		 */
		function getAllKeys(object) {
		  return baseGetAllKeys(object, keys, getSymbols);
		}

		/**
		 * Gets the data for `map`.
		 *
		 * @private
		 * @param {Object} map The map to query.
		 * @param {string} key The reference key.
		 * @returns {*} Returns the map data.
		 */
		function getMapData(map, key) {
		  var data = map.__data__;
		  return isKeyable(key)
		    ? data[typeof key == 'string' ? 'string' : 'hash']
		    : data.map;
		}

		/**
		 * Gets the native function at `key` of `object`.
		 *
		 * @private
		 * @param {Object} object The object to query.
		 * @param {string} key The key of the method to get.
		 * @returns {*} Returns the function if it's native, else `undefined`.
		 */
		function getNative(object, key) {
		  var value = getValue(object, key);
		  return baseIsNative(value) ? value : undefined;
		}

		/**
		 * Creates an array of the own enumerable symbol properties of `object`.
		 *
		 * @private
		 * @param {Object} object The object to query.
		 * @returns {Array} Returns the array of symbols.
		 */
		var getSymbols = nativeGetSymbols ? overArg(nativeGetSymbols, Object) : stubArray;

		/**
		 * Gets the `toStringTag` of `value`.
		 *
		 * @private
		 * @param {*} value The value to query.
		 * @returns {string} Returns the `toStringTag`.
		 */
		var getTag = baseGetTag;

		// Fallback for data views, maps, sets, and weak maps in IE 11,
		// for data views in Edge < 14, and promises in Node.js.
		if ((DataView && getTag(new DataView(new ArrayBuffer(1))) != dataViewTag) ||
		    (Map && getTag(new Map) != mapTag) ||
		    (Promise && getTag(Promise.resolve()) != promiseTag) ||
		    (Set && getTag(new Set) != setTag) ||
		    (WeakMap && getTag(new WeakMap) != weakMapTag)) {
		  getTag = function(value) {
		    var result = objectToString.call(value),
		        Ctor = result == objectTag ? value.constructor : undefined,
		        ctorString = Ctor ? toSource(Ctor) : undefined;

		    if (ctorString) {
		      switch (ctorString) {
		        case dataViewCtorString: return dataViewTag;
		        case mapCtorString: return mapTag;
		        case promiseCtorString: return promiseTag;
		        case setCtorString: return setTag;
		        case weakMapCtorString: return weakMapTag;
		      }
		    }
		    return result;
		  };
		}

		/**
		 * Initializes an array clone.
		 *
		 * @private
		 * @param {Array} array The array to clone.
		 * @returns {Array} Returns the initialized clone.
		 */
		function initCloneArray(array) {
		  var length = array.length,
		      result = array.constructor(length);

		  // Add properties assigned by `RegExp#exec`.
		  if (length && typeof array[0] == 'string' && hasOwnProperty.call(array, 'index')) {
		    result.index = array.index;
		    result.input = array.input;
		  }
		  return result;
		}

		/**
		 * Initializes an object clone.
		 *
		 * @private
		 * @param {Object} object The object to clone.
		 * @returns {Object} Returns the initialized clone.
		 */
		function initCloneObject(object) {
		  return (typeof object.constructor == 'function' && !isPrototype(object))
		    ? baseCreate(getPrototype(object))
		    : {};
		}

		/**
		 * Initializes an object clone based on its `toStringTag`.
		 *
		 * **Note:** This function only supports cloning values with tags of
		 * `Boolean`, `Date`, `Error`, `Number`, `RegExp`, or `String`.
		 *
		 * @private
		 * @param {Object} object The object to clone.
		 * @param {string} tag The `toStringTag` of the object to clone.
		 * @param {Function} cloneFunc The function to clone values.
		 * @param {boolean} [isDeep] Specify a deep clone.
		 * @returns {Object} Returns the initialized clone.
		 */
		function initCloneByTag(object, tag, cloneFunc, isDeep) {
		  var Ctor = object.constructor;
		  switch (tag) {
		    case arrayBufferTag:
		      return cloneArrayBuffer(object);

		    case boolTag:
		    case dateTag:
		      return new Ctor(+object);

		    case dataViewTag:
		      return cloneDataView(object, isDeep);

		    case float32Tag: case float64Tag:
		    case int8Tag: case int16Tag: case int32Tag:
		    case uint8Tag: case uint8ClampedTag: case uint16Tag: case uint32Tag:
		      return cloneTypedArray(object, isDeep);

		    case mapTag:
		      return cloneMap(object, isDeep, cloneFunc);

		    case numberTag:
		    case stringTag:
		      return new Ctor(object);

		    case regexpTag:
		      return cloneRegExp(object);

		    case setTag:
		      return cloneSet(object, isDeep, cloneFunc);

		    case symbolTag:
		      return cloneSymbol(object);
		  }
		}

		/**
		 * Checks if `value` is a valid array-like index.
		 *
		 * @private
		 * @param {*} value The value to check.
		 * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
		 * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
		 */
		function isIndex(value, length) {
		  length = length == null ? MAX_SAFE_INTEGER : length;
		  return !!length &&
		    (typeof value == 'number' || reIsUint.test(value)) &&
		    (value > -1 && value % 1 == 0 && value < length);
		}

		/**
		 * Checks if `value` is suitable for use as unique object key.
		 *
		 * @private
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is suitable, else `false`.
		 */
		function isKeyable(value) {
		  var type = typeof value;
		  return (type == 'string' || type == 'number' || type == 'symbol' || type == 'boolean')
		    ? (value !== '__proto__')
		    : (value === null);
		}

		/**
		 * Checks if `func` has its source masked.
		 *
		 * @private
		 * @param {Function} func The function to check.
		 * @returns {boolean} Returns `true` if `func` is masked, else `false`.
		 */
		function isMasked(func) {
		  return !!maskSrcKey && (maskSrcKey in func);
		}

		/**
		 * Checks if `value` is likely a prototype object.
		 *
		 * @private
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a prototype, else `false`.
		 */
		function isPrototype(value) {
		  var Ctor = value && value.constructor,
		      proto = (typeof Ctor == 'function' && Ctor.prototype) || objectProto;

		  return value === proto;
		}

		/**
		 * Converts `func` to its source code.
		 *
		 * @private
		 * @param {Function} func The function to process.
		 * @returns {string} Returns the source code.
		 */
		function toSource(func) {
		  if (func != null) {
		    try {
		      return funcToString.call(func);
		    } catch (e) {}
		    try {
		      return (func + '');
		    } catch (e) {}
		  }
		  return '';
		}

		/**
		 * This method is like `_.clone` except that it recursively clones `value`.
		 *
		 * @static
		 * @memberOf _
		 * @since 1.0.0
		 * @category Lang
		 * @param {*} value The value to recursively clone.
		 * @returns {*} Returns the deep cloned value.
		 * @see _.clone
		 * @example
		 *
		 * var objects = [{ 'a': 1 }, { 'b': 2 }];
		 *
		 * var deep = _.cloneDeep(objects);
		 * console.log(deep[0] === objects[0]);
		 * // => false
		 */
		function cloneDeep(value) {
		  return baseClone(value, true, true);
		}

		/**
		 * Performs a
		 * [`SameValueZero`](http://ecma-international.org/ecma-262/7.0/#sec-samevaluezero)
		 * comparison between two values to determine if they are equivalent.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.0.0
		 * @category Lang
		 * @param {*} value The value to compare.
		 * @param {*} other The other value to compare.
		 * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
		 * @example
		 *
		 * var object = { 'a': 1 };
		 * var other = { 'a': 1 };
		 *
		 * _.eq(object, object);
		 * // => true
		 *
		 * _.eq(object, other);
		 * // => false
		 *
		 * _.eq('a', 'a');
		 * // => true
		 *
		 * _.eq('a', Object('a'));
		 * // => false
		 *
		 * _.eq(NaN, NaN);
		 * // => true
		 */
		function eq(value, other) {
		  return value === other || (value !== value && other !== other);
		}

		/**
		 * Checks if `value` is likely an `arguments` object.
		 *
		 * @static
		 * @memberOf _
		 * @since 0.1.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is an `arguments` object,
		 *  else `false`.
		 * @example
		 *
		 * _.isArguments(function() { return arguments; }());
		 * // => true
		 *
		 * _.isArguments([1, 2, 3]);
		 * // => false
		 */
		function isArguments(value) {
		  // Safari 8.1 makes `arguments.callee` enumerable in strict mode.
		  return isArrayLikeObject(value) && hasOwnProperty.call(value, 'callee') &&
		    (!propertyIsEnumerable.call(value, 'callee') || objectToString.call(value) == argsTag);
		}

		/**
		 * Checks if `value` is classified as an `Array` object.
		 *
		 * @static
		 * @memberOf _
		 * @since 0.1.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is an array, else `false`.
		 * @example
		 *
		 * _.isArray([1, 2, 3]);
		 * // => true
		 *
		 * _.isArray(document.body.children);
		 * // => false
		 *
		 * _.isArray('abc');
		 * // => false
		 *
		 * _.isArray(_.noop);
		 * // => false
		 */
		var isArray = Array.isArray;

		/**
		 * Checks if `value` is array-like. A value is considered array-like if it's
		 * not a function and has a `value.length` that's an integer greater than or
		 * equal to `0` and less than or equal to `Number.MAX_SAFE_INTEGER`.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.0.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
		 * @example
		 *
		 * _.isArrayLike([1, 2, 3]);
		 * // => true
		 *
		 * _.isArrayLike(document.body.children);
		 * // => true
		 *
		 * _.isArrayLike('abc');
		 * // => true
		 *
		 * _.isArrayLike(_.noop);
		 * // => false
		 */
		function isArrayLike(value) {
		  return value != null && isLength(value.length) && !isFunction(value);
		}

		/**
		 * This method is like `_.isArrayLike` except that it also checks if `value`
		 * is an object.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.0.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is an array-like object,
		 *  else `false`.
		 * @example
		 *
		 * _.isArrayLikeObject([1, 2, 3]);
		 * // => true
		 *
		 * _.isArrayLikeObject(document.body.children);
		 * // => true
		 *
		 * _.isArrayLikeObject('abc');
		 * // => false
		 *
		 * _.isArrayLikeObject(_.noop);
		 * // => false
		 */
		function isArrayLikeObject(value) {
		  return isObjectLike(value) && isArrayLike(value);
		}

		/**
		 * Checks if `value` is a buffer.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.3.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a buffer, else `false`.
		 * @example
		 *
		 * _.isBuffer(new Buffer(2));
		 * // => true
		 *
		 * _.isBuffer(new Uint8Array(2));
		 * // => false
		 */
		var isBuffer = nativeIsBuffer || stubFalse;

		/**
		 * Checks if `value` is classified as a `Function` object.
		 *
		 * @static
		 * @memberOf _
		 * @since 0.1.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a function, else `false`.
		 * @example
		 *
		 * _.isFunction(_);
		 * // => true
		 *
		 * _.isFunction(/abc/);
		 * // => false
		 */
		function isFunction(value) {
		  // The use of `Object#toString` avoids issues with the `typeof` operator
		  // in Safari 8-9 which returns 'object' for typed array and other constructors.
		  var tag = isObject(value) ? objectToString.call(value) : '';
		  return tag == funcTag || tag == genTag;
		}

		/**
		 * Checks if `value` is a valid array-like length.
		 *
		 * **Note:** This method is loosely based on
		 * [`ToLength`](http://ecma-international.org/ecma-262/7.0/#sec-tolength).
		 *
		 * @static
		 * @memberOf _
		 * @since 4.0.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
		 * @example
		 *
		 * _.isLength(3);
		 * // => true
		 *
		 * _.isLength(Number.MIN_VALUE);
		 * // => false
		 *
		 * _.isLength(Infinity);
		 * // => false
		 *
		 * _.isLength('3');
		 * // => false
		 */
		function isLength(value) {
		  return typeof value == 'number' &&
		    value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
		}

		/**
		 * Checks if `value` is the
		 * [language type](http://www.ecma-international.org/ecma-262/7.0/#sec-ecmascript-language-types)
		 * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
		 *
		 * @static
		 * @memberOf _
		 * @since 0.1.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
		 * @example
		 *
		 * _.isObject({});
		 * // => true
		 *
		 * _.isObject([1, 2, 3]);
		 * // => true
		 *
		 * _.isObject(_.noop);
		 * // => true
		 *
		 * _.isObject(null);
		 * // => false
		 */
		function isObject(value) {
		  var type = typeof value;
		  return !!value && (type == 'object' || type == 'function');
		}

		/**
		 * Checks if `value` is object-like. A value is object-like if it's not `null`
		 * and has a `typeof` result of "object".
		 *
		 * @static
		 * @memberOf _
		 * @since 4.0.0
		 * @category Lang
		 * @param {*} value The value to check.
		 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
		 * @example
		 *
		 * _.isObjectLike({});
		 * // => true
		 *
		 * _.isObjectLike([1, 2, 3]);
		 * // => true
		 *
		 * _.isObjectLike(_.noop);
		 * // => false
		 *
		 * _.isObjectLike(null);
		 * // => false
		 */
		function isObjectLike(value) {
		  return !!value && typeof value == 'object';
		}

		/**
		 * Creates an array of the own enumerable property names of `object`.
		 *
		 * **Note:** Non-object values are coerced to objects. See the
		 * [ES spec](http://ecma-international.org/ecma-262/7.0/#sec-object.keys)
		 * for more details.
		 *
		 * @static
		 * @since 0.1.0
		 * @memberOf _
		 * @category Object
		 * @param {Object} object The object to query.
		 * @returns {Array} Returns the array of property names.
		 * @example
		 *
		 * function Foo() {
		 *   this.a = 1;
		 *   this.b = 2;
		 * }
		 *
		 * Foo.prototype.c = 3;
		 *
		 * _.keys(new Foo);
		 * // => ['a', 'b'] (iteration order is not guaranteed)
		 *
		 * _.keys('hi');
		 * // => ['0', '1']
		 */
		function keys(object) {
		  return isArrayLike(object) ? arrayLikeKeys(object) : baseKeys(object);
		}

		/**
		 * This method returns a new empty array.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.13.0
		 * @category Util
		 * @returns {Array} Returns the new empty array.
		 * @example
		 *
		 * var arrays = _.times(2, _.stubArray);
		 *
		 * console.log(arrays);
		 * // => [[], []]
		 *
		 * console.log(arrays[0] === arrays[1]);
		 * // => false
		 */
		function stubArray() {
		  return [];
		}

		/**
		 * This method returns `false`.
		 *
		 * @static
		 * @memberOf _
		 * @since 4.13.0
		 * @category Util
		 * @returns {boolean} Returns `false`.
		 * @example
		 *
		 * _.times(2, _.stubFalse);
		 * // => [false, false]
		 */
		function stubFalse() {
		  return false;
		}

		module.exports = cloneDeep; 
	} (lodash_clonedeep, lodash_clonedeep.exports));
	return lodash_clonedeep.exports;
}

var lodash_clonedeepExports = requireLodash_clonedeep();
var lodashCloneDeep = /*@__PURE__*/getDefaultExportFromCjs(lodash_clonedeepExports);

var ClarityType$1;
(function (ClarityType) {
    ClarityType["Int"] = "int";
    ClarityType["UInt"] = "uint";
    ClarityType["Buffer"] = "buffer";
    ClarityType["BoolTrue"] = "true";
    ClarityType["BoolFalse"] = "false";
    ClarityType["PrincipalStandard"] = "address";
    ClarityType["PrincipalContract"] = "contract";
    ClarityType["ResponseOk"] = "ok";
    ClarityType["ResponseErr"] = "err";
    ClarityType["OptionalNone"] = "none";
    ClarityType["OptionalSome"] = "some";
    ClarityType["List"] = "list";
    ClarityType["Tuple"] = "tuple";
    ClarityType["StringASCII"] = "ascii";
    ClarityType["StringUTF8"] = "utf8";
})(ClarityType$1 || (ClarityType$1 = {}));
var ClarityWireType;
(function (ClarityWireType) {
    ClarityWireType[ClarityWireType["int"] = 0] = "int";
    ClarityWireType[ClarityWireType["uint"] = 1] = "uint";
    ClarityWireType[ClarityWireType["buffer"] = 2] = "buffer";
    ClarityWireType[ClarityWireType["true"] = 3] = "true";
    ClarityWireType[ClarityWireType["false"] = 4] = "false";
    ClarityWireType[ClarityWireType["address"] = 5] = "address";
    ClarityWireType[ClarityWireType["contract"] = 6] = "contract";
    ClarityWireType[ClarityWireType["ok"] = 7] = "ok";
    ClarityWireType[ClarityWireType["err"] = 8] = "err";
    ClarityWireType[ClarityWireType["none"] = 9] = "none";
    ClarityWireType[ClarityWireType["some"] = 10] = "some";
    ClarityWireType[ClarityWireType["list"] = 11] = "list";
    ClarityWireType[ClarityWireType["tuple"] = 12] = "tuple";
    ClarityWireType[ClarityWireType["ascii"] = 13] = "ascii";
    ClarityWireType[ClarityWireType["utf8"] = 14] = "utf8";
})(ClarityWireType || (ClarityWireType = {}));
function clarityTypeToByte(type) {
    return ClarityWireType[type];
}

const trueCV = () => ({ type: ClarityType$1.BoolTrue });
const falseCV = () => ({ type: ClarityType$1.BoolFalse });
const boolCV = (bool) => (bool ? trueCV() : falseCV());

const bufferCV = (buffer) => {
    if (buffer.byteLength > 1048576) {
        throw new Error('Cannot construct clarity buffer that is greater than 1MB');
    }
    return { type: ClarityType$1.Buffer, value: bytesToHex$2(buffer) };
};

const MAX_U128 = BigInt('0xffffffffffffffffffffffffffffffff');
const MIN_U128 = BigInt(0);
const MAX_I128 = BigInt('0x7fffffffffffffffffffffffffffffff');
const MIN_I128 = BigInt('-170141183460469231731687303715884105728');
const intCV = (value) => {
    if (typeof value === 'string' && value.toLowerCase().startsWith('0x')) {
        value = bytesToTwosBigInt(hexToBytes$2(value));
    }
    if (isInstance(value, Uint8Array))
        value = bytesToTwosBigInt(value);
    const bigInt = intToBigInt$1(value);
    if (bigInt > MAX_I128) {
        throw new RangeError(`Cannot construct clarity integer from value greater than ${MAX_I128}`);
    }
    else if (bigInt < MIN_I128) {
        throw new RangeError(`Cannot construct clarity integer form value less than ${MIN_I128}`);
    }
    return { type: ClarityType$1.Int, value: bigInt };
};
const uintCV = (value) => {
    const bigInt = intToBigInt$1(value);
    if (bigInt < MIN_U128) {
        throw new RangeError('Cannot construct unsigned clarity integer from negative value');
    }
    else if (bigInt > MAX_U128) {
        throw new RangeError(`Cannot construct unsigned clarity integer greater than ${MAX_U128}`);
    }
    return { type: ClarityType$1.UInt, value: bigInt };
};

function listCV(values) {
    return { type: ClarityType$1.List, value: values };
}

function noneCV() {
    return { type: ClarityType$1.OptionalNone };
}
function someCV(value) {
    return { type: ClarityType$1.OptionalSome, value };
}

var StacksWireType;
(function (StacksWireType) {
    StacksWireType[StacksWireType["Address"] = 0] = "Address";
    StacksWireType[StacksWireType["Principal"] = 1] = "Principal";
    StacksWireType[StacksWireType["LengthPrefixedString"] = 2] = "LengthPrefixedString";
    StacksWireType[StacksWireType["MemoString"] = 3] = "MemoString";
    StacksWireType[StacksWireType["Asset"] = 4] = "Asset";
    StacksWireType[StacksWireType["PostCondition"] = 5] = "PostCondition";
    StacksWireType[StacksWireType["PublicKey"] = 6] = "PublicKey";
    StacksWireType[StacksWireType["LengthPrefixedList"] = 7] = "LengthPrefixedList";
    StacksWireType[StacksWireType["Payload"] = 8] = "Payload";
    StacksWireType[StacksWireType["MessageSignature"] = 9] = "MessageSignature";
    StacksWireType[StacksWireType["StructuredDataSignature"] = 10] = "StructuredDataSignature";
    StacksWireType[StacksWireType["TransactionAuthField"] = 11] = "TransactionAuthField";
})(StacksWireType || (StacksWireType = {}));

function createEmptyAddress() {
    return {
        type: StacksWireType.Address,
        version: AddressVersion$1.MainnetSingleSig,
        hash160: '0'.repeat(40),
    };
}
function createMemoString(content) {
    if (content && exceedsMaxLengthBytes$1(content, MEMO_MAX_LENGTH_BYTES)) {
        throw new Error(`Memo exceeds maximum length of ${MEMO_MAX_LENGTH_BYTES} bytes`);
    }
    return { type: StacksWireType.MemoString, content };
}
function createLPList(values, lengthPrefixBytes) {
    return {
        type: StacksWireType.LengthPrefixedList,
        lengthPrefixBytes: lengthPrefixBytes || 4,
        values,
    };
}
function createMessageSignature(signature) {
    const length = hexToBytes$2(signature).byteLength;
    if (length != RECOVERABLE_ECDSA_SIG_LENGTH_BYTES) {
        throw Error('Invalid signature');
    }
    return {
        type: StacksWireType.MessageSignature,
        data: signature,
    };
}
function createTokenTransferPayload(recipient, amount, memo) {
    if (typeof recipient === 'string') {
        recipient = principalCV(recipient);
    }
    if (typeof memo === 'string') {
        memo = createMemoString(memo);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.TokenTransfer,
        recipient,
        amount: intToBigInt$1(amount),
        memo: memo ?? createMemoString(''),
    };
}
function createContractCallPayload(contractAddress, contractName, functionName, functionArgs) {
    if (typeof contractName === 'string') {
        contractName = createLPString$1(contractName);
    }
    if (typeof functionName === 'string') {
        functionName = createLPString$1(functionName);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.ContractCall,
        contractAddress: typeof contractAddress === 'string' ? createAddress(contractAddress) : contractAddress,
        contractName,
        functionName,
        functionArgs,
    };
}
function codeBodyString(content) {
    return createLPString$1(content, 4, 100000);
}
function createSmartContractPayload(contractName, codeBody, clarityVersion) {
    if (typeof contractName === 'string') {
        contractName = createLPString$1(contractName);
    }
    if (typeof codeBody === 'string') {
        codeBody = codeBodyString(codeBody);
    }
    if (typeof clarityVersion === 'number') {
        return {
            type: StacksWireType.Payload,
            payloadType: PayloadType$1.VersionedSmartContract,
            clarityVersion,
            contractName,
            codeBody,
        };
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.SmartContract,
        contractName,
        codeBody,
    };
}
function createPoisonPayload() {
    return { type: StacksWireType.Payload, payloadType: PayloadType$1.PoisonMicroblock };
}
function createCoinbasePayload(coinbaseBytes, altRecipient) {
    if (coinbaseBytes.byteLength != COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${COINBASE_BYTES_LENGTH} bytes`);
    }
    if (altRecipient != undefined) {
        return {
            type: StacksWireType.Payload,
            payloadType: PayloadType$1.CoinbaseToAltRecipient,
            coinbaseBytes,
            recipient: altRecipient,
        };
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.Coinbase,
        coinbaseBytes,
    };
}
function createNakamotoCoinbasePayload(coinbaseBytes, recipient, vrfProof) {
    if (coinbaseBytes.byteLength != COINBASE_BYTES_LENGTH) {
        throw Error(`Coinbase buffer size must be ${COINBASE_BYTES_LENGTH} bytes`);
    }
    if (vrfProof.byteLength != VRF_PROOF_BYTES_LENGTH) {
        throw Error(`VRF proof buffer size must be ${VRF_PROOF_BYTES_LENGTH} bytes`);
    }
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.NakamotoCoinbase,
        coinbaseBytes,
        recipient: recipient.type === ClarityType$1.OptionalSome ? recipient.value : undefined,
        vrfProof,
    };
}
function createTenureChangePayload(tenureHash, previousTenureHash, burnViewHash, previousTenureEnd, previousTenureBlocks, cause, publicKeyHash) {
    return {
        type: StacksWireType.Payload,
        payloadType: PayloadType$1.TenureChange,
        tenureHash,
        previousTenureHash,
        burnViewHash,
        previousTenureEnd,
        previousTenureBlocks,
        cause,
        publicKeyHash,
    };
}
function createLPString$1(content, lengthPrefixBytes, maxLengthBytes) {
    const prefixLength = lengthPrefixBytes || 1;
    const maxLength = maxLengthBytes || MAX_STRING_LENGTH_BYTES$1;
    if (exceedsMaxLengthBytes$1(content, maxLength)) {
        throw new Error(`String length exceeds maximum bytes ${maxLength}`);
    }
    return {
        type: StacksWireType.LengthPrefixedString,
        content,
        lengthPrefixBytes: prefixLength,
        maxLengthBytes: maxLength,
    };
}
function createAsset(addressString, contractName, assetName) {
    return {
        type: StacksWireType.Asset,
        address: createAddress(addressString),
        contractName: createLPString$1(contractName),
        assetName: createLPString$1(assetName),
    };
}
function createAddress(c32AddressString) {
    const addressData = libExports.c32addressDecode(c32AddressString);
    return {
        type: StacksWireType.Address,
        version: addressData[0],
        hash160: addressData[1],
    };
}
function createContractPrincipal(addressString, contractName) {
    const addr = createAddress(addressString);
    const name = createLPString$1(contractName);
    return {
        type: StacksWireType.Principal,
        prefix: PostConditionPrincipalId.Contract,
        address: addr,
        contractName: name,
    };
}
function createStandardPrincipal(addressString) {
    const addr = createAddress(addressString);
    return {
        type: StacksWireType.Principal,
        prefix: PostConditionPrincipalId.Standard,
        address: addr,
    };
}
function createTransactionAuthField(pubKeyEncoding, contents) {
    return {
        pubKeyEncoding,
        type: StacksWireType.TransactionAuthField,
        contents,
    };
}

function serializeStacksWireBytes(wire) {
    switch (wire.type) {
        case StacksWireType.Address:
            return serializeAddressBytes(wire);
        case StacksWireType.Principal:
            return serializePrincipalBytes(wire);
        case StacksWireType.LengthPrefixedString:
            return serializeLPStringBytes(wire);
        case StacksWireType.MemoString:
            return serializeMemoStringBytes(wire);
        case StacksWireType.Asset:
            return serializeAssetBytes(wire);
        case StacksWireType.PostCondition:
            return serializePostConditionWireBytes(wire);
        case StacksWireType.PublicKey:
            return serializePublicKeyBytes(wire);
        case StacksWireType.LengthPrefixedList:
            return serializeLPListBytes(wire);
        case StacksWireType.Payload:
            return serializePayloadBytes(wire);
        case StacksWireType.TransactionAuthField:
            return serializeTransactionAuthFieldBytes(wire);
        case StacksWireType.MessageSignature:
            return serializeMessageSignatureBytes(wire);
    }
}
function serializeAddressBytes(address) {
    const bytesArray = [];
    bytesArray.push(hexToBytes$2(intToHex$1(address.version, 1)));
    bytesArray.push(hexToBytes$2(address.hash160));
    return concatArray$1(bytesArray);
}
function deserializeAddress(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const version = hexToInt(bytesToHex$2(bytesReader.readBytes(1)));
    const data = bytesToHex$2(bytesReader.readBytes(20));
    return { type: StacksWireType.Address, version, hash160: data };
}
function serializePrincipalBytes(principal) {
    const bytesArray = [];
    bytesArray.push(principal.prefix);
    if (principal.prefix === PostConditionPrincipalId.Standard ||
        principal.prefix === PostConditionPrincipalId.Contract) {
        bytesArray.push(serializeAddressBytes(principal.address));
    }
    if (principal.prefix === PostConditionPrincipalId.Contract) {
        bytesArray.push(serializeLPStringBytes(principal.contractName));
    }
    return concatArray$1(bytesArray);
}
function deserializePrincipal(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const prefix = bytesReader.readUInt8Enum(PostConditionPrincipalId, n => {
        throw new DeserializationError(`Unexpected Principal payload type: ${n}`);
    });
    if (prefix === PostConditionPrincipalId.Origin) {
        return { type: StacksWireType.Principal, prefix };
    }
    const address = deserializeAddress(bytesReader);
    if (prefix === PostConditionPrincipalId.Standard) {
        return { type: StacksWireType.Principal, prefix, address };
    }
    const contractName = deserializeLPString(bytesReader);
    return {
        type: StacksWireType.Principal,
        prefix,
        address,
        contractName,
    };
}
function serializeLPStringBytes(lps) {
    const bytesArray = [];
    const contentBytes = utf8ToBytes$2(lps.content);
    const length = contentBytes.byteLength;
    bytesArray.push(hexToBytes$2(intToHex$1(length, lps.lengthPrefixBytes)));
    bytesArray.push(contentBytes);
    return concatArray$1(bytesArray);
}
function deserializeLPString(serialized, prefixBytes, maxLength) {
    prefixBytes = prefixBytes ? prefixBytes : 1;
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const length = hexToInt(bytesToHex$2(bytesReader.readBytes(prefixBytes)));
    const content = bytesToUtf8(bytesReader.readBytes(length));
    return createLPString$1(content, prefixBytes, maxLength ?? 128);
}
function serializeMemoStringBytes(memoString) {
    const bytesArray = [];
    const contentBytes = utf8ToBytes$2(memoString.content);
    const paddedContent = rightPadHexToLength(bytesToHex$2(contentBytes), MEMO_MAX_LENGTH_BYTES * 2);
    bytesArray.push(hexToBytes$2(paddedContent));
    return concatArray$1(bytesArray);
}
function deserializeMemoString(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    let content = bytesToUtf8(bytesReader.readBytes(MEMO_MAX_LENGTH_BYTES));
    content = content.replace(/\u0000*$/, '');
    return { type: StacksWireType.MemoString, content };
}
function serializeAssetBytes(info) {
    const bytesArray = [];
    bytesArray.push(serializeAddressBytes(info.address));
    bytesArray.push(serializeLPStringBytes(info.contractName));
    bytesArray.push(serializeLPStringBytes(info.assetName));
    return concatArray$1(bytesArray);
}
function deserializeAsset(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    return {
        type: StacksWireType.Asset,
        address: deserializeAddress(bytesReader),
        contractName: deserializeLPString(bytesReader),
        assetName: deserializeLPString(bytesReader),
    };
}
function serializeLPListBytes(lpList) {
    const list = lpList.values;
    const bytesArray = [];
    bytesArray.push(hexToBytes$2(intToHex$1(list.length, lpList.lengthPrefixBytes)));
    for (const l of list) {
        bytesArray.push(serializeStacksWireBytes(l));
    }
    return concatArray$1(bytesArray);
}
function deserializeLPList(serialized, type, lengthPrefixBytes) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const length = hexToInt(bytesToHex$2(bytesReader.readBytes(4)));
    const l = [];
    for (let index = 0; index < length; index++) {
        switch (type) {
            case StacksWireType.Address:
                l.push(deserializeAddress(bytesReader));
                break;
            case StacksWireType.LengthPrefixedString:
                l.push(deserializeLPString(bytesReader));
                break;
            case StacksWireType.MemoString:
                l.push(deserializeMemoString(bytesReader));
                break;
            case StacksWireType.Asset:
                l.push(deserializeAsset(bytesReader));
                break;
            case StacksWireType.PostCondition:
                l.push(deserializePostConditionWire(bytesReader));
                break;
            case StacksWireType.PublicKey:
                l.push(deserializePublicKey(bytesReader));
                break;
            case StacksWireType.TransactionAuthField:
                l.push(deserializeTransactionAuthField(bytesReader));
                break;
        }
    }
    return createLPList(l, lengthPrefixBytes);
}
function serializePostConditionWire(postCondition) {
    return bytesToHex$2(serializePostConditionWireBytes(postCondition));
}
function serializePostConditionWireBytes(postCondition) {
    const bytesArray = [];
    bytesArray.push(postCondition.conditionType);
    bytesArray.push(serializePrincipalBytes(postCondition.principal));
    if (postCondition.conditionType === PostConditionType$1.Fungible ||
        postCondition.conditionType === PostConditionType$1.NonFungible) {
        bytesArray.push(serializeAssetBytes(postCondition.asset));
    }
    if (postCondition.conditionType === PostConditionType$1.NonFungible) {
        bytesArray.push(serializeCVBytes(postCondition.assetName));
    }
    bytesArray.push(postCondition.conditionCode);
    if (postCondition.conditionType === PostConditionType$1.STX ||
        postCondition.conditionType === PostConditionType$1.Fungible) {
        if (postCondition.amount > BigInt('0xffffffffffffffff'))
            throw new SerializationError$1('The post-condition amount may not be larger than 8 bytes');
        bytesArray.push(intToBytes$1(postCondition.amount, 8));
    }
    return concatArray$1(bytesArray);
}
function deserializePostConditionWire(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const postConditionType = bytesReader.readUInt8Enum(PostConditionType$1, n => {
        throw new DeserializationError(`Could not read ${n} as PostConditionType`);
    });
    const principal = deserializePrincipal(bytesReader);
    let conditionCode;
    let asset;
    let amount;
    switch (postConditionType) {
        case PostConditionType$1.STX:
            conditionCode = bytesReader.readUInt8Enum(FungibleConditionCode$1, n => {
                throw new DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            amount = BigInt(`0x${bytesToHex$2(bytesReader.readBytes(8))}`);
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.STX,
                principal,
                conditionCode,
                amount,
            };
        case PostConditionType$1.Fungible:
            asset = deserializeAsset(bytesReader);
            conditionCode = bytesReader.readUInt8Enum(FungibleConditionCode$1, n => {
                throw new DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            amount = BigInt(`0x${bytesToHex$2(bytesReader.readBytes(8))}`);
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.Fungible,
                principal,
                conditionCode,
                amount,
                asset: asset,
            };
        case PostConditionType$1.NonFungible:
            asset = deserializeAsset(bytesReader);
            const assetName = deserializeCV(bytesReader);
            conditionCode = bytesReader.readUInt8Enum(NonFungibleConditionCode$1, n => {
                throw new DeserializationError(`Could not read ${n} as FungibleConditionCode`);
            });
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.NonFungible,
                principal,
                conditionCode,
                asset,
                assetName,
            };
    }
}
function serializePayloadBytes(payload) {
    const bytesArray = [];
    bytesArray.push(payload.payloadType);
    switch (payload.payloadType) {
        case PayloadType$1.TokenTransfer:
            bytesArray.push(serializeCVBytes(payload.recipient));
            bytesArray.push(intToBytes$1(payload.amount, 8));
            bytesArray.push(serializeStacksWireBytes(payload.memo));
            break;
        case PayloadType$1.ContractCall:
            bytesArray.push(serializeStacksWireBytes(payload.contractAddress));
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.functionName));
            const numArgs = new Uint8Array(4);
            writeUInt32BE$1(numArgs, payload.functionArgs.length, 0);
            bytesArray.push(numArgs);
            payload.functionArgs.forEach(arg => {
                bytesArray.push(serializeCVBytes(arg));
            });
            break;
        case PayloadType$1.SmartContract:
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.codeBody));
            break;
        case PayloadType$1.VersionedSmartContract:
            bytesArray.push(payload.clarityVersion);
            bytesArray.push(serializeStacksWireBytes(payload.contractName));
            bytesArray.push(serializeStacksWireBytes(payload.codeBody));
            break;
        case PayloadType$1.PoisonMicroblock:
            break;
        case PayloadType$1.Coinbase:
            bytesArray.push(payload.coinbaseBytes);
            break;
        case PayloadType$1.CoinbaseToAltRecipient:
            bytesArray.push(payload.coinbaseBytes);
            bytesArray.push(serializeCVBytes(payload.recipient));
            break;
        case PayloadType$1.NakamotoCoinbase:
            bytesArray.push(payload.coinbaseBytes);
            bytesArray.push(serializeCVBytes(payload.recipient ? someCV(payload.recipient) : noneCV()));
            bytesArray.push(payload.vrfProof);
            break;
        case PayloadType$1.TenureChange:
            bytesArray.push(hexToBytes$2(payload.tenureHash));
            bytesArray.push(hexToBytes$2(payload.previousTenureHash));
            bytesArray.push(hexToBytes$2(payload.burnViewHash));
            bytesArray.push(hexToBytes$2(payload.previousTenureEnd));
            bytesArray.push(writeUInt32BE$1(new Uint8Array(4), payload.previousTenureBlocks));
            bytesArray.push(writeUInt8(new Uint8Array(1), payload.cause));
            bytesArray.push(hexToBytes$2(payload.publicKeyHash));
            break;
    }
    return concatArray$1(bytesArray);
}
function deserializePayload(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const payloadType = bytesReader.readUInt8Enum(PayloadType$1, n => {
        throw new Error(`Cannot recognize PayloadType: ${n}`);
    });
    switch (payloadType) {
        case PayloadType$1.TokenTransfer:
            const recipient = deserializeCV(bytesReader);
            const amount = intToBigInt$1(bytesReader.readBytes(8));
            const memo = deserializeMemoString(bytesReader);
            return createTokenTransferPayload(recipient, amount, memo);
        case PayloadType$1.ContractCall:
            const contractAddress = deserializeAddress(bytesReader);
            const contractCallName = deserializeLPString(bytesReader);
            const functionName = deserializeLPString(bytesReader);
            const functionArgs = [];
            const numberOfArgs = bytesReader.readUInt32BE();
            for (let i = 0; i < numberOfArgs; i++) {
                const clarityValue = deserializeCV(bytesReader);
                functionArgs.push(clarityValue);
            }
            return createContractCallPayload(contractAddress, contractCallName, functionName, functionArgs);
        case PayloadType$1.SmartContract:
            const smartContractName = deserializeLPString(bytesReader);
            const codeBody = deserializeLPString(bytesReader, 4, 100000);
            return createSmartContractPayload(smartContractName, codeBody);
        case PayloadType$1.VersionedSmartContract: {
            const clarityVersion = bytesReader.readUInt8Enum(ClarityVersion$1, n => {
                throw new Error(`Cannot recognize ClarityVersion: ${n}`);
            });
            const smartContractName = deserializeLPString(bytesReader);
            const codeBody = deserializeLPString(bytesReader, 4, STRING_MAX_LENGTH);
            return createSmartContractPayload(smartContractName, codeBody, clarityVersion);
        }
        case PayloadType$1.PoisonMicroblock:
            return createPoisonPayload();
        case PayloadType$1.Coinbase: {
            const coinbaseBytes = bytesReader.readBytes(COINBASE_BYTES_LENGTH);
            return createCoinbasePayload(coinbaseBytes);
        }
        case PayloadType$1.CoinbaseToAltRecipient: {
            const coinbaseBytes = bytesReader.readBytes(COINBASE_BYTES_LENGTH);
            const altRecipient = deserializeCV(bytesReader);
            return createCoinbasePayload(coinbaseBytes, altRecipient);
        }
        case PayloadType$1.NakamotoCoinbase: {
            const coinbaseBytes = bytesReader.readBytes(COINBASE_BYTES_LENGTH);
            const recipient = deserializeCV(bytesReader);
            const vrfProof = bytesReader.readBytes(VRF_PROOF_BYTES_LENGTH);
            return createNakamotoCoinbasePayload(coinbaseBytes, recipient, vrfProof);
        }
        case PayloadType$1.TenureChange:
            const tenureHash = bytesToHex$2(bytesReader.readBytes(20));
            const previousTenureHash = bytesToHex$2(bytesReader.readBytes(20));
            const burnViewHash = bytesToHex$2(bytesReader.readBytes(20));
            const previousTenureEnd = bytesToHex$2(bytesReader.readBytes(32));
            const previousTenureBlocks = bytesReader.readUInt32BE();
            const cause = bytesReader.readUInt8Enum(TenureChangeCause, n => {
                throw new Error(`Cannot recognize TenureChangeCause: ${n}`);
            });
            const publicKeyHash = bytesToHex$2(bytesReader.readBytes(20));
            return createTenureChangePayload(tenureHash, previousTenureHash, burnViewHash, previousTenureEnd, previousTenureBlocks, cause, publicKeyHash);
    }
}
function deserializeMessageSignature(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    return createMessageSignature(bytesToHex$2(bytesReader.readBytes(RECOVERABLE_ECDSA_SIG_LENGTH_BYTES)));
}
function deserializeTransactionAuthField(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const authFieldType = bytesReader.readUInt8Enum(AuthFieldType, n => {
        throw new DeserializationError(`Could not read ${n} as AuthFieldType`);
    });
    switch (authFieldType) {
        case AuthFieldType.PublicKeyCompressed:
            return createTransactionAuthField(PubKeyEncoding$1.Compressed, deserializePublicKey(bytesReader));
        case AuthFieldType.PublicKeyUncompressed:
            return createTransactionAuthField(PubKeyEncoding$1.Uncompressed, createStacksPublicKey(uncompressPublicKey(deserializePublicKey(bytesReader).data)));
        case AuthFieldType.SignatureCompressed:
            return createTransactionAuthField(PubKeyEncoding$1.Compressed, deserializeMessageSignature(bytesReader));
        case AuthFieldType.SignatureUncompressed:
            return createTransactionAuthField(PubKeyEncoding$1.Uncompressed, deserializeMessageSignature(bytesReader));
        default:
            throw new Error(`Unknown auth field type: ${JSON.stringify(authFieldType)}`);
    }
}
function serializeMessageSignatureBytes(messageSignature) {
    return hexToBytes$2(messageSignature.data);
}
function serializeTransactionAuthFieldBytes(field) {
    const bytesArray = [];
    switch (field.contents.type) {
        case StacksWireType.PublicKey:
            bytesArray.push(field.pubKeyEncoding === PubKeyEncoding$1.Compressed
                ? AuthFieldType.PublicKeyCompressed
                : AuthFieldType.PublicKeyUncompressed);
            bytesArray.push(hexToBytes$2(compressPublicKey(field.contents.data)));
            break;
        case StacksWireType.MessageSignature:
            bytesArray.push(field.pubKeyEncoding === PubKeyEncoding$1.Compressed
                ? AuthFieldType.SignatureCompressed
                : AuthFieldType.SignatureUncompressed);
            bytesArray.push(serializeMessageSignatureBytes(field.contents));
            break;
    }
    return concatArray$1(bytesArray);
}
function serializePublicKeyBytes(key) {
    return key.data.slice();
}
function deserializePublicKey(serialized) {
    const bytesReader = isInstance(serialized, BytesReader)
        ? serialized
        : new BytesReader(serialized);
    const fieldId = bytesReader.readUInt8();
    const keyLength = fieldId === 4 ? UNCOMPRESSED_PUBKEY_LENGTH_BYTES : COMPRESSED_PUBKEY_LENGTH_BYTES;
    return createStacksPublicKey(concatArray$1([fieldId, bytesReader.readBytes(keyLength)]));
}

function addressFromPublicKeys(version, hashMode, numSigs, publicKeys) {
    if (publicKeys.length === 0) {
        throw Error('Invalid number of public keys');
    }
    if (hashMode === AddressHashMode$1.P2PKH || hashMode === AddressHashMode$1.P2WPKH) {
        if (publicKeys.length !== 1 || numSigs !== 1) {
            throw Error('Invalid number of public keys or signatures');
        }
    }
    if (hashMode === AddressHashMode$1.P2WPKH ||
        hashMode === AddressHashMode$1.P2WSH ||
        hashMode === AddressHashMode$1.P2WSHNonSequential) {
        if (!publicKeys.map(p => p.data).every(publicKeyIsCompressed)) {
            throw Error('Public keys must be compressed for segwit');
        }
    }
    switch (hashMode) {
        case AddressHashMode$1.P2PKH:
            return addressFromVersionHash(version, hashP2PKH(publicKeys[0].data));
        case AddressHashMode$1.P2WPKH:
            return addressFromVersionHash(version, hashP2WPKH(publicKeys[0].data));
        case AddressHashMode$1.P2SH:
        case AddressHashMode$1.P2SHNonSequential:
            return addressFromVersionHash(version, hashP2SH(numSigs, publicKeys.map(serializePublicKeyBytes)));
        case AddressHashMode$1.P2WSH:
        case AddressHashMode$1.P2WSHNonSequential:
            return addressFromVersionHash(version, hashP2WSH(numSigs, publicKeys.map(serializePublicKeyBytes)));
    }
}
function addressFromVersionHash(version, hash) {
    return { type: StacksWireType.Address, version, hash160: hash };
}
function addressToString(address) {
    return libExports.c32address(address.version, address.hash160);
}
function parseAssetString(id) {
    const [assetAddress, assetContractName, assetTokenName] = id.split(/\.|::/);
    const asset = createAsset(assetAddress, assetContractName, assetTokenName);
    return asset;
}
function parsePrincipalString(principalString) {
    if (principalString.includes('.')) {
        const [address, contractName] = principalString.split('.');
        return createContractPrincipal(address, contractName);
    }
    else {
        return createStandardPrincipal(principalString);
    }
}

function principalCV(principal) {
    if (principal.includes('.')) {
        const [address, contractName] = principal.split('.');
        return contractPrincipalCV(address, contractName);
    }
    else {
        return standardPrincipalCV(principal);
    }
}
function standardPrincipalCV(addressString) {
    const addr = createAddress(addressString);
    return { type: ClarityType$1.PrincipalStandard, value: addressToString(addr) };
}
function standardPrincipalCVFromAddress(address) {
    return { type: ClarityType$1.PrincipalStandard, value: addressToString(address) };
}
function contractPrincipalCV(addressString, contractName) {
    const addr = createAddress(addressString);
    const lengthPrefixedContractName = createLPString$1(contractName);
    return contractPrincipalCVFromAddress(addr, lengthPrefixedContractName);
}
function contractPrincipalCVFromAddress(address, contractName) {
    if (utf8ToBytes$2(contractName.content).byteLength >= 128) {
        throw new Error('Contract name must be less than 128 bytes');
    }
    return {
        type: ClarityType$1.PrincipalContract,
        value: `${addressToString(address)}.${contractName.content}`,
    };
}

function responseErrorCV(value) {
    return { type: ClarityType$1.ResponseErr, value };
}
function responseOkCV(value) {
    return { type: ClarityType$1.ResponseOk, value };
}

const stringAsciiCV = (data) => {
    return { type: ClarityType$1.StringASCII, value: data };
};
const stringUtf8CV = (data) => {
    return { type: ClarityType$1.StringUTF8, value: data };
};

function tupleCV(data) {
    for (const key in data) {
        if (!isClarityName(key)) {
            throw new Error(`"${key}" is not a valid Clarity name`);
        }
    }
    return { type: ClarityType$1.Tuple, value: data };
}

function deserializeCV(serializedClarityValue) {
    let bytesReader;
    if (typeof serializedClarityValue === 'string') {
        const hasHexPrefix = serializedClarityValue.slice(0, 2).toLowerCase() === '0x';
        bytesReader = new BytesReader(hexToBytes$2(hasHexPrefix ? serializedClarityValue.slice(2) : serializedClarityValue));
    }
    else if (serializedClarityValue instanceof Uint8Array) {
        bytesReader = new BytesReader(serializedClarityValue);
    }
    else {
        bytesReader = serializedClarityValue;
    }
    const type = bytesReader.readUInt8Enum(ClarityWireType, n => {
        throw new DeserializationError(`Cannot recognize Clarity Type: ${n}`);
    });
    switch (type) {
        case ClarityWireType.int:
            return intCV(bytesToTwosBigInt(bytesReader.readBytes(16)));
        case ClarityWireType.uint:
            return uintCV(bytesReader.readBytes(16));
        case ClarityWireType.buffer:
            const bufferLength = bytesReader.readUInt32BE();
            return bufferCV(bytesReader.readBytes(bufferLength));
        case ClarityWireType.true:
            return trueCV();
        case ClarityWireType.false:
            return falseCV();
        case ClarityWireType.address:
            const sAddress = deserializeAddress(bytesReader);
            return standardPrincipalCVFromAddress(sAddress);
        case ClarityWireType.contract:
            const cAddress = deserializeAddress(bytesReader);
            const contractName = deserializeLPString(bytesReader);
            return contractPrincipalCVFromAddress(cAddress, contractName);
        case ClarityWireType.ok:
            return responseOkCV(deserializeCV(bytesReader));
        case ClarityWireType.err:
            return responseErrorCV(deserializeCV(bytesReader));
        case ClarityWireType.none:
            return noneCV();
        case ClarityWireType.some:
            return someCV(deserializeCV(bytesReader));
        case ClarityWireType.list:
            const listLength = bytesReader.readUInt32BE();
            const listContents = [];
            for (let i = 0; i < listLength; i++) {
                listContents.push(deserializeCV(bytesReader));
            }
            return listCV(listContents);
        case ClarityWireType.tuple:
            const tupleLength = bytesReader.readUInt32BE();
            const tupleContents = {};
            for (let i = 0; i < tupleLength; i++) {
                const clarityName = deserializeLPString(bytesReader).content;
                if (clarityName === undefined) {
                    throw new DeserializationError('"content" is undefined');
                }
                tupleContents[clarityName] = deserializeCV(bytesReader);
            }
            return tupleCV(tupleContents);
        case ClarityWireType.ascii:
            const asciiStrLen = bytesReader.readUInt32BE();
            const asciiStr = bytesToAscii(bytesReader.readBytes(asciiStrLen));
            return stringAsciiCV(asciiStr);
        case ClarityWireType.utf8:
            const utf8StrLen = bytesReader.readUInt32BE();
            const utf8Str = bytesToUtf8(bytesReader.readBytes(utf8StrLen));
            return stringUtf8CV(utf8Str);
        default:
            throw new DeserializationError('Unable to deserialize Clarity Value from Uint8Array. Could not find valid Clarity Type.');
    }
}

function bytesWithTypeID$1(typeId, bytes) {
    return concatArray$1([clarityTypeToByte(typeId), bytes]);
}
function serializeBoolCV$1(value) {
    return new Uint8Array([clarityTypeToByte(value.type)]);
}
function serializeOptionalCV$1(cv) {
    if (cv.type === ClarityType$1.OptionalNone) {
        return new Uint8Array([clarityTypeToByte(cv.type)]);
    }
    else {
        return bytesWithTypeID$1(cv.type, serializeCVBytes(cv.value));
    }
}
function serializeBufferCV$1(cv) {
    const length = new Uint8Array(4);
    writeUInt32BE$1(length, Math.ceil(cv.value.length / 2), 0);
    return bytesWithTypeID$1(cv.type, concatBytes$2(length, hexToBytes$2(cv.value)));
}
function serializeIntCV$1(cv) {
    const bytes = bigIntToBytes$1(toTwos$1(BigInt(cv.value), BigInt(CLARITY_INT_SIZE$1)), CLARITY_INT_BYTE_SIZE$1);
    return bytesWithTypeID$1(cv.type, bytes);
}
function serializeUIntCV$1(cv) {
    const bytes = bigIntToBytes$1(BigInt(cv.value), CLARITY_INT_BYTE_SIZE$1);
    return bytesWithTypeID$1(cv.type, bytes);
}
function serializeStandardPrincipalCV$1(cv) {
    return bytesWithTypeID$1(cv.type, serializeAddressBytes(createAddress(cv.value)));
}
function serializeContractPrincipalCV$1(cv) {
    const [address, name] = parseContractId(cv.value);
    return bytesWithTypeID$1(cv.type, concatBytes$2(serializeAddressBytes(createAddress(address)), serializeLPStringBytes(createLPString$1(name))));
}
function serializeResponseCV$1(cv) {
    return bytesWithTypeID$1(cv.type, serializeCVBytes(cv.value));
}
function serializeListCV$1(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    writeUInt32BE$1(length, cv.value.length, 0);
    bytesArray.push(length);
    for (const value of cv.value) {
        const serializedValue = serializeCVBytes(value);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID$1(cv.type, concatArray$1(bytesArray));
}
function serializeTupleCV$1(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    writeUInt32BE$1(length, Object.keys(cv.value).length, 0);
    bytesArray.push(length);
    const lexicographicOrder = Object.keys(cv.value).sort((a, b) => a.localeCompare(b));
    for (const key of lexicographicOrder) {
        const nameWithLength = createLPString$1(key);
        bytesArray.push(serializeLPStringBytes(nameWithLength));
        const serializedValue = serializeCVBytes(cv.value[key]);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID$1(cv.type, concatArray$1(bytesArray));
}
function serializeStringCV$1(cv, encoding) {
    const bytesArray = [];
    const str = encoding == 'ascii' ? asciiToBytes$1(cv.value) : utf8ToBytes$2(cv.value);
    const len = new Uint8Array(4);
    writeUInt32BE$1(len, str.length, 0);
    bytesArray.push(len);
    bytesArray.push(str);
    return bytesWithTypeID$1(cv.type, concatArray$1(bytesArray));
}
function serializeStringAsciiCV$1(cv) {
    return serializeStringCV$1(cv, 'ascii');
}
function serializeStringUtf8CV$1(cv) {
    return serializeStringCV$1(cv, 'utf8');
}
function serializeCV$1(value) {
    return bytesToHex$2(serializeCVBytes(value));
}
function serializeCVBytes(value) {
    switch (value.type) {
        case ClarityType$1.BoolTrue:
        case ClarityType$1.BoolFalse:
            return serializeBoolCV$1(value);
        case ClarityType$1.OptionalNone:
        case ClarityType$1.OptionalSome:
            return serializeOptionalCV$1(value);
        case ClarityType$1.Buffer:
            return serializeBufferCV$1(value);
        case ClarityType$1.UInt:
            return serializeUIntCV$1(value);
        case ClarityType$1.Int:
            return serializeIntCV$1(value);
        case ClarityType$1.PrincipalStandard:
            return serializeStandardPrincipalCV$1(value);
        case ClarityType$1.PrincipalContract:
            return serializeContractPrincipalCV$1(value);
        case ClarityType$1.ResponseOk:
        case ClarityType$1.ResponseErr:
            return serializeResponseCV$1(value);
        case ClarityType$1.List:
            return serializeListCV$1(value);
        case ClarityType$1.Tuple:
            return serializeTupleCV$1(value);
        case ClarityType$1.StringASCII:
            return serializeStringAsciiCV$1(value);
        case ClarityType$1.StringUTF8:
            return serializeStringUtf8CV$1(value);
        default:
            throw new SerializationError$1('Unable to serialize. Invalid Clarity Value.');
    }
}

const leftPadHex = (hexString) => hexString.length % 2 ? `0${hexString}` : hexString;
const rightPadHexToLength = (hexString, length) => hexString.padEnd(length, '0');
const exceedsMaxLengthBytes$1 = (string, maxLengthBytes) => string ? utf8ToBytes$2(string).length > maxLengthBytes : false;
function cloneDeep(obj) {
    return lodashCloneDeep(obj);
}
const hash160 = (input) => {
    return ripemd160(sha256$1(input));
};
const txidFromData = (data) => {
    return bytesToHex$2(sha512_256(data));
};
const hashP2PKH = (input) => {
    return bytesToHex$2(hash160(input));
};
const hashP2WPKH = (input) => {
    const keyHash = hash160(input);
    const redeemScript = concatBytes$2(new Uint8Array([0]), new Uint8Array([keyHash.length]), keyHash);
    const redeemScriptHash = hash160(redeemScript);
    return bytesToHex$2(redeemScriptHash);
};
const hashP2SH = (numSigs, pubKeys) => {
    if (numSigs > 15 || pubKeys.length > 15) {
        throw Error('P2SH multisig address can only contain up to 15 public keys');
    }
    const bytesArray = [];
    bytesArray.push(80 + numSigs);
    pubKeys.forEach(pubKey => {
        bytesArray.push(pubKey.length);
        bytesArray.push(pubKey);
    });
    bytesArray.push(80 + pubKeys.length);
    bytesArray.push(174);
    const redeemScript = concatArray$1(bytesArray);
    const redeemScriptHash = hash160(redeemScript);
    return bytesToHex$2(redeemScriptHash);
};
const hashP2WSH = (numSigs, pubKeys) => {
    if (numSigs > 15 || pubKeys.length > 15) {
        throw Error('P2WSH multisig address can only contain up to 15 public keys');
    }
    const scriptArray = [];
    scriptArray.push(80 + numSigs);
    pubKeys.forEach(pubKey => {
        scriptArray.push(pubKey.length);
        scriptArray.push(pubKey);
    });
    scriptArray.push(80 + pubKeys.length);
    scriptArray.push(174);
    const script = concatArray$1(scriptArray);
    const digest = sha256$1(script);
    const bytesArray = [];
    bytesArray.push(0);
    bytesArray.push(digest.length);
    bytesArray.push(digest);
    const redeemScript = concatArray$1(bytesArray);
    const redeemScriptHash = hash160(redeemScript);
    return bytesToHex$2(redeemScriptHash);
};
function isClarityName(name) {
    const regex = /^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$/;
    return regex.test(name) && name.length < 128;
}
function parseContractId(contractId) {
    const [address, name] = contractId.split('.');
    if (!address || !name)
        throw new Error(`Invalid contract identifier: ${contractId}`);
    return [address, name];
}

utils$1.hmacSha256Sync = (key, ...msgs) => {
    const h = hmac.create(sha256$1, key);
    msgs.forEach(msg => h.update(msg));
    return h.digest();
};
function createStacksPublicKey(publicKey) {
    publicKey = typeof publicKey === 'string' ? hexToBytes$2(publicKey) : publicKey;
    return {
        type: StacksWireType.PublicKey,
        data: publicKey,
    };
}
function publicKeyFromSignatureVrs(messageHash, messageSignature, pubKeyEncoding = PubKeyEncoding$1.Compressed) {
    const parsedSignature = parseRecoverableSignatureVrs(messageSignature);
    const signature = new Signature(hexToBigInt(parsedSignature.r), hexToBigInt(parsedSignature.s));
    const point = Point.fromSignature(messageHash, signature, parsedSignature.recoveryId);
    const compressed = pubKeyEncoding === PubKeyEncoding$1.Compressed;
    return point.toHex(compressed);
}
function privateKeyToHex(publicKey) {
    return typeof publicKey === 'string' ? publicKey : bytesToHex$2(publicKey);
}
const publicKeyToHex = privateKeyToHex;
function privateKeyIsCompressed(privateKey) {
    const length = typeof privateKey === 'string' ? privateKey.length / 2 : privateKey.byteLength;
    return length === PRIVATE_KEY_BYTES_COMPRESSED;
}
function publicKeyIsCompressed(publicKey) {
    return !publicKeyToHex(publicKey).startsWith('04');
}
function privateKeyToPublic(privateKey) {
    privateKey = privateKeyToBytes(privateKey);
    const isCompressed = privateKeyIsCompressed(privateKey);
    return bytesToHex$2(getPublicKey(privateKey.slice(0, 32), isCompressed));
}
function compressPublicKey(publicKey) {
    return Point.fromHex(publicKeyToHex(publicKey)).toHex(true);
}
function uncompressPublicKey(publicKey) {
    return Point.fromHex(publicKeyToHex(publicKey)).toHex(false);
}
function signWithKey(privateKey, messageHash) {
    privateKey = privateKeyToBytes(privateKey);
    const [rawSignature, recoveryId] = signSync(messageHash, privateKey.slice(0, 32), {
        canonical: true,
        recovered: true,
    });
    if (recoveryId == null) {
        throw new Error('No signature recoveryId received');
    }
    const recoveryIdHex = intToHex$1(recoveryId, 1);
    return recoveryIdHex + Signature.fromHex(rawSignature).toCompactHex();
}

function emptyMessageSignature() {
    return {
        type: StacksWireType.MessageSignature,
        data: bytesToHex$2(new Uint8Array(RECOVERABLE_ECDSA_SIG_LENGTH_BYTES)),
    };
}
function createSingleSigSpendingCondition(hashMode, pubKey, nonce, fee) {
    const signer = addressFromPublicKeys(0, hashMode, 1, [createStacksPublicKey(pubKey)]).hash160;
    const keyEncoding = publicKeyIsCompressed(pubKey)
        ? PubKeyEncoding$1.Compressed
        : PubKeyEncoding$1.Uncompressed;
    return {
        hashMode,
        signer,
        nonce: intToBigInt$1(nonce),
        fee: intToBigInt$1(fee),
        keyEncoding,
        signature: emptyMessageSignature(),
    };
}
function isSingleSig(condition) {
    return 'signature' in condition;
}
function isSequentialMultiSig(hashMode) {
    return hashMode === AddressHashMode$1.P2SH || hashMode === AddressHashMode$1.P2WSH;
}
function isNonSequentialMultiSig(hashMode) {
    return (hashMode === AddressHashMode$1.P2SHNonSequential ||
        hashMode === AddressHashMode$1.P2WSHNonSequential);
}
function clearCondition(condition) {
    const cloned = cloneDeep(condition);
    cloned.nonce = 0;
    cloned.fee = 0;
    if (isSingleSig(cloned)) {
        cloned.signature = emptyMessageSignature();
    }
    else {
        cloned.fields = [];
    }
    return {
        ...cloned,
        nonce: BigInt(0),
        fee: BigInt(0),
    };
}
function serializeSingleSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        hexToBytes$2(condition.signer),
        intToBytes$1(condition.nonce, 8),
        intToBytes$1(condition.fee, 8),
        condition.keyEncoding,
        serializeMessageSignatureBytes(condition.signature),
    ];
    return concatArray$1(bytesArray);
}
function serializeMultiSigSpendingConditionBytes(condition) {
    const bytesArray = [
        condition.hashMode,
        hexToBytes$2(condition.signer),
        intToBytes$1(condition.nonce, 8),
        intToBytes$1(condition.fee, 8),
    ];
    const fields = createLPList(condition.fields);
    bytesArray.push(serializeLPListBytes(fields));
    const numSigs = new Uint8Array(2);
    writeUInt16BE(numSigs, condition.signaturesRequired, 0);
    bytesArray.push(numSigs);
    return concatArray$1(bytesArray);
}
function deserializeSingleSigSpendingCondition(hashMode, bytesReader) {
    const signer = bytesToHex$2(bytesReader.readBytes(20));
    const nonce = BigInt(`0x${bytesToHex$2(bytesReader.readBytes(8))}`);
    const fee = BigInt(`0x${bytesToHex$2(bytesReader.readBytes(8))}`);
    const keyEncoding = bytesReader.readUInt8Enum(PubKeyEncoding$1, n => {
        throw new DeserializationError(`Could not parse ${n} as PubKeyEncoding`);
    });
    if (hashMode === AddressHashMode$1.P2WPKH && keyEncoding != PubKeyEncoding$1.Compressed) {
        throw new DeserializationError('Failed to parse singlesig spending condition: incomaptible hash mode and key encoding');
    }
    const signature = deserializeMessageSignature(bytesReader);
    return {
        hashMode,
        signer,
        nonce,
        fee,
        keyEncoding,
        signature,
    };
}
function deserializeMultiSigSpendingCondition(hashMode, bytesReader) {
    const signer = bytesToHex$2(bytesReader.readBytes(20));
    const nonce = BigInt('0x' + bytesToHex$2(bytesReader.readBytes(8)));
    const fee = BigInt('0x' + bytesToHex$2(bytesReader.readBytes(8)));
    const fields = deserializeLPList(bytesReader, StacksWireType.TransactionAuthField)
        .values;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of fields) {
        switch (field.contents.type) {
            case StacksWireType.PublicKey:
                if (!publicKeyIsCompressed(field.contents.data))
                    haveUncompressed = true;
                break;
            case StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === PubKeyEncoding$1.Uncompressed)
                    haveUncompressed = true;
                numSigs += 1;
                if (numSigs === 65536)
                    throw new VerificationError('Failed to parse multisig spending condition: too many signatures');
                break;
        }
    }
    const signaturesRequired = bytesReader.readUInt16BE();
    if (haveUncompressed &&
        (hashMode === AddressHashMode$1.P2WSH || hashMode === AddressHashMode$1.P2WSHNonSequential)) {
        throw new VerificationError('Uncompressed keys are not allowed in this hash mode');
    }
    return {
        hashMode,
        signer,
        nonce,
        fee,
        fields,
        signaturesRequired,
    };
}
function serializeSpendingConditionBytes(condition) {
    if (isSingleSig(condition))
        return serializeSingleSigSpendingConditionBytes(condition);
    return serializeMultiSigSpendingConditionBytes(condition);
}
function deserializeSpendingCondition(bytesReader) {
    const hashMode = bytesReader.readUInt8Enum(AddressHashMode$1, n => {
        throw new DeserializationError(`Could not parse ${n} as AddressHashMode`);
    });
    if (hashMode === AddressHashMode$1.P2PKH || hashMode === AddressHashMode$1.P2WPKH) {
        return deserializeSingleSigSpendingCondition(hashMode, bytesReader);
    }
    else {
        return deserializeMultiSigSpendingCondition(hashMode, bytesReader);
    }
}
function sigHashPreSign(curSigHash, authType, fee, nonce) {
    const hashLength = 32 + 1 + 8 + 8;
    const sigHash = curSigHash +
        bytesToHex$2(new Uint8Array([authType])) +
        bytesToHex$2(intToBytes$1(fee, 8)) +
        bytesToHex$2(intToBytes$1(nonce, 8));
    if (hexToBytes$2(sigHash).byteLength !== hashLength) {
        throw Error('Invalid signature hash length');
    }
    return txidFromData(hexToBytes$2(sigHash));
}
function sigHashPostSign(curSigHash, pubKey, signature) {
    const hashLength = 32 + 1 + RECOVERABLE_ECDSA_SIG_LENGTH_BYTES;
    const pubKeyEncoding = publicKeyIsCompressed(pubKey.data)
        ? PubKeyEncoding$1.Compressed
        : PubKeyEncoding$1.Uncompressed;
    const sigHash = curSigHash + leftPadHex(pubKeyEncoding.toString(16)) + signature;
    const sigHashBytes = hexToBytes$2(sigHash);
    if (sigHashBytes.byteLength > hashLength) {
        throw Error('Invalid signature hash length');
    }
    return txidFromData(sigHashBytes);
}
function nextSignature(curSigHash, authType, fee, nonce, privateKey) {
    const sigHashPre = sigHashPreSign(curSigHash, authType, fee, nonce);
    const signature = signWithKey(privateKey, sigHashPre);
    const publicKey = createStacksPublicKey(privateKeyToPublic(privateKey));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        nextSig: signature,
        nextSigHash,
    };
}
function nextVerification(initialSigHash, authType, fee, nonce, pubKeyEncoding, signature) {
    const sigHashPre = sigHashPreSign(initialSigHash, authType, fee, nonce);
    const publicKey = createStacksPublicKey(publicKeyFromSignatureVrs(sigHashPre, signature, pubKeyEncoding));
    const nextSigHash = sigHashPostSign(sigHashPre, publicKey, signature);
    return {
        pubKey: publicKey,
        nextSigHash,
    };
}
function newInitialSigHash() {
    const spendingCondition = createSingleSigSpendingCondition(AddressHashMode$1.P2PKH, '', 0, 0);
    spendingCondition.signer = createEmptyAddress().hash160;
    spendingCondition.keyEncoding = PubKeyEncoding$1.Compressed;
    spendingCondition.signature = emptyMessageSignature();
    return spendingCondition;
}
function verify(condition, initialSigHash, authType) {
    if (isSingleSig(condition)) {
        return verifySingleSig(condition, initialSigHash, authType);
    }
    else {
        return verifyMultiSig(condition, initialSigHash, authType);
    }
}
function verifySingleSig(condition, initialSigHash, authType) {
    const { pubKey, nextSigHash } = nextVerification(initialSigHash, authType, condition.fee, condition.nonce, condition.keyEncoding, condition.signature.data);
    const addrBytes = addressFromPublicKeys(0, condition.hashMode, 1, [pubKey]).hash160;
    if (addrBytes !== condition.signer)
        throw new VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return nextSigHash;
}
function verifyMultiSig(condition, initialSigHash, authType) {
    const publicKeys = [];
    let curSigHash = initialSigHash;
    let haveUncompressed = false;
    let numSigs = 0;
    for (const field of condition.fields) {
        switch (field.contents.type) {
            case StacksWireType.PublicKey:
                if (!publicKeyIsCompressed(field.contents.data))
                    haveUncompressed = true;
                publicKeys.push(field.contents);
                break;
            case StacksWireType.MessageSignature:
                if (field.pubKeyEncoding === PubKeyEncoding$1.Uncompressed)
                    haveUncompressed = true;
                const { pubKey, nextSigHash } = nextVerification(curSigHash, authType, condition.fee, condition.nonce, field.pubKeyEncoding, field.contents.data);
                if (isSequentialMultiSig(condition.hashMode)) {
                    curSigHash = nextSigHash;
                }
                publicKeys.push(pubKey);
                numSigs += 1;
                if (numSigs === 65536)
                    throw new VerificationError('Too many signatures');
                break;
        }
    }
    if ((isSequentialMultiSig(condition.hashMode) && numSigs !== condition.signaturesRequired) ||
        (isNonSequentialMultiSig(condition.hashMode) && numSigs < condition.signaturesRequired))
        throw new VerificationError('Incorrect number of signatures');
    if (haveUncompressed &&
        (condition.hashMode === AddressHashMode$1.P2WSH ||
            condition.hashMode === AddressHashMode$1.P2WSHNonSequential))
        throw new VerificationError('Uncompressed keys are not allowed in this hash mode');
    const addrBytes = addressFromPublicKeys(0, condition.hashMode, condition.signaturesRequired, publicKeys).hash160;
    if (addrBytes !== condition.signer)
        throw new VerificationError(`Signer hash does not equal hash of public key(s): ${addrBytes} != ${condition.signer}`);
    return curSigHash;
}
function createStandardAuth(spendingCondition) {
    return {
        authType: AuthType$1.Standard,
        spendingCondition,
    };
}
function createSponsoredAuth(spendingCondition, sponsorSpendingCondition) {
    return {
        authType: AuthType$1.Sponsored,
        spendingCondition,
        sponsorSpendingCondition: sponsorSpendingCondition
            ? sponsorSpendingCondition
            : createSingleSigSpendingCondition(AddressHashMode$1.P2PKH, '0'.repeat(66), 0, 0),
    };
}
function intoInitialSighashAuth(auth) {
    if (auth.spendingCondition) {
        switch (auth.authType) {
            case AuthType$1.Standard:
                return createStandardAuth(clearCondition(auth.spendingCondition));
            case AuthType$1.Sponsored:
                return createSponsoredAuth(clearCondition(auth.spendingCondition), newInitialSigHash());
            default:
                throw new SigningError('Unexpected authorization type for signing');
        }
    }
    throw new Error('Authorization missing SpendingCondition');
}
function verifyOrigin(auth, initialSigHash) {
    switch (auth.authType) {
        case AuthType$1.Standard:
            return verify(auth.spendingCondition, initialSigHash, AuthType$1.Standard);
        case AuthType$1.Sponsored:
            return verify(auth.spendingCondition, initialSigHash, AuthType$1.Standard);
        default:
            throw new SigningError('Invalid origin auth type');
    }
}
function setFee(auth, amount) {
    switch (auth.authType) {
        case AuthType$1.Standard:
            const spendingCondition = {
                ...auth.spendingCondition,
                fee: intToBigInt$1(amount),
            };
            return { ...auth, spendingCondition };
        case AuthType$1.Sponsored:
            const sponsorSpendingCondition = {
                ...auth.sponsorSpendingCondition,
                fee: intToBigInt$1(amount),
            };
            return { ...auth, sponsorSpendingCondition };
    }
}
function setNonce(auth, nonce) {
    const spendingCondition = {
        ...auth.spendingCondition,
        nonce: intToBigInt$1(nonce),
    };
    return {
        ...auth,
        spendingCondition,
    };
}
function setSponsorNonce(auth, nonce) {
    const sponsorSpendingCondition = {
        ...auth.sponsorSpendingCondition,
        nonce: intToBigInt$1(nonce),
    };
    return {
        ...auth,
        sponsorSpendingCondition,
    };
}
function setSponsor(auth, sponsorSpendingCondition) {
    const sc = {
        ...sponsorSpendingCondition,
        nonce: intToBigInt$1(sponsorSpendingCondition.nonce),
        fee: intToBigInt$1(sponsorSpendingCondition.fee),
    };
    return {
        ...auth,
        sponsorSpendingCondition: sc,
    };
}
function serializeAuthorizationBytes(auth) {
    const bytesArray = [];
    bytesArray.push(auth.authType);
    switch (auth.authType) {
        case AuthType$1.Standard:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            break;
        case AuthType$1.Sponsored:
            bytesArray.push(serializeSpendingConditionBytes(auth.spendingCondition));
            bytesArray.push(serializeSpendingConditionBytes(auth.sponsorSpendingCondition));
            break;
    }
    return concatArray$1(bytesArray);
}
function deserializeAuthorization(bytesReader) {
    const authType = bytesReader.readUInt8Enum(AuthType$1, n => {
        throw new DeserializationError(`Could not parse ${n} as AuthType`);
    });
    let spendingCondition;
    switch (authType) {
        case AuthType$1.Standard:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            return createStandardAuth(spendingCondition);
        case AuthType$1.Sponsored:
            spendingCondition = deserializeSpendingCondition(bytesReader);
            const sponsorSpendingCondition = deserializeSpendingCondition(bytesReader);
            return createSponsoredAuth(spendingCondition, sponsorSpendingCondition);
    }
}

class StacksTransactionWire {
    constructor({ auth, payload, postConditions = createLPList([]), postConditionMode = PostConditionMode$1.Deny, transactionVersion, chainId, network = 'mainnet', }) {
        network = networkFrom(network);
        this.transactionVersion = transactionVersion ?? network.transactionVersion;
        this.chainId = chainId ?? network.chainId;
        this.auth = auth;
        if ('amount' in payload) {
            this.payload = {
                ...payload,
                amount: intToBigInt$1(payload.amount),
            };
        }
        else {
            this.payload = payload;
        }
        this.postConditionMode = postConditionMode;
        this.postConditions = postConditions;
        this.anchorMode = AnchorMode$1.Any;
    }
    signBegin() {
        const tx = cloneDeep(this);
        tx.auth = intoInitialSighashAuth(tx.auth);
        return tx.txid();
    }
    verifyBegin() {
        const tx = cloneDeep(this);
        tx.auth = intoInitialSighashAuth(tx.auth);
        return tx.txid();
    }
    verifyOrigin() {
        return verifyOrigin(this.auth, this.verifyBegin());
    }
    signNextOrigin(sigHash, privateKey) {
        if (this.auth.spendingCondition === undefined) {
            throw new Error('"auth.spendingCondition" is undefined');
        }
        if (this.auth.authType === undefined) {
            throw new Error('"auth.authType" is undefined');
        }
        return this.signAndAppend(this.auth.spendingCondition, sigHash, AuthType$1.Standard, privateKey);
    }
    signNextSponsor(sigHash, privateKey) {
        if (this.auth.authType === AuthType$1.Sponsored) {
            return this.signAndAppend(this.auth.sponsorSpendingCondition, sigHash, AuthType$1.Sponsored, privateKey);
        }
        else {
            throw new Error('"auth.sponsorSpendingCondition" is undefined');
        }
    }
    appendPubkey(publicKey) {
        const wire = typeof publicKey === 'object' && 'type' in publicKey
            ? publicKey
            : createStacksPublicKey(publicKey);
        const cond = this.auth.spendingCondition;
        if (cond && !isSingleSig(cond)) {
            const compressed = publicKeyIsCompressed(wire.data);
            cond.fields.push(createTransactionAuthField(compressed ? PubKeyEncoding$1.Compressed : PubKeyEncoding$1.Uncompressed, wire));
        }
        else {
            throw new Error(`Can't append public key to a singlesig condition`);
        }
    }
    signAndAppend(condition, curSigHash, authType, privateKey) {
        const { nextSig, nextSigHash } = nextSignature(curSigHash, authType, condition.fee, condition.nonce, privateKey);
        if (isSingleSig(condition)) {
            condition.signature = createMessageSignature(nextSig);
        }
        else {
            const compressed = privateKeyIsCompressed(privateKey);
            condition.fields.push(createTransactionAuthField(compressed ? PubKeyEncoding$1.Compressed : PubKeyEncoding$1.Uncompressed, createMessageSignature(nextSig)));
        }
        return nextSigHash;
    }
    txid() {
        const serialized = this.serializeBytes();
        return txidFromData(serialized);
    }
    setSponsor(sponsorSpendingCondition) {
        if (this.auth.authType != AuthType$1.Sponsored) {
            throw new SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = setSponsor(this.auth, sponsorSpendingCondition);
    }
    setFee(amount) {
        this.auth = setFee(this.auth, amount);
    }
    setNonce(nonce) {
        this.auth = setNonce(this.auth, nonce);
    }
    setSponsorNonce(nonce) {
        if (this.auth.authType != AuthType$1.Sponsored) {
            throw new SigningError('Cannot sponsor sign a non-sponsored transaction');
        }
        this.auth = setSponsorNonce(this.auth, nonce);
    }
    serialize() {
        return bytesToHex$2(this.serializeBytes());
    }
    serializeBytes() {
        if (this.transactionVersion === undefined) {
            throw new SerializationError$1('"transactionVersion" is undefined');
        }
        if (this.chainId === undefined) {
            throw new SerializationError$1('"chainId" is undefined');
        }
        if (this.auth === undefined) {
            throw new SerializationError$1('"auth" is undefined');
        }
        if (this.payload === undefined) {
            throw new SerializationError$1('"payload" is undefined');
        }
        const bytesArray = [];
        bytesArray.push(this.transactionVersion);
        const chainIdBytes = new Uint8Array(4);
        writeUInt32BE$1(chainIdBytes, this.chainId, 0);
        bytesArray.push(chainIdBytes);
        bytesArray.push(serializeAuthorizationBytes(this.auth));
        bytesArray.push(this.anchorMode);
        bytesArray.push(this.postConditionMode);
        bytesArray.push(serializeLPListBytes(this.postConditions));
        bytesArray.push(serializePayloadBytes(this.payload));
        return concatArray$1(bytesArray);
    }
}
function deserializeTransaction(tx) {
    const bytesReader = isInstance(tx, BytesReader) ? tx : new BytesReader(tx);
    const transactionVersion = bytesReader.readUInt8Enum(TransactionVersion$2, n => {
        throw new Error(`Could not parse ${n} as TransactionVersion`);
    });
    const chainId = bytesReader.readUInt32BE();
    const auth = deserializeAuthorization(bytesReader);
    const anchorMode = bytesReader.readUInt8Enum(AnchorMode$1, n => {
        throw new Error(`Could not parse ${n} as AnchorMode`);
    });
    const postConditionMode = bytesReader.readUInt8Enum(PostConditionMode$1, n => {
        throw new Error(`Could not parse ${n} as PostConditionMode`);
    });
    const postConditions = deserializeLPList(bytesReader, StacksWireType.PostCondition);
    const payload = deserializePayload(bytesReader);
    const transaction = new StacksTransactionWire({
        transactionVersion,
        chainId,
        auth,
        payload,
        postConditions,
        postConditionMode,
    });
    transaction.anchorMode = anchorMode;
    return transaction;
}

var PostConditionCodeWireType;
(function (PostConditionCodeWireType) {
    PostConditionCodeWireType[PostConditionCodeWireType["eq"] = 1] = "eq";
    PostConditionCodeWireType[PostConditionCodeWireType["gt"] = 2] = "gt";
    PostConditionCodeWireType[PostConditionCodeWireType["lt"] = 4] = "lt";
    PostConditionCodeWireType[PostConditionCodeWireType["gte"] = 3] = "gte";
    PostConditionCodeWireType[PostConditionCodeWireType["lte"] = 5] = "lte";
    PostConditionCodeWireType[PostConditionCodeWireType["sent"] = 16] = "sent";
    PostConditionCodeWireType[PostConditionCodeWireType["not-sent"] = 17] = "not-sent";
})(PostConditionCodeWireType || (PostConditionCodeWireType = {}));
function postConditionToWire(postcondition) {
    switch (postcondition.type) {
        case 'stx-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.STX,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
            };
        case 'ft-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.Fungible,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                amount: BigInt(postcondition.amount),
                asset: parseAssetString(postcondition.asset),
            };
        case 'nft-postcondition':
            return {
                type: StacksWireType.PostCondition,
                conditionType: PostConditionType$1.NonFungible,
                principal: postcondition.address === 'origin'
                    ? { type: StacksWireType.Principal, prefix: PostConditionPrincipalId.Origin }
                    : parsePrincipalString(postcondition.address),
                conditionCode: conditionTypeToByte(postcondition.condition),
                asset: parseAssetString(postcondition.asset),
                assetName: postcondition.assetId,
            };
        default:
            throw new Error('Invalid post condition type');
    }
}
function conditionTypeToByte(condition) {
    return PostConditionCodeWireType[condition];
}
function postConditionToHex(postcondition) {
    const wire = postConditionToWire(postcondition);
    return serializePostConditionWire(wire);
}

const C32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function stringify(address) {
    const version = 'version' in address ? address.version : C32.indexOf(address.versionChar.toUpperCase());
    const addr = libExports.c32address(version, address.hash160);
    if (address.contractName)
        return `${addr}.${address.contractName}`;
    return addr;
}

const bool = boolCV;
const int = intCV;
const uint = uintCV;
const contractPrincipal = contractPrincipalCV;
const standardPrincipal = standardPrincipalCV;
const list = listCV;
const stringAscii = stringAsciiCV;
const stringUtf8 = stringUtf8CV;
const buffer = bufferCV;
const none = noneCV;
const some = someCV;
const ok = responseOkCV;
const error = responseErrorCV;
const tuple = tupleCV;
const serialize = serializeCV$1;
const deserialize = deserializeCV;

var browserPolyfill = {};

var hasRequiredBrowserPolyfill;

function requireBrowserPolyfill () {
	if (hasRequiredBrowserPolyfill) return browserPolyfill;
	hasRequiredBrowserPolyfill = 1;
	(function () {
		(function(self) {

		((function (exports) {

		  /* eslint-disable no-prototype-builtins */
		  var g =
		    (typeof globalThis !== 'undefined' && globalThis) ||
		    (typeof self !== 'undefined' && self) ||
		    // eslint-disable-next-line no-undef
		    (typeof commonjsGlobal !== 'undefined' && commonjsGlobal) ||
		    {};

		  var support = {
		    searchParams: 'URLSearchParams' in g,
		    iterable: 'Symbol' in g && 'iterator' in Symbol,
		    blob:
		      'FileReader' in g &&
		      'Blob' in g &&
		      (function() {
		        try {
		          new Blob();
		          return true
		        } catch (e) {
		          return false
		        }
		      })(),
		    formData: 'FormData' in g,
		    arrayBuffer: 'ArrayBuffer' in g
		  };

		  function isDataView(obj) {
		    return obj && DataView.prototype.isPrototypeOf(obj)
		  }

		  if (support.arrayBuffer) {
		    var viewClasses = [
		      '[object Int8Array]',
		      '[object Uint8Array]',
		      '[object Uint8ClampedArray]',
		      '[object Int16Array]',
		      '[object Uint16Array]',
		      '[object Int32Array]',
		      '[object Uint32Array]',
		      '[object Float32Array]',
		      '[object Float64Array]'
		    ];

		    var isArrayBufferView =
		      ArrayBuffer.isView ||
		      function(obj) {
		        return obj && viewClasses.indexOf(Object.prototype.toString.call(obj)) > -1
		      };
		  }

		  function normalizeName(name) {
		    if (typeof name !== 'string') {
		      name = String(name);
		    }
		    if (/[^a-z0-9\-#$%&'*+.^_`|~!]/i.test(name) || name === '') {
		      throw new TypeError('Invalid character in header field name: "' + name + '"')
		    }
		    return name.toLowerCase()
		  }

		  function normalizeValue(value) {
		    if (typeof value !== 'string') {
		      value = String(value);
		    }
		    return value
		  }

		  // Build a destructive iterator for the value list
		  function iteratorFor(items) {
		    var iterator = {
		      next: function() {
		        var value = items.shift();
		        return {done: value === undefined, value: value}
		      }
		    };

		    if (support.iterable) {
		      iterator[Symbol.iterator] = function() {
		        return iterator
		      };
		    }

		    return iterator
		  }

		  function Headers(headers) {
		    this.map = {};

		    if (headers instanceof Headers) {
		      headers.forEach(function(value, name) {
		        this.append(name, value);
		      }, this);
		    } else if (Array.isArray(headers)) {
		      headers.forEach(function(header) {
		        if (header.length != 2) {
		          throw new TypeError('Headers constructor: expected name/value pair to be length 2, found' + header.length)
		        }
		        this.append(header[0], header[1]);
		      }, this);
		    } else if (headers) {
		      Object.getOwnPropertyNames(headers).forEach(function(name) {
		        this.append(name, headers[name]);
		      }, this);
		    }
		  }

		  Headers.prototype.append = function(name, value) {
		    name = normalizeName(name);
		    value = normalizeValue(value);
		    var oldValue = this.map[name];
		    this.map[name] = oldValue ? oldValue + ', ' + value : value;
		  };

		  Headers.prototype['delete'] = function(name) {
		    delete this.map[normalizeName(name)];
		  };

		  Headers.prototype.get = function(name) {
		    name = normalizeName(name);
		    return this.has(name) ? this.map[name] : null
		  };

		  Headers.prototype.has = function(name) {
		    return this.map.hasOwnProperty(normalizeName(name))
		  };

		  Headers.prototype.set = function(name, value) {
		    this.map[normalizeName(name)] = normalizeValue(value);
		  };

		  Headers.prototype.forEach = function(callback, thisArg) {
		    for (var name in this.map) {
		      if (this.map.hasOwnProperty(name)) {
		        callback.call(thisArg, this.map[name], name, this);
		      }
		    }
		  };

		  Headers.prototype.keys = function() {
		    var items = [];
		    this.forEach(function(value, name) {
		      items.push(name);
		    });
		    return iteratorFor(items)
		  };

		  Headers.prototype.values = function() {
		    var items = [];
		    this.forEach(function(value) {
		      items.push(value);
		    });
		    return iteratorFor(items)
		  };

		  Headers.prototype.entries = function() {
		    var items = [];
		    this.forEach(function(value, name) {
		      items.push([name, value]);
		    });
		    return iteratorFor(items)
		  };

		  if (support.iterable) {
		    Headers.prototype[Symbol.iterator] = Headers.prototype.entries;
		  }

		  function consumed(body) {
		    if (body._noBody) return
		    if (body.bodyUsed) {
		      return Promise.reject(new TypeError('Already read'))
		    }
		    body.bodyUsed = true;
		  }

		  function fileReaderReady(reader) {
		    return new Promise(function(resolve, reject) {
		      reader.onload = function() {
		        resolve(reader.result);
		      };
		      reader.onerror = function() {
		        reject(reader.error);
		      };
		    })
		  }

		  function readBlobAsArrayBuffer(blob) {
		    var reader = new FileReader();
		    var promise = fileReaderReady(reader);
		    reader.readAsArrayBuffer(blob);
		    return promise
		  }

		  function readBlobAsText(blob) {
		    var reader = new FileReader();
		    var promise = fileReaderReady(reader);
		    var match = /charset=([A-Za-z0-9_-]+)/.exec(blob.type);
		    var encoding = match ? match[1] : 'utf-8';
		    reader.readAsText(blob, encoding);
		    return promise
		  }

		  function readArrayBufferAsText(buf) {
		    var view = new Uint8Array(buf);
		    var chars = new Array(view.length);

		    for (var i = 0; i < view.length; i++) {
		      chars[i] = String.fromCharCode(view[i]);
		    }
		    return chars.join('')
		  }

		  function bufferClone(buf) {
		    if (buf.slice) {
		      return buf.slice(0)
		    } else {
		      var view = new Uint8Array(buf.byteLength);
		      view.set(new Uint8Array(buf));
		      return view.buffer
		    }
		  }

		  function Body() {
		    this.bodyUsed = false;

		    this._initBody = function(body) {
		      /*
		        fetch-mock wraps the Response object in an ES6 Proxy to
		        provide useful test harness features such as flush. However, on
		        ES5 browsers without fetch or Proxy support pollyfills must be used;
		        the proxy-pollyfill is unable to proxy an attribute unless it exists
		        on the object before the Proxy is created. This change ensures
		        Response.bodyUsed exists on the instance, while maintaining the
		        semantic of setting Request.bodyUsed in the constructor before
		        _initBody is called.
		      */
		      // eslint-disable-next-line no-self-assign
		      this.bodyUsed = this.bodyUsed;
		      this._bodyInit = body;
		      if (!body) {
		        this._noBody = true;
		        this._bodyText = '';
		      } else if (typeof body === 'string') {
		        this._bodyText = body;
		      } else if (support.blob && Blob.prototype.isPrototypeOf(body)) {
		        this._bodyBlob = body;
		      } else if (support.formData && FormData.prototype.isPrototypeOf(body)) {
		        this._bodyFormData = body;
		      } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
		        this._bodyText = body.toString();
		      } else if (support.arrayBuffer && support.blob && isDataView(body)) {
		        this._bodyArrayBuffer = bufferClone(body.buffer);
		        // IE 10-11 can't handle a DataView body.
		        this._bodyInit = new Blob([this._bodyArrayBuffer]);
		      } else if (support.arrayBuffer && (ArrayBuffer.prototype.isPrototypeOf(body) || isArrayBufferView(body))) {
		        this._bodyArrayBuffer = bufferClone(body);
		      } else {
		        this._bodyText = body = Object.prototype.toString.call(body);
		      }

		      if (!this.headers.get('content-type')) {
		        if (typeof body === 'string') {
		          this.headers.set('content-type', 'text/plain;charset=UTF-8');
		        } else if (this._bodyBlob && this._bodyBlob.type) {
		          this.headers.set('content-type', this._bodyBlob.type);
		        } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
		          this.headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
		        }
		      }
		    };

		    if (support.blob) {
		      this.blob = function() {
		        var rejected = consumed(this);
		        if (rejected) {
		          return rejected
		        }

		        if (this._bodyBlob) {
		          return Promise.resolve(this._bodyBlob)
		        } else if (this._bodyArrayBuffer) {
		          return Promise.resolve(new Blob([this._bodyArrayBuffer]))
		        } else if (this._bodyFormData) {
		          throw new Error('could not read FormData body as blob')
		        } else {
		          return Promise.resolve(new Blob([this._bodyText]))
		        }
		      };
		    }

		    this.arrayBuffer = function() {
		      if (this._bodyArrayBuffer) {
		        var isConsumed = consumed(this);
		        if (isConsumed) {
		          return isConsumed
		        } else if (ArrayBuffer.isView(this._bodyArrayBuffer)) {
		          return Promise.resolve(
		            this._bodyArrayBuffer.buffer.slice(
		              this._bodyArrayBuffer.byteOffset,
		              this._bodyArrayBuffer.byteOffset + this._bodyArrayBuffer.byteLength
		            )
		          )
		        } else {
		          return Promise.resolve(this._bodyArrayBuffer)
		        }
		      } else if (support.blob) {
		        return this.blob().then(readBlobAsArrayBuffer)
		      } else {
		        throw new Error('could not read as ArrayBuffer')
		      }
		    };

		    this.text = function() {
		      var rejected = consumed(this);
		      if (rejected) {
		        return rejected
		      }

		      if (this._bodyBlob) {
		        return readBlobAsText(this._bodyBlob)
		      } else if (this._bodyArrayBuffer) {
		        return Promise.resolve(readArrayBufferAsText(this._bodyArrayBuffer))
		      } else if (this._bodyFormData) {
		        throw new Error('could not read FormData body as text')
		      } else {
		        return Promise.resolve(this._bodyText)
		      }
		    };

		    if (support.formData) {
		      this.formData = function() {
		        return this.text().then(decode)
		      };
		    }

		    this.json = function() {
		      return this.text().then(JSON.parse)
		    };

		    return this
		  }

		  // HTTP methods whose capitalization should be normalized
		  var methods = ['CONNECT', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT', 'TRACE'];

		  function normalizeMethod(method) {
		    var upcased = method.toUpperCase();
		    return methods.indexOf(upcased) > -1 ? upcased : method
		  }

		  function Request(input, options) {
		    if (!(this instanceof Request)) {
		      throw new TypeError('Please use the "new" operator, this DOM object constructor cannot be called as a function.')
		    }

		    options = options || {};
		    var body = options.body;

		    if (input instanceof Request) {
		      if (input.bodyUsed) {
		        throw new TypeError('Already read')
		      }
		      this.url = input.url;
		      this.credentials = input.credentials;
		      if (!options.headers) {
		        this.headers = new Headers(input.headers);
		      }
		      this.method = input.method;
		      this.mode = input.mode;
		      this.signal = input.signal;
		      if (!body && input._bodyInit != null) {
		        body = input._bodyInit;
		        input.bodyUsed = true;
		      }
		    } else {
		      this.url = String(input);
		    }

		    this.credentials = options.credentials || this.credentials || 'same-origin';
		    if (options.headers || !this.headers) {
		      this.headers = new Headers(options.headers);
		    }
		    this.method = normalizeMethod(options.method || this.method || 'GET');
		    this.mode = options.mode || this.mode || null;
		    this.signal = options.signal || this.signal || (function () {
		      if ('AbortController' in g) {
		        var ctrl = new AbortController();
		        return ctrl.signal;
		      }
		    }());
		    this.referrer = null;

		    if ((this.method === 'GET' || this.method === 'HEAD') && body) {
		      throw new TypeError('Body not allowed for GET or HEAD requests')
		    }
		    this._initBody(body);

		    if (this.method === 'GET' || this.method === 'HEAD') {
		      if (options.cache === 'no-store' || options.cache === 'no-cache') {
		        // Search for a '_' parameter in the query string
		        var reParamSearch = /([?&])_=[^&]*/;
		        if (reParamSearch.test(this.url)) {
		          // If it already exists then set the value with the current time
		          this.url = this.url.replace(reParamSearch, '$1_=' + new Date().getTime());
		        } else {
		          // Otherwise add a new '_' parameter to the end with the current time
		          var reQueryString = /\?/;
		          this.url += (reQueryString.test(this.url) ? '&' : '?') + '_=' + new Date().getTime();
		        }
		      }
		    }
		  }

		  Request.prototype.clone = function() {
		    return new Request(this, {body: this._bodyInit})
		  };

		  function decode(body) {
		    var form = new FormData();
		    body
		      .trim()
		      .split('&')
		      .forEach(function(bytes) {
		        if (bytes) {
		          var split = bytes.split('=');
		          var name = split.shift().replace(/\+/g, ' ');
		          var value = split.join('=').replace(/\+/g, ' ');
		          form.append(decodeURIComponent(name), decodeURIComponent(value));
		        }
		      });
		    return form
		  }

		  function parseHeaders(rawHeaders) {
		    var headers = new Headers();
		    // Replace instances of \r\n and \n followed by at least one space or horizontal tab with a space
		    // https://tools.ietf.org/html/rfc7230#section-3.2
		    var preProcessedHeaders = rawHeaders.replace(/\r?\n[\t ]+/g, ' ');
		    // Avoiding split via regex to work around a common IE11 bug with the core-js 3.6.0 regex polyfill
		    // https://github.com/github/fetch/issues/748
		    // https://github.com/zloirock/core-js/issues/751
		    preProcessedHeaders
		      .split('\r')
		      .map(function(header) {
		        return header.indexOf('\n') === 0 ? header.substr(1, header.length) : header
		      })
		      .forEach(function(line) {
		        var parts = line.split(':');
		        var key = parts.shift().trim();
		        if (key) {
		          var value = parts.join(':').trim();
		          try {
		            headers.append(key, value);
		          } catch (error) {
		            console.warn('Response ' + error.message);
		          }
		        }
		      });
		    return headers
		  }

		  Body.call(Request.prototype);

		  function Response(bodyInit, options) {
		    if (!(this instanceof Response)) {
		      throw new TypeError('Please use the "new" operator, this DOM object constructor cannot be called as a function.')
		    }
		    if (!options) {
		      options = {};
		    }

		    this.type = 'default';
		    this.status = options.status === undefined ? 200 : options.status;
		    if (this.status < 200 || this.status > 599) {
		      throw new RangeError("Failed to construct 'Response': The status provided (0) is outside the range [200, 599].")
		    }
		    this.ok = this.status >= 200 && this.status < 300;
		    this.statusText = options.statusText === undefined ? '' : '' + options.statusText;
		    this.headers = new Headers(options.headers);
		    this.url = options.url || '';
		    this._initBody(bodyInit);
		  }

		  Body.call(Response.prototype);

		  Response.prototype.clone = function() {
		    return new Response(this._bodyInit, {
		      status: this.status,
		      statusText: this.statusText,
		      headers: new Headers(this.headers),
		      url: this.url
		    })
		  };

		  Response.error = function() {
		    var response = new Response(null, {status: 200, statusText: ''});
		    response.ok = false;
		    response.status = 0;
		    response.type = 'error';
		    return response
		  };

		  var redirectStatuses = [301, 302, 303, 307, 308];

		  Response.redirect = function(url, status) {
		    if (redirectStatuses.indexOf(status) === -1) {
		      throw new RangeError('Invalid status code')
		    }

		    return new Response(null, {status: status, headers: {location: url}})
		  };

		  exports.DOMException = g.DOMException;
		  try {
		    new exports.DOMException();
		  } catch (err) {
		    exports.DOMException = function(message, name) {
		      this.message = message;
		      this.name = name;
		      var error = Error(message);
		      this.stack = error.stack;
		    };
		    exports.DOMException.prototype = Object.create(Error.prototype);
		    exports.DOMException.prototype.constructor = exports.DOMException;
		  }

		  function fetch(input, init) {
		    return new Promise(function(resolve, reject) {
		      var request = new Request(input, init);

		      if (request.signal && request.signal.aborted) {
		        return reject(new exports.DOMException('Aborted', 'AbortError'))
		      }

		      var xhr = new XMLHttpRequest();

		      function abortXhr() {
		        xhr.abort();
		      }

		      xhr.onload = function() {
		        var options = {
		          statusText: xhr.statusText,
		          headers: parseHeaders(xhr.getAllResponseHeaders() || '')
		        };
		        // This check if specifically for when a user fetches a file locally from the file system
		        // Only if the status is out of a normal range
		        if (request.url.indexOf('file://') === 0 && (xhr.status < 200 || xhr.status > 599)) {
		          options.status = 200;
		        } else {
		          options.status = xhr.status;
		        }
		        options.url = 'responseURL' in xhr ? xhr.responseURL : options.headers.get('X-Request-URL');
		        var body = 'response' in xhr ? xhr.response : xhr.responseText;
		        setTimeout(function() {
		          resolve(new Response(body, options));
		        }, 0);
		      };

		      xhr.onerror = function() {
		        setTimeout(function() {
		          reject(new TypeError('Network request failed'));
		        }, 0);
		      };

		      xhr.ontimeout = function() {
		        setTimeout(function() {
		          reject(new TypeError('Network request timed out'));
		        }, 0);
		      };

		      xhr.onabort = function() {
		        setTimeout(function() {
		          reject(new exports.DOMException('Aborted', 'AbortError'));
		        }, 0);
		      };

		      function fixUrl(url) {
		        try {
		          return url === '' && g.location.href ? g.location.href : url
		        } catch (e) {
		          return url
		        }
		      }

		      xhr.open(request.method, fixUrl(request.url), true);

		      if (request.credentials === 'include') {
		        xhr.withCredentials = true;
		      } else if (request.credentials === 'omit') {
		        xhr.withCredentials = false;
		      }

		      if ('responseType' in xhr) {
		        if (support.blob) {
		          xhr.responseType = 'blob';
		        } else if (
		          support.arrayBuffer
		        ) {
		          xhr.responseType = 'arraybuffer';
		        }
		      }

		      if (init && typeof init.headers === 'object' && !(init.headers instanceof Headers || (g.Headers && init.headers instanceof g.Headers))) {
		        var names = [];
		        Object.getOwnPropertyNames(init.headers).forEach(function(name) {
		          names.push(normalizeName(name));
		          xhr.setRequestHeader(name, normalizeValue(init.headers[name]));
		        });
		        request.headers.forEach(function(value, name) {
		          if (names.indexOf(name) === -1) {
		            xhr.setRequestHeader(name, value);
		          }
		        });
		      } else {
		        request.headers.forEach(function(value, name) {
		          xhr.setRequestHeader(name, value);
		        });
		      }

		      if (request.signal) {
		        request.signal.addEventListener('abort', abortXhr);

		        xhr.onreadystatechange = function() {
		          // DONE (success or failure)
		          if (xhr.readyState === 4) {
		            request.signal.removeEventListener('abort', abortXhr);
		          }
		        };
		      }

		      xhr.send(typeof request._bodyInit === 'undefined' ? null : request._bodyInit);
		    })
		  }

		  fetch.polyfill = true;

		  if (!g.fetch) {
		    g.fetch = fetch;
		    g.Headers = Headers;
		    g.Request = Request;
		    g.Response = Response;
		  }

		  exports.Headers = Headers;
		  exports.Request = Request;
		  exports.Response = Response;
		  exports.fetch = fetch;

		  Object.defineProperty(exports, '__esModule', { value: true });

		  return exports;

		}))({});
		})(typeof self !== 'undefined' ? self : browserPolyfill); 
	} ());
	return browserPolyfill;
}

requireBrowserPolyfill();

const defaultFetchOpts = {
    referrerPolicy: 'origin',
    headers: {
        'x-hiro-product': 'stacksjs',
    },
};
async function fetchWrapper(input, init) {
    const fetchOpts = {};
    Object.assign(fetchOpts, defaultFetchOpts, init);
    const fetchResult = await fetch(input, fetchOpts);
    return fetchResult;
}
function argsForCreateFetchFn(args) {
    let fetchLib = fetchWrapper;
    let middlewares = [];
    if (args.length > 0 && typeof args[0] === 'function') {
        fetchLib = args.shift();
    }
    if (args.length > 0) {
        middlewares = args;
    }
    return { fetchLib, middlewares };
}
function createFetchFn(...args) {
    const { fetchLib, middlewares } = argsForCreateFetchFn(args);
    const fetchFn = async (url, init) => {
        let fetchParams = { url, init: init ?? {} };
        for (const middleware of middlewares) {
            if (typeof middleware.pre === 'function') {
                const result = await Promise.resolve(middleware.pre({
                    fetch: fetchLib,
                    ...fetchParams,
                }));
                fetchParams = result ?? fetchParams;
            }
        }
        let response = await fetchLib(fetchParams.url, fetchParams.init);
        for (const middleware of middlewares) {
            if (typeof middleware.post === 'function') {
                const result = await Promise.resolve(middleware.post({
                    fetch: fetchLib,
                    url: fetchParams.url,
                    init: fetchParams.init,
                    response: response?.clone() ?? response,
                }));
                response = result ?? response;
            }
        }
        return response;
    };
    return fetchFn;
}

var ChainID$1;
(function (ChainID) {
    ChainID[ChainID["Testnet"] = 2147483648] = "Testnet";
    ChainID[ChainID["Mainnet"] = 1] = "Mainnet";
})(ChainID$1 || (ChainID$1 = {}));
var TransactionVersion$1;
(function (TransactionVersion) {
    TransactionVersion[TransactionVersion["Mainnet"] = 0] = "Mainnet";
    TransactionVersion[TransactionVersion["Testnet"] = 128] = "Testnet";
})(TransactionVersion$1 || (TransactionVersion$1 = {}));
var PeerNetworkID;
(function (PeerNetworkID) {
    PeerNetworkID[PeerNetworkID["Mainnet"] = 385875968] = "Mainnet";
    PeerNetworkID[PeerNetworkID["Testnet"] = 4278190080] = "Testnet";
})(PeerNetworkID || (PeerNetworkID = {}));

const HIRO_MAINNET_DEFAULT = 'https://api.mainnet.hiro.so';
const HIRO_TESTNET_DEFAULT = 'https://api.testnet.hiro.so';
const HIRO_MOCKNET_DEFAULT = 'http://localhost:3999';
const StacksNetworks = ['mainnet', 'testnet', 'devnet', 'mocknet'];
class StacksNetwork {
    constructor(networkConfig) {
        this.version = TransactionVersion$1.Mainnet;
        this.chainId = ChainID$1.Mainnet;
        this.bnsLookupUrl = 'https://api.mainnet.hiro.so';
        this.broadcastEndpoint = '/v2/transactions';
        this.transferFeeEstimateEndpoint = '/v2/fees/transfer';
        this.transactionFeeEstimateEndpoint = '/v2/fees/transaction';
        this.accountEndpoint = '/v2/accounts';
        this.contractAbiEndpoint = '/v2/contracts/interface';
        this.readOnlyFunctionCallEndpoint = '/v2/contracts/call-read';
        this.isMainnet = () => this.version === TransactionVersion$1.Mainnet;
        this.getBroadcastApiUrl = () => `${this.coreApiUrl}${this.broadcastEndpoint}`;
        this.getTransferFeeEstimateApiUrl = () => `${this.coreApiUrl}${this.transferFeeEstimateEndpoint}`;
        this.getTransactionFeeEstimateApiUrl = () => `${this.coreApiUrl}${this.transactionFeeEstimateEndpoint}`;
        this.getAccountApiUrl = (address) => `${this.coreApiUrl}${this.accountEndpoint}/${address}?proof=0`;
        this.getAccountExtendedBalancesApiUrl = (address) => `${this.coreApiUrl}/extended/v1/address/${address}/balances`;
        this.getAbiApiUrl = (address, contract) => `${this.coreApiUrl}${this.contractAbiEndpoint}/${address}/${contract}`;
        this.getReadOnlyFunctionCallApiUrl = (contractAddress, contractName, functionName) => `${this.coreApiUrl}${this.readOnlyFunctionCallEndpoint}/${contractAddress}/${contractName}/${encodeURIComponent(functionName)}`;
        this.getInfoUrl = () => `${this.coreApiUrl}/v2/info`;
        this.getBlockTimeInfoUrl = () => `${this.coreApiUrl}/extended/v1/info/network_block_times`;
        this.getPoxInfoUrl = () => `${this.coreApiUrl}/v2/pox`;
        this.getRewardsUrl = (address, options) => {
            let url = `${this.coreApiUrl}/extended/v1/burnchain/rewards/${address}`;
            if (options) {
                url = `${url}?limit=${options.limit}&offset=${options.offset}`;
            }
            return url;
        };
        this.getRewardsTotalUrl = (address) => `${this.coreApiUrl}/extended/v1/burnchain/rewards/${address}/total`;
        this.getRewardHoldersUrl = (address, options) => {
            let url = `${this.coreApiUrl}/extended/v1/burnchain/reward_slot_holders/${address}`;
            if (options) {
                url = `${url}?limit=${options.limit}&offset=${options.offset}`;
            }
            return url;
        };
        this.getStackerInfoUrl = (contractAddress, contractName) => `${this.coreApiUrl}${this.readOnlyFunctionCallEndpoint}
    ${contractAddress}/${contractName}/get-stacker-info`;
        this.getDataVarUrl = (contractAddress, contractName, dataVarName) => `${this.coreApiUrl}/v2/data_var/${contractAddress}/${contractName}/${dataVarName}?proof=0`;
        this.getMapEntryUrl = (contractAddress, contractName, mapName) => `${this.coreApiUrl}/v2/map_entry/${contractAddress}/${contractName}/${mapName}?proof=0`;
        this.coreApiUrl = networkConfig.url;
        this.fetchFn = networkConfig.fetchFn ?? createFetchFn();
    }
    getNameInfo(fullyQualifiedName) {
        const nameLookupURL = `${this.bnsLookupUrl}/v1/names/${fullyQualifiedName}`;
        return this.fetchFn(nameLookupURL)
            .then(resp => {
            if (resp.status === 404) {
                throw new Error('Name not found');
            }
            else if (resp.status !== 200) {
                throw new Error(`Bad response status: ${resp.status}`);
            }
            else {
                return resp.json();
            }
        })
            .then(nameInfo => {
            if (nameInfo.address) {
                return Object.assign({}, nameInfo, { address: nameInfo.address });
            }
            else {
                return nameInfo;
            }
        });
    }
}
StacksNetwork.fromName = (networkName) => {
    switch (networkName) {
        case 'mainnet':
            return new StacksMainnet();
        case 'testnet':
            return new StacksTestnet();
        case 'devnet':
            return new StacksDevnet();
        case 'mocknet':
            return new StacksMocknet();
        default:
            throw new Error(`Invalid network name provided. Must be one of the following: ${StacksNetworks.join(', ')}`);
    }
};
StacksNetwork.fromNameOrNetwork = (network) => {
    if (typeof network !== 'string' && 'version' in network) {
        return network;
    }
    return StacksNetwork.fromName(network);
};
class StacksMainnet extends StacksNetwork {
    constructor(opts) {
        super({
            url: opts?.url ?? HIRO_MAINNET_DEFAULT,
            fetchFn: opts?.fetchFn,
        });
        this.version = TransactionVersion$1.Mainnet;
        this.chainId = ChainID$1.Mainnet;
    }
}
class StacksTestnet extends StacksNetwork {
    constructor(opts) {
        super({
            url: opts?.url ?? HIRO_TESTNET_DEFAULT,
            fetchFn: opts?.fetchFn,
        });
        this.version = TransactionVersion$1.Testnet;
        this.chainId = ChainID$1.Testnet;
    }
}
class StacksMocknet extends StacksNetwork {
    constructor(opts) {
        super({
            url: opts?.url ?? HIRO_MOCKNET_DEFAULT,
            fetchFn: opts?.fetchFn,
        });
        this.version = TransactionVersion$1.Testnet;
        this.chainId = ChainID$1.Testnet;
    }
}
const StacksDevnet = StacksMocknet;

function intToBytes(value, signed, byteLength) {
    return bigIntToBytes(intToBigInt(value), byteLength);
}
function intToBigInt(value, signed) {
    let parsedValue = value;
    if (typeof parsedValue === 'number') {
        if (!Number.isInteger(parsedValue)) {
            throw new RangeError(`Invalid value. Values of type 'number' must be an integer.`);
        }
        if (parsedValue > Number.MAX_SAFE_INTEGER) {
            throw new RangeError(`Invalid value. Values of type 'number' must be less than or equal to ${Number.MAX_SAFE_INTEGER}. For larger values, try using a BigInt instead.`);
        }
        return BigInt(parsedValue);
    }
    if (typeof parsedValue === 'string') {
        if (parsedValue.toLowerCase().startsWith('0x')) {
            let hex = parsedValue.slice(2);
            hex = hex.padStart(hex.length + (hex.length % 2), '0');
            parsedValue = hexToBytes(hex);
        }
        else {
            try {
                return BigInt(parsedValue);
            }
            catch (error) {
                if (error instanceof SyntaxError) {
                    throw new RangeError(`Invalid value. String integer '${parsedValue}' is not finite.`);
                }
            }
        }
    }
    if (typeof parsedValue === 'bigint') {
        return parsedValue;
    }
    if (parsedValue instanceof Uint8Array) {
        {
            return BigInt(`0x${bytesToHex(parsedValue)}`);
        }
    }
    if (parsedValue != null &&
        typeof parsedValue === 'object' &&
        parsedValue.constructor.name === 'BN') {
        return BigInt(parsedValue.toString());
    }
    throw new TypeError(`Invalid value type. Must be a number, bigint, integer-string, hex-string, or Uint8Array.`);
}
function intToHex(integer, lengthBytes = 8) {
    const value = typeof integer === 'bigint' ? integer : intToBigInt(integer);
    return value.toString(16).padStart(lengthBytes * 2, '0');
}
function bigIntToBytes(value, length = 16) {
    const hex = intToHex(value, length);
    return hexToBytes(hex);
}
function toTwos(value, width) {
    if (value < -(BigInt(1) << (width - BigInt(1))) ||
        (BigInt(1) << (width - BigInt(1))) - BigInt(1) < value) {
        throw `Unable to represent integer in width: ${width}`;
    }
    if (value >= BigInt(0)) {
        return BigInt(value);
    }
    return value + (BigInt(1) << width);
}
const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Uint8Array expected');
    let hex = '';
    for (const u of uint8a) {
        hex += hexes[u];
    }
    return hex;
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError(`hexToBytes: expected string, got ${typeof hex}`);
    }
    hex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
    const paddedHex = hex.length % 2 ? `0${hex}` : hex;
    const array = new Uint8Array(paddedHex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = paddedHex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
}
function asciiToBytes(str) {
    const byteArray = [];
    for (let i = 0; i < str.length; i++) {
        byteArray.push(str.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(byteArray);
}
function isNotOctet(octet) {
    return !Number.isInteger(octet) || octet < 0 || octet > 255;
}
function octetsToBytes(numbers) {
    if (numbers.some(isNotOctet))
        throw new Error('Some values are invalid bytes.');
    return new Uint8Array(numbers);
}
function concatBytes(...arrays) {
    if (!arrays.every(a => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function concatArray(elements) {
    return concatBytes(...elements.map(e => {
        if (typeof e === 'number')
            return octetsToBytes([e]);
        if (e instanceof Array)
            return octetsToBytes(e);
        return e;
    }));
}

function writeUInt32BE(destination, value, offset = 0) {
    destination[offset + 3] = value;
    value >>>= 8;
    destination[offset + 2] = value;
    value >>>= 8;
    destination[offset + 1] = value;
    value >>>= 8;
    destination[offset] = value;
    return destination;
}

var ChainID;
(function (ChainID) {
    ChainID[ChainID["Testnet"] = 2147483648] = "Testnet";
    ChainID[ChainID["Mainnet"] = 1] = "Mainnet";
})(ChainID || (ChainID = {}));
ChainID.Mainnet;
const MAX_STRING_LENGTH_BYTES = 128;
const CLARITY_INT_SIZE = 128;
const CLARITY_INT_BYTE_SIZE = 16;
var StacksMessageType;
(function (StacksMessageType) {
    StacksMessageType[StacksMessageType["Address"] = 0] = "Address";
    StacksMessageType[StacksMessageType["Principal"] = 1] = "Principal";
    StacksMessageType[StacksMessageType["LengthPrefixedString"] = 2] = "LengthPrefixedString";
    StacksMessageType[StacksMessageType["MemoString"] = 3] = "MemoString";
    StacksMessageType[StacksMessageType["AssetInfo"] = 4] = "AssetInfo";
    StacksMessageType[StacksMessageType["PostCondition"] = 5] = "PostCondition";
    StacksMessageType[StacksMessageType["PublicKey"] = 6] = "PublicKey";
    StacksMessageType[StacksMessageType["LengthPrefixedList"] = 7] = "LengthPrefixedList";
    StacksMessageType[StacksMessageType["Payload"] = 8] = "Payload";
    StacksMessageType[StacksMessageType["MessageSignature"] = 9] = "MessageSignature";
    StacksMessageType[StacksMessageType["StructuredDataSignature"] = 10] = "StructuredDataSignature";
    StacksMessageType[StacksMessageType["TransactionAuthField"] = 11] = "TransactionAuthField";
})(StacksMessageType || (StacksMessageType = {}));
var PayloadType;
(function (PayloadType) {
    PayloadType[PayloadType["TokenTransfer"] = 0] = "TokenTransfer";
    PayloadType[PayloadType["SmartContract"] = 1] = "SmartContract";
    PayloadType[PayloadType["VersionedSmartContract"] = 6] = "VersionedSmartContract";
    PayloadType[PayloadType["ContractCall"] = 2] = "ContractCall";
    PayloadType[PayloadType["PoisonMicroblock"] = 3] = "PoisonMicroblock";
    PayloadType[PayloadType["Coinbase"] = 4] = "Coinbase";
    PayloadType[PayloadType["CoinbaseToAltRecipient"] = 5] = "CoinbaseToAltRecipient";
    PayloadType[PayloadType["TenureChange"] = 7] = "TenureChange";
    PayloadType[PayloadType["NakamotoCoinbase"] = 8] = "NakamotoCoinbase";
})(PayloadType || (PayloadType = {}));
var ClarityVersion;
(function (ClarityVersion) {
    ClarityVersion[ClarityVersion["Clarity1"] = 1] = "Clarity1";
    ClarityVersion[ClarityVersion["Clarity2"] = 2] = "Clarity2";
    ClarityVersion[ClarityVersion["Clarity3"] = 3] = "Clarity3";
})(ClarityVersion || (ClarityVersion = {}));
var AnchorMode;
(function (AnchorMode) {
    AnchorMode[AnchorMode["OnChainOnly"] = 1] = "OnChainOnly";
    AnchorMode[AnchorMode["OffChainOnly"] = 2] = "OffChainOnly";
    AnchorMode[AnchorMode["Any"] = 3] = "Any";
})(AnchorMode || (AnchorMode = {}));
const AnchorModeNames = ['onChainOnly', 'offChainOnly', 'any'];
({
    [AnchorModeNames[0]]: AnchorMode.OnChainOnly,
    [AnchorModeNames[1]]: AnchorMode.OffChainOnly,
    [AnchorModeNames[2]]: AnchorMode.Any,
    [AnchorMode.OnChainOnly]: AnchorMode.OnChainOnly,
    [AnchorMode.OffChainOnly]: AnchorMode.OffChainOnly,
    [AnchorMode.Any]: AnchorMode.Any,
});
var TransactionVersion;
(function (TransactionVersion) {
    TransactionVersion[TransactionVersion["Mainnet"] = 0] = "Mainnet";
    TransactionVersion[TransactionVersion["Testnet"] = 128] = "Testnet";
})(TransactionVersion || (TransactionVersion = {}));
TransactionVersion.Mainnet;
var PostConditionMode;
(function (PostConditionMode) {
    PostConditionMode[PostConditionMode["Allow"] = 1] = "Allow";
    PostConditionMode[PostConditionMode["Deny"] = 2] = "Deny";
})(PostConditionMode || (PostConditionMode = {}));
var PostConditionType;
(function (PostConditionType) {
    PostConditionType[PostConditionType["STX"] = 0] = "STX";
    PostConditionType[PostConditionType["Fungible"] = 1] = "Fungible";
    PostConditionType[PostConditionType["NonFungible"] = 2] = "NonFungible";
})(PostConditionType || (PostConditionType = {}));
var AuthType;
(function (AuthType) {
    AuthType[AuthType["Standard"] = 4] = "Standard";
    AuthType[AuthType["Sponsored"] = 5] = "Sponsored";
})(AuthType || (AuthType = {}));
var AddressHashMode;
(function (AddressHashMode) {
    AddressHashMode[AddressHashMode["SerializeP2PKH"] = 0] = "SerializeP2PKH";
    AddressHashMode[AddressHashMode["SerializeP2SH"] = 1] = "SerializeP2SH";
    AddressHashMode[AddressHashMode["SerializeP2WPKH"] = 2] = "SerializeP2WPKH";
    AddressHashMode[AddressHashMode["SerializeP2WSH"] = 3] = "SerializeP2WSH";
    AddressHashMode[AddressHashMode["SerializeP2SHNonSequential"] = 5] = "SerializeP2SHNonSequential";
    AddressHashMode[AddressHashMode["SerializeP2WSHNonSequential"] = 7] = "SerializeP2WSHNonSequential";
})(AddressHashMode || (AddressHashMode = {}));
var AddressVersion;
(function (AddressVersion) {
    AddressVersion[AddressVersion["MainnetSingleSig"] = 22] = "MainnetSingleSig";
    AddressVersion[AddressVersion["MainnetMultiSig"] = 20] = "MainnetMultiSig";
    AddressVersion[AddressVersion["TestnetSingleSig"] = 26] = "TestnetSingleSig";
    AddressVersion[AddressVersion["TestnetMultiSig"] = 21] = "TestnetMultiSig";
})(AddressVersion || (AddressVersion = {}));
var PubKeyEncoding;
(function (PubKeyEncoding) {
    PubKeyEncoding[PubKeyEncoding["Compressed"] = 0] = "Compressed";
    PubKeyEncoding[PubKeyEncoding["Uncompressed"] = 1] = "Uncompressed";
})(PubKeyEncoding || (PubKeyEncoding = {}));
var FungibleConditionCode;
(function (FungibleConditionCode) {
    FungibleConditionCode[FungibleConditionCode["Equal"] = 1] = "Equal";
    FungibleConditionCode[FungibleConditionCode["Greater"] = 2] = "Greater";
    FungibleConditionCode[FungibleConditionCode["GreaterEqual"] = 3] = "GreaterEqual";
    FungibleConditionCode[FungibleConditionCode["Less"] = 4] = "Less";
    FungibleConditionCode[FungibleConditionCode["LessEqual"] = 5] = "LessEqual";
})(FungibleConditionCode || (FungibleConditionCode = {}));
var NonFungibleConditionCode;
(function (NonFungibleConditionCode) {
    NonFungibleConditionCode[NonFungibleConditionCode["Sends"] = 16] = "Sends";
    NonFungibleConditionCode[NonFungibleConditionCode["DoesNotSend"] = 17] = "DoesNotSend";
})(NonFungibleConditionCode || (NonFungibleConditionCode = {}));
var PostConditionPrincipalID;
(function (PostConditionPrincipalID) {
    PostConditionPrincipalID[PostConditionPrincipalID["Origin"] = 1] = "Origin";
    PostConditionPrincipalID[PostConditionPrincipalID["Standard"] = 2] = "Standard";
    PostConditionPrincipalID[PostConditionPrincipalID["Contract"] = 3] = "Contract";
})(PostConditionPrincipalID || (PostConditionPrincipalID = {}));
var AssetType;
(function (AssetType) {
    AssetType[AssetType["STX"] = 0] = "STX";
    AssetType[AssetType["Fungible"] = 1] = "Fungible";
    AssetType[AssetType["NonFungible"] = 2] = "NonFungible";
})(AssetType || (AssetType = {}));
var TxRejectedReason;
(function (TxRejectedReason) {
    TxRejectedReason["Serialization"] = "Serialization";
    TxRejectedReason["Deserialization"] = "Deserialization";
    TxRejectedReason["SignatureValidation"] = "SignatureValidation";
    TxRejectedReason["FeeTooLow"] = "FeeTooLow";
    TxRejectedReason["BadNonce"] = "BadNonce";
    TxRejectedReason["NotEnoughFunds"] = "NotEnoughFunds";
    TxRejectedReason["NoSuchContract"] = "NoSuchContract";
    TxRejectedReason["NoSuchPublicFunction"] = "NoSuchPublicFunction";
    TxRejectedReason["BadFunctionArgument"] = "BadFunctionArgument";
    TxRejectedReason["ContractAlreadyExists"] = "ContractAlreadyExists";
    TxRejectedReason["PoisonMicroblocksDoNotConflict"] = "PoisonMicroblocksDoNotConflict";
    TxRejectedReason["PoisonMicroblockHasUnknownPubKeyHash"] = "PoisonMicroblockHasUnknownPubKeyHash";
    TxRejectedReason["PoisonMicroblockIsInvalid"] = "PoisonMicroblockIsInvalid";
    TxRejectedReason["BadAddressVersionByte"] = "BadAddressVersionByte";
    TxRejectedReason["NoCoinbaseViaMempool"] = "NoCoinbaseViaMempool";
    TxRejectedReason["ServerFailureNoSuchChainTip"] = "ServerFailureNoSuchChainTip";
    TxRejectedReason["TooMuchChaining"] = "TooMuchChaining";
    TxRejectedReason["ConflictingNonceInMempool"] = "ConflictingNonceInMempool";
    TxRejectedReason["BadTransactionVersion"] = "BadTransactionVersion";
    TxRejectedReason["TransferRecipientCannotEqualSender"] = "TransferRecipientCannotEqualSender";
    TxRejectedReason["TransferAmountMustBePositive"] = "TransferAmountMustBePositive";
    TxRejectedReason["ServerFailureDatabase"] = "ServerFailureDatabase";
    TxRejectedReason["EstimatorError"] = "EstimatorError";
    TxRejectedReason["TemporarilyBlacklisted"] = "TemporarilyBlacklisted";
    TxRejectedReason["ServerFailureOther"] = "ServerFailureOther";
})(TxRejectedReason || (TxRejectedReason = {}));

function createLPString(content, lengthPrefixBytes, maxLengthBytes) {
    const prefixLength = 1;
    const maxLength = MAX_STRING_LENGTH_BYTES;
    if (exceedsMaxLengthBytes(content, maxLength)) {
        throw new Error(`String length exceeds maximum bytes ${maxLength}`);
    }
    return {
        type: StacksMessageType.LengthPrefixedString,
        content,
        lengthPrefixBytes: prefixLength,
        maxLengthBytes: maxLength,
    };
}

var ClarityType;
(function (ClarityType) {
    ClarityType[ClarityType["Int"] = 0] = "Int";
    ClarityType[ClarityType["UInt"] = 1] = "UInt";
    ClarityType[ClarityType["Buffer"] = 2] = "Buffer";
    ClarityType[ClarityType["BoolTrue"] = 3] = "BoolTrue";
    ClarityType[ClarityType["BoolFalse"] = 4] = "BoolFalse";
    ClarityType[ClarityType["PrincipalStandard"] = 5] = "PrincipalStandard";
    ClarityType[ClarityType["PrincipalContract"] = 6] = "PrincipalContract";
    ClarityType[ClarityType["ResponseOk"] = 7] = "ResponseOk";
    ClarityType[ClarityType["ResponseErr"] = 8] = "ResponseErr";
    ClarityType[ClarityType["OptionalNone"] = 9] = "OptionalNone";
    ClarityType[ClarityType["OptionalSome"] = 10] = "OptionalSome";
    ClarityType[ClarityType["List"] = 11] = "List";
    ClarityType[ClarityType["Tuple"] = 12] = "Tuple";
    ClarityType[ClarityType["StringASCII"] = 13] = "StringASCII";
    ClarityType[ClarityType["StringUTF8"] = 14] = "StringUTF8";
})(ClarityType || (ClarityType = {}));

class TransactionError extends Error {
    constructor(message) {
        super(message);
        this.message = message;
        this.name = this.constructor.name;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
class SerializationError extends TransactionError {
    constructor(message) {
        super(message);
    }
}

function serializeAddress(address) {
    const bytesArray = [];
    bytesArray.push(hexToBytes(intToHex(address.version, 1)));
    bytesArray.push(hexToBytes(address.hash160));
    return concatArray(bytesArray);
}
function serializePrincipal(principal) {
    const bytesArray = [];
    bytesArray.push(principal.prefix);
    bytesArray.push(serializeAddress(principal.address));
    if (principal.prefix === PostConditionPrincipalID.Contract) {
        bytesArray.push(serializeLPString(principal.contractName));
    }
    return concatArray(bytesArray);
}
function serializeLPString(lps) {
    const bytesArray = [];
    const contentBytes = utf8ToBytes(lps.content);
    const length = contentBytes.byteLength;
    bytesArray.push(hexToBytes(intToHex(length, lps.lengthPrefixBytes)));
    bytesArray.push(contentBytes);
    return concatArray(bytesArray);
}
function serializeAssetInfo(info) {
    const bytesArray = [];
    bytesArray.push(serializeAddress(info.address));
    bytesArray.push(serializeLPString(info.contractName));
    bytesArray.push(serializeLPString(info.assetName));
    return concatArray(bytesArray);
}
function serializePostCondition(postCondition) {
    const bytesArray = [];
    bytesArray.push(postCondition.conditionType);
    bytesArray.push(serializePrincipal(postCondition.principal));
    if (postCondition.conditionType === PostConditionType.Fungible ||
        postCondition.conditionType === PostConditionType.NonFungible) {
        bytesArray.push(serializeAssetInfo(postCondition.assetInfo));
    }
    if (postCondition.conditionType === PostConditionType.NonFungible) {
        bytesArray.push(serializeCV(postCondition.assetName));
    }
    bytesArray.push(postCondition.conditionCode);
    if (postCondition.conditionType === PostConditionType.STX ||
        postCondition.conditionType === PostConditionType.Fungible) {
        if (postCondition.amount > BigInt('0xffffffffffffffff'))
            throw new SerializationError('The post-condition amount may not be larger than 8 bytes');
        bytesArray.push(intToBytes(postCondition.amount, false, 8));
    }
    return concatArray(bytesArray);
}

function bytesWithTypeID(typeId, bytes) {
    return concatArray([typeId, bytes]);
}
function serializeBoolCV(value) {
    return new Uint8Array([value.type]);
}
function serializeOptionalCV(cv) {
    if (cv.type === ClarityType.OptionalNone) {
        return new Uint8Array([cv.type]);
    }
    else {
        return bytesWithTypeID(cv.type, serializeCV(cv.value));
    }
}
function serializeBufferCV(cv) {
    const length = new Uint8Array(4);
    writeUInt32BE(length, cv.buffer.length, 0);
    return bytesWithTypeID(cv.type, concatBytes(length, cv.buffer));
}
function serializeIntCV(cv) {
    const bytes = bigIntToBytes(toTwos(cv.value, BigInt(CLARITY_INT_SIZE)), CLARITY_INT_BYTE_SIZE);
    return bytesWithTypeID(cv.type, bytes);
}
function serializeUIntCV(cv) {
    const bytes = bigIntToBytes(cv.value, CLARITY_INT_BYTE_SIZE);
    return bytesWithTypeID(cv.type, bytes);
}
function serializeStandardPrincipalCV(cv) {
    return bytesWithTypeID(cv.type, serializeAddress(cv.address));
}
function serializeContractPrincipalCV(cv) {
    return bytesWithTypeID(cv.type, concatBytes(serializeAddress(cv.address), serializeLPString(cv.contractName)));
}
function serializeResponseCV(cv) {
    return bytesWithTypeID(cv.type, serializeCV(cv.value));
}
function serializeListCV(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    writeUInt32BE(length, cv.list.length, 0);
    bytesArray.push(length);
    for (const value of cv.list) {
        const serializedValue = serializeCV(value);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID(cv.type, concatArray(bytesArray));
}
function serializeTupleCV(cv) {
    const bytesArray = [];
    const length = new Uint8Array(4);
    writeUInt32BE(length, Object.keys(cv.data).length, 0);
    bytesArray.push(length);
    const lexicographicOrder = Object.keys(cv.data).sort((a, b) => a.localeCompare(b));
    for (const key of lexicographicOrder) {
        const nameWithLength = createLPString(key);
        bytesArray.push(serializeLPString(nameWithLength));
        const serializedValue = serializeCV(cv.data[key]);
        bytesArray.push(serializedValue);
    }
    return bytesWithTypeID(cv.type, concatArray(bytesArray));
}
function serializeStringCV(cv, encoding) {
    const bytesArray = [];
    const str = encoding == 'ascii' ? asciiToBytes(cv.data) : utf8ToBytes(cv.data);
    const len = new Uint8Array(4);
    writeUInt32BE(len, str.length, 0);
    bytesArray.push(len);
    bytesArray.push(str);
    return bytesWithTypeID(cv.type, concatArray(bytesArray));
}
function serializeStringAsciiCV(cv) {
    return serializeStringCV(cv, 'ascii');
}
function serializeStringUtf8CV(cv) {
    return serializeStringCV(cv, 'utf8');
}
function serializeCV(value) {
    switch (value.type) {
        case ClarityType.BoolTrue:
        case ClarityType.BoolFalse:
            return serializeBoolCV(value);
        case ClarityType.OptionalNone:
        case ClarityType.OptionalSome:
            return serializeOptionalCV(value);
        case ClarityType.Buffer:
            return serializeBufferCV(value);
        case ClarityType.UInt:
            return serializeUIntCV(value);
        case ClarityType.Int:
            return serializeIntCV(value);
        case ClarityType.PrincipalStandard:
            return serializeStandardPrincipalCV(value);
        case ClarityType.PrincipalContract:
            return serializeContractPrincipalCV(value);
        case ClarityType.ResponseOk:
        case ClarityType.ResponseErr:
            return serializeResponseCV(value);
        case ClarityType.List:
            return serializeListCV(value);
        case ClarityType.Tuple:
            return serializeTupleCV(value);
        case ClarityType.StringASCII:
            return serializeStringAsciiCV(value);
        case ClarityType.StringUTF8:
            return serializeStringUtf8CV(value);
        default:
            throw new SerializationError('Unable to serialize. Invalid Clarity Value.');
    }
}

const exceedsMaxLengthBytes = (string, maxLengthBytes) => string ? utf8ToBytes(string).length > maxLengthBytes : false;

var Fe=Object.defineProperty,Be=Object.defineProperties;var We=Object.getOwnPropertyDescriptors;var w=Object.getOwnPropertySymbols;var le=Object.prototype.hasOwnProperty,ge=Object.prototype.propertyIsEnumerable;var pe=(e,t,o)=>t in e?Fe(e,t,{enumerable:true,configurable:true,writable:true,value:o}):e[t]=o,u=(e,t)=>{for(var o in t||(t={}))le.call(t,o)&&pe(e,o,t[o]);if(w)for(var o of w(t))ge.call(t,o)&&pe(e,o,t[o]);return e},M=(e,t)=>Be(e,We(t));var Se=(e,t)=>{var o={};for(var s in e)le.call(e,s)&&t.indexOf(s)<0&&(o[s]=e[s]);if(e!=null&&w)for(var s of w(e))t.indexOf(s)<0&&ge.call(e,s)&&(o[s]=e[s]);return o};var I=class e extends Error{constructor(o,s,n,r){super(o);this.message=o;this.code=s;this.data=n;this.cause=r;this.name="JsonRpcError",this.message=o,this.code=s,this.data=n,this.cause=r;}static fromResponse(o){return new e(o.message,o.code,o.data)}toString(){return `${this.name} (${this.code}): ${this.message}${this.data?`: ${JSON.stringify(this.data)}`:""}`}},fe=(i=>(i[i.ParseError=-32700]="ParseError",i[i.InvalidRequest=-32600]="InvalidRequest",i[i.MethodNotFound=-32601]="MethodNotFound",i[i.InvalidParams=-32602]="InvalidParams",i[i.InternalError=-32603]="InternalError",i[i.UserRejection=-32e3]="UserRejection",i[i.MethodAddressMismatch=-32001]="MethodAddressMismatch",i[i.MethodAccessDenied=-32002]="MethodAccessDenied",i[i.UnknownError=-31e3]="UnknownError",i[i.UserCanceled=-31001]="UserCanceled",i))(fe||{});var Ae="asigna-stx",U=(e,t)=>new Promise(o=>{function s(n){n.data.source===Ae&&n.data[t]&&(o(n.data[t]),window.removeEventListener("message",s));}window.addEventListener("message",s),window.top.postMessage(Ze(e,t),"*");}),qe={authenticationRequest:async e=>U(e,"authenticationRequest"),transactionRequest:async e=>U(e,"transactionRequest"),request:async(e,t)=>U(t,e)},Ze=(e,t)=>({source:Ae,[t]:e}),ye=()=>{if(typeof window=="undefined")return;window.top!==window.self&&(window.AsignaProvider=qe);};ye();var De=[{id:"LeatherProvider",name:"Leather",icon:"data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTI4IiBoZWlnaHQ9IjEyOCIgdmlld0JveD0iMCAwIDEyOCAxMjgiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMjgiIGhlaWdodD0iMTI4IiByeD0iMjYuODM4NyIgZmlsbD0iIzEyMTAwRiIvPgo8cGF0aCBkPSJNNzQuOTE3MSA1Mi43MTE0QzgyLjQ3NjYgNTEuNTQwOCA5My40MDg3IDQzLjU4MDQgOTMuNDA4NyAzNy4zNzYxQzkzLjQwODcgMzUuNTAzMSA5MS44OTY4IDM0LjIxNTQgODkuNjg3MSAzNC4yMTU0Qzg1LjUwMDQgMzQuMjE1NCA3OC40MDYxIDQwLjUzNjggNzQuOTE3MSA1Mi43MTE0Wk0zOS45MTEgODMuNDk5MUMzMC4wMjU2IDgzLjQ5OTEgMjkuMjExNSA5My4zMzI0IDM5LjA5NjkgOTMuMzMyNEM0My41MTYzIDkzLjMzMjQgNDguODY2MSA5MS41NzY0IDUxLjY1NzMgODguNDE1N0M0Ny41ODY4IDg0LjkwMzggNDQuMjE0MSA4My40OTkxIDM5LjkxMSA4My40OTkxWk0xMDIuODI5IDc5LjI4NDhDMTAzLjQxIDk1Ljc5MDcgOTUuMDM2OSAxMDUuMDM5IDgwLjg0ODQgMTA1LjAzOUM3Mi40NzQ4IDEwNS4wMzkgNjguMjg4MSAxMDEuODc4IDU5LjMzMyA5Ni4wMjQ5QzU0LjY4MSAxMDEuMTc2IDQ1Ljg0MjMgMTA1LjAzOSAzOC41MTU0IDEwNS4wMzlDMTMuMjc4NSAxMDUuMDM5IDE0LjMyNTIgNzIuODQ2MyA0MC4wMjczIDcyLjg0NjNDNDUuMzc3MSA3Mi44NDYzIDQ5LjkxMjggNzQuMjUxMSA1NS43Mjc3IDc3Ljg4TDU5LjU2NTYgNjQuNDE3N0M0My43NDg5IDYwLjA4NjQgMzUuODQwNSA0Ny45MTE4IDQzLjYzMjYgMzAuNDY5M0g1Ni4xOTI5QzQ5LjIxNSA0Mi4wNTg2IDUzLjk4MzIgNTEuNjU3OCA2Mi44MjIgNTIuNzExNEM2Ny41OTAzIDM1LjczNzIgNzcuODI0NiAyMi41MDkgOTEuNDMxNiAyMi41MDlDOTkuMTA3NCAyMi41MDkgMTA1LjE1NSAyNy41NDI4IDEwNS4xNTUgMzYuNjczN0MxMDUuMTU1IDUxLjMwNjYgODYuMDgxOSA2My4yNDcxIDcxLjY2MDcgNjQuNDE3N0w2NS43Mjk1IDg1LjM3MjFDNzIuNDc0OCA5My4yMTUzIDkxLjE5OSAxMDAuODI0IDkxLjE5OSA3OS4yODQ4SDEwMi44MjlaIiBmaWxsPSIjRjVGMUVEIi8+Cjwvc3ZnPgo=",webUrl:"https://leather.io",chromeWebStoreUrl:"https://chrome.google.com/webstore/detail/hiro-wallet/ldinpeekobnhjjdofggfgjlcehhmanlj",mozillaAddOnsUrl:"https://leather.io/install-extension"},{id:"XverseProviders.BitcoinProvider",name:"Xverse Wallet",icon:"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2MDAiIGhlaWdodD0iNjAwIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGZpbGw9IiMxNzE3MTciIGQ9Ik0wIDBoNjAwdjYwMEgweiIvPjxwYXRoIGZpbGw9IiNGRkYiIGZpbGwtcnVsZT0ibm9uemVybyIgZD0iTTQ0MCA0MzUuNHYtNTFjMC0yLS44LTMuOS0yLjItNS4zTDIyMCAxNjIuMmE3LjYgNy42IDAgMCAwLTUuNC0yLjJoLTUxLjFjLTIuNSAwLTQuNiAyLTQuNiA0LjZ2NDcuM2MwIDIgLjggNCAyLjIgNS40bDc4LjIgNzcuOGE0LjYgNC42IDAgMCAxIDAgNi41bC03OSA3OC43Yy0xIC45LTEuNCAyLTEuNCAzLjJ2NTJjMCAyLjQgMiA0LjUgNC42IDQuNUgyNDljMi42IDAgNC42LTIgNC42LTQuNlY0MDVjMC0xLjIuNS0yLjQgMS40LTMuM2w0Mi40LTQyLjJhNC42IDQuNiAwIDAgMSA2LjQgMGw3OC43IDc4LjRhNy42IDcuNiAwIDAgMCA1LjQgMi4yaDQ3LjVjMi41IDAgNC42LTIgNC42LTQuNloiLz48cGF0aCBmaWxsPSIjRUU3QTMwIiBmaWxsLXJ1bGU9Im5vbnplcm8iIGQ9Ik0zMjUuNiAyMjcuMmg0Mi44YzIuNiAwIDQuNiAyLjEgNC42IDQuNnY0Mi42YzAgNCA1IDYuMSA4IDMuMmw1OC43LTU4LjVjLjgtLjggMS4zLTIgMS4zLTMuMnYtNTEuMmMwLTIuNi0yLTQuNi00LjYtNC42TDM4NCAxNjBjLTEuMiAwLTIuNC41LTMuMyAxLjNsLTU4LjQgNTguMWE0LjYgNC42IDAgMCAwIDMuMiA3LjhaIi8+PC9nPjwvc3ZnPg==",webUrl:"https://xverse.app",chromeWebStoreUrl:"https://chrome.google.com/webstore/detail/xverse-wallet/idnnbdplmphpflfnlkomgpfbpcgelopg",googlePlayStoreUrl:"https://play.google.com/store/apps/details?id=com.secretkeylabs.xverse",iOSAppStoreUrl:"https://apps.apple.com/app/xverse-bitcoin-web3-wallet/id1552272513",mozillaAddOnsUrl:"https://www.xverse.app/download"},{id:"AsignaProvider",name:"Asigna Multisig",icon:"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgZmlsbD0ibm9uZSI+PHBhdGggZmlsbD0iIzAwMDEwMCIgZD0iTTAgMGgzMnYzMkgweiIvPjxwYXRoIGZpbGw9InVybCgjYSkiIGQ9Ik0xNS4xMSA1LjU1YTMgMyAwIDAgMC0xLjgyIDEuM2wtLjA1LjA4LS40My43Mi0uMDcuMTEtLjUuODUtLjA1LjA5LTEuMjkgMi4xOC0uMDQuMDctLjQ3LjgtLjA2LjEtLjQ2Ljc4LS4wNy4xMS0xLjYzIDIuNzYtLjA3LjExLS4zOC42Ni0uMDUuMDgtLjczIDEuMjQtLjM1LjYtLjQuNjctLjA1LjA5TDUuMSAyMC43bC0uMTEuMTgtLjE0LjIzLS4wNy4xMy0uMzMuNTUtLjA0LjA3di4wMWExLjI2IDEuMjYgMCAwIDAtLjE0LjQ3IDEuMzEgMS4zMSAwIDAgMCAxLjI0IDEuNGgxLjVsLjA1LS4wNi4wNC0uMDYuODctMS4yMS4wNS0uMDguNzctMS4wNy4wNS0uMDcuNC0uNTcuMDUtLjA2LjI0LS4zNGExLjUyIDEuNTIgMCAwIDEgMS4zOS0uNjIgMS41IDEuNSAwIDAgMSAuNjQuMiAxLjQ3IDEuNDcgMCAwIDEgLjczIDEuMjcgMS40NCAxLjQ0IDAgMCAxLS4yNy44NGwtLjYzLjg4LS4wNS4wNy0uMzIuNDUtLjA2LjA4LS4wOC4xMi0uMTIuMTYtLjA1LjA4aDIuMTNhMi4zMiAyLjMyIDAgMCAwIDEuNzctLjk2bDEuMTgtMS42My43Ny0xLjA4IDEuMy0xLjhhMS4yNCAxLjI0IDAgMCAxIC41NS0uNDNsLjA4LS4wM2ExLjMgMS4zIDAgMCAxIC4zLS4wNiAxLjI4IDEuMjggMCAwIDEgMS4xNS41NGwuMTEuMmExLjEzIDEuMTMgMCAwIDEgLjEuNDEgMS4xOSAxLjE5IDAgMCAxLS4yMy43N2wtLjAzLjA1LS41Ny44LS43Ljk4LS4yNy4zN2ExLjIyIDEuMjIgMCAwIDAtLjIuNSAxLjA1IDEuMDUgMCAwIDAtLjAyLjIzdi4wNmExLjE3IDEuMTcgMCAwIDAgLjE0LjQzbC4wMi4wNS4wNy4xYTEuNDQgMS40NCAwIDAgMCAuMS4xMWwuMDUuMDYuMDEuMDFhMS44IDEuOCAwIDAgMCAuMTQuMWMwIC4wMi4wMi4wMy4wNC4wM2ExIDEgMCAwIDAgLjA4LjA1bC4wNy4wNGExLjI1IDEuMjUgMCAwIDAgLjUuMWg2LjljLjEgMCAuMi0uMDEuMjktLjAzbC4wNi0uMDJhMS4yNyAxLjI3IDAgMCAwIC4yNy0uMS41Ny41NyAwIDAgMCAuMDctLjAzIDEuMjEgMS4yMSAwIDAgMCAuMjYtLjE5bC4wOC0uMDdhLjkyLjkyIDAgMCAwIC4xNS0uMTkgMS41NSAxLjU1IDAgMCAwIC4wOS0uMTdsLjAyLS4wNWExLjIyIDEuMjIgMCAwIDAgLjA4LS4yNnYtLjA0bC4wMi0uMDh2LS4wOGExLjMyIDEuMzIgMCAwIDAtLjItLjc0bC0xLjYtMi42NC0uMDYtLjEtLjItLjMyLS4zMy0uNTR2LS4wMWwtLjA1LS4wOC0xLjMtMi4xNS0uMDctLjEtLjA0LS4wNi0uOC0xLjMyLS4wNC0uMDctLjItLjM0LS4xLS4xNC0uMS0uMTYtLjUzLS45LS4xMy0uMi0uMDktLjE0LTIuMTctMy41Ny0uMDQtLjA3LS43Mi0xLjE5LS4wNS0uMDctLjQtLjY1YTIuNjUgMi42NSAwIDAgMC0uMy0uNCAyLjk2IDIuOTYgMCAwIDAtLjk3LS43NCAzLjA0IDMuMDQgMCAwIDAtMS4zLS4zYy0uMjUgMC0uNS4wNC0uNzQuMVoiLz48cGF0aCBmaWxsPSJ1cmwoI2IpIiBkPSJNMTkgMTYuM2E1LjQ1IDUuNDUgMCAwIDAtLjgzIDEuNTZsLS4wNC4xNWExLjM2IDEuMzYgMCAwIDEgLjI4LS4xNiAxLjI0IDEuMjQgMCAwIDEgLjM4LS4wOGguMWExLjI4IDEuMjggMCAwIDEgMS4wNS41NGMuMDQuMDYuMDguMTMuMS4yYTEuMjQgMS4yNCAwIDAgMSAuMDkuMjcgMS4xOSAxLjE5IDAgMCAxLS4yLjkxbC0uMDQuMDUtLjU3Ljc5LS43Ljk5LS4yNy4zN2ExLjIzIDEuMjMgMCAwIDAtLjIuNDIgMS4wNiAxLjA2IDAgMCAwLS4wMi4zMXYuMDZhMS4xNyAxLjE3IDAgMCAwIC4xNi40Ny45My45MyAwIDAgMCAuMDcuMSAxLjUgMS41IDAgMCAwIC4xLjEybC4wNS4wNmguMDFhMS45NCAxLjk0IDAgMCAwIC4wOS4wOCAxIDEgMCAwIDAgLjE3LjFsLjA3LjA0YTEuMjUgMS4yNSAwIDAgMCAuNS4xaDYuOWMuMSAwIC4yIDAgLjI4LS4wMmwuMDctLjAyYTEuMzIgMS4zMiAwIDAgMCAuMzQtLjEzbC4xNi0uMS4wMy0uMDNhMS4yOSAxLjI5IDAgMCAwIC4yLS4yIDIuNDMgMi40MyAwIDAgMCAuMTItLjE3Yy4wMy0uMDMuMDUtLjA4LjA3LS4xMmwuMDItLjA1YTEuMjEgMS4yMSAwIDAgMCAuMDktLjN2LS4wOGwuMDEtLjA5YTEuMzIgMS4zMiAwIDAgMC0uMi0uNzNsLTEuNi0yLjY0LS4wNi0uMS0uMi0uMzItLjMzLS41NHYtLjAybC0uMDUtLjA3LTEuMy0yLjE1LS4xMi0uMDctLjA3LS4wNGE0Ljk0IDQuOTQgMCAwIDAtMi40Ni0uNjdjLTEuMDMgMC0xLjc2LjU3LTIuMjYgMS4yWiIvPjxwYXRoIGZpbGw9IiNmZmYiIGQ9Ik0xMi4yOSAyMS4wOGMwIC4yOS0uMDkuNTgtLjI3Ljg0bC0xLjMxIDEuODRIN2wyLjUyLTMuNTNhMS41NCAxLjU0IDAgMCAxIDIuMS0uMzZjLjQzLjI4LjY2Ljc0LjY2IDEuMloiLz48cGF0aCBmaWxsPSIjMDAwIiBkPSJNMTEuMTYgMjEuMjVhLjU2LjU2IDAgMCAxLS41Ny41NS41Ni41NiAwIDAgMS0uNTctLjU2LjU2LjU2IDAgMCAxIC41Ny0uNTUuNTYuNTYgMCAwIDEgLjU3LjU2WiIvPjxkZWZzPjxsaW5lYXJHcmFkaWVudCBpZD0iYSIgeDE9IjE1LjIzIiB4Mj0iMTkuMyIgeTE9IjI1Ljc4IiB5Mj0iNi4xMSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIHN0b3AtY29sb3I9IiM2NTIyRjQiLz48c3RvcCBvZmZzZXQ9Ii41NSIgc3RvcC1jb2xvcj0iIzlCNkJGRiIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iI0E1ODVGRiIvPjwvbGluZWFyR3JhZGllbnQ+PGxpbmVhckdyYWRpZW50IGlkPSJiIiB4MT0iMjIuNTkiIHgyPSIyNC44IiB5MT0iMjQuNzEiIHkyPSIxNS41MyIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIHN0b3AtY29sb3I9IiM0MjFGOEIiLz48c3RvcCBvZmZzZXQ9Ii41NSIgc3RvcC1jb2xvcj0iIzcyMzBGRiIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzk3NzNGRiIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjwvc3ZnPg==",webUrl:"https://asigna.io",chromeWebStoreUrl:"https://stx.asigna.io/"},{id:"FordefiProviders.UtxoProvider",name:"Fordefi",icon:"data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDIiIGhlaWdodD0iNDIiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHBhdGggZmlsbD0iIzEwMTExNCIgZD0iTTAgMGg0MnY0MkgweiIvPgogIDxwYXRoIGQ9Ik0xOS40NyAyNi44OUg1djMuNTdhNC41NyA0LjU3IDAgMCAwIDQuNTggNC41N2g1LjgzbDQuMDYtOC4xNFoiIGZpbGw9IiM3OTk0RkYiLz4KICA8cGF0aCBkPSJNNSAxNy40aDI3LjU4bC0zLjIgNi43OEg1VjE3LjRaIiBmaWxsPSIjNDg2REZGIi8+CiAgPHBhdGggZD0iTTE0LjY3IDdINXY3LjY4aDMzVjdoLTkuNjd2NS43NGgtMlY3aC05LjY3djUuNzRoLTEuOTlWN1oiIGZpbGw9IiM1Q0QxRkEiLz4KPC9zdmc+Cg==",webUrl:"https://www.fordefi.com/",chromeWebStoreUrl:"https://chromewebstore.google.com/detail/fordefi/hcmehenccjdmfbojapcbcofkgdpbnlle"}];var z="@stacks/connect",$e={addresses:{stx:[],btc:[]},version:"0.0.1"},Ie=e=>[...new Map(e.map(o=>[o.address,o])).values()].map(s=>{var o=Se(s,[]);return "publicKey"in o&&delete o.publicKey,"derivationPath"in o&&delete o.derivationPath,"tweakedPublicKey"in o&&delete o.tweakedPublicKey,o});function xe(e){try{let o=G()||$e,s=M(u({},o),{updatedAt:Date.now(),addresses:u(u({},o.addresses),e.addresses&&{stx:e.addresses.stx&&Ie([...o.addresses.stx,...e.addresses.stx]),btc:e.addresses.btc&&Ie([...o.addresses.btc,...e.addresses.btc])})});localStorage.setItem(z,bytesToHex$2(utf8ToBytes$2(JSON.stringify(s))));}catch(t){console.warn("Failed to store data in localStorage:",t);}}function me(){try{localStorage.removeItem(z);}catch(e){console.warn("Failed to clear localStorage:",e);}}function G(){try{let e=localStorage.getItem(z);return e?JSON.parse(bytesToUtf8(hexToBytes$2(e))):null}catch(e){return console.warn("Failed to get data from localStorage:",e),null}}function et(){clearSelectedProviderId(),me(),new T().store.deleteSessionData();}function tt(){let e=G();return (e==null?void 0:e.addresses.stx.length)>0||(e==null?void 0:e.addresses.btc.length)>0}async function O(e,t,o){var s;try{let n=await e.request(t,o);if("error"in n)throw I.fromResponse(n.error);return n.result}catch(n){if(n instanceof I)throw n;if("jsonrpc"in n)throw I.fromResponse(n.error);let r=(s=n.code)!=null?s:-31e3;throw new I(n.message,r,n.data,n)}}function dt(e){return e?async function(o,s,n){let r=await O(o,s,n);if((s==="getAddresses"||s==="wallet_connect")&&"addresses"in r){let{stx:a,btc:c}=At(r.addresses).reduce((d,f)=>(d[f.address.startsWith("S")?"stx":"btc"].push(f),d),{stx:[],btc:[]});xe({addresses:{stx:a,btc:c}});}return r}:O}async function P(...e){let{options:t,method:o,params:s}=ut(e),n=Object.assign({provider:getProvider(),defaultProviders:De,forceWalletSelect:false,persistWalletSelect:true,enableOverrides:true,enableLocalStorage:true},gt(t)),r=St(n.enableOverrides,dt(n.enableLocalStorage));if(n.provider&&!n.forceWalletSelect){let{method:a,params:c}=Y(n.provider,o,s,n.enableOverrides);return await r(n.provider,a,Q(c))}if(typeof window!="undefined")return defineCustomElements(),new Promise((a,c)=>{let d=document.createElement("connect-modal");d.defaultProviders=Le(n.approvedProviderIds,n.defaultProviders),d.installedProviders=Le(n.approvedProviderIds,getInstalledProviders(n.defaultProviders));let f=document.body.style.overflow;document.body.style.overflow="hidden";let i=()=>{d.remove(),document.body.style.overflow=f;};d.callback=m=>{i();let L=getProviderFromId(m),{method:y,params:j}=Y(L,o,s,n.enableOverrides),v=ft(n.persistWalletSelect,m);a(r(L,y,Q(j)).then(v));},d.cancelCallback=()=>{i(),c(new I("User canceled the request",-31001));},document.body.appendChild(d);let x=m=>{m.key==="Escape"&&(document.removeEventListener("keydown",x),d.remove(),c(new I("User canceled the request",-31001)));};document.addEventListener("keydown",x);})}function ut(e){return typeof e[0]=="string"?{method:e[0],params:e[1]}:{options:e[0],method:e[1],params:e[2]}}function Le(e,t){return e?t.filter(o=>e.includes(o.id)):t}function Mt(e){let t=e&&"network"in e?{network:e.network}:void 0;return P(M(u({},e),{forceWalletSelect:true}),"getAddresses",t)}function S(e,t,o){return (s,n)=>{if(!n)throw new Error("[Connect] No installed Stacks wallet found");let r=t(s),a=s,{method:c,params:d}=Y(n,e,r);O(n,c,Q(d)).then(f=>{var x;let i=o(f);(x=a.onFinish)==null||x.call(a,i);}).catch(a.onCancel);}}function h(e){return pt(e)||lt(e)}function pt(e){return "signMultipleTransactions"in e&&"createRepeatInscriptions"in e&&!(e!=null&&e.isLeather)&&!(e!=null&&e.isFordefi)}function lt(e){return "isFordefi"in e&&!!e.isFordefi}function Ne(e){return "isLeather"in e&&!!e.isLeather}function gt(e){if(e===void 0)return {};let t={};for(let[o,s]of Object.entries(e))s!==void 0&&(t[o]=s);return t}function St(e,t){return e?async(o,s,n)=>{let r=await t(o,s,n),a=u({},r);return r!==null&&"txId"in r&&r.txId&&!("txid"in a)&&(a.txid=r.txId),r!==null&&"hex"in r&&r.hex&&typeof r.hex=="string"&&!("psbt"in a)&&(a.psbt=base64.encode(hexToBytes$2(r.hex))),a}:t}function Y(e,t,o,s=true){if(!s)return {method:t,params:o};if(h(e)&&["getAddresses","stx_getAddresses"].includes(t))return {method:"wallet_connect",params:o};if(h(e)&&t==="sendTransfer"){let n=M(u({},o),{recipients:o.recipients.map(r=>M(u({},r),{amount:Number(r.amount)})),network:void 0});return {method:t,params:n}}if(h(e)&&t==="signPsbt"){let n=o.signInputs;if(!n)return {method:t,params:o};let r={};for(let c of n)typeof c!="number"&&c.address&&(r[c.address]||(r[c.address]=[]),r[c.address].push(c.index));let a={psbt:o.psbt,signInputs:r,broadcast:o.broadcast};return {method:t,params:a}}if(!h(e)&&t==="stx_signMessage"){let n=u({},o);return delete n.publicKey,{method:t,params:n}}if(Ne(e)&&t==="sendTransfer"){let n=M(u({},o),{recipients:o.recipients.map(r=>M(u({},r),{amount:r.amount.toString()}))});return {method:t,params:n}}if(Ne(e)&&t==="signPsbt"){let n={hex:bytesToHex$2(base64.decode(o.psbt)),signAtIndex:o.signInputs.map(r=>typeof r=="number"?r:r.index),allowedSighash:o.allowedSighash,broadcast:o.broadcast,network:o.network};return {method:t,params:n}}return {method:t,params:o}}var Pe=["stx-postcondition","ft-postcondition","nft-postcondition"];function Q(e){if(!e||typeof e!="object")return e;let t=u({},e);for(let[o,s]of Object.entries(e)){if(typeof s=="bigint"){t[o]=s.toString();continue}if(s){if(Array.isArray(s)){t[o]=s.map(n=>typeof n=="bigint"?n.toString():!n||typeof n!="object"||!("type"in n)?n:Pe.includes(n.type)?postConditionToHex(n):serialize(n));continue}typeof s=="object"&&"type"in s&&(t[o]=Pe.includes(s.type)?postConditionToHex(s):serialize(s));}}return t}function ft(e,t){return function(s){if(e)try{setSelectedProviderId(t);}catch(n){}return s}}function At(e){return e.slice().sort((t,o)=>{let s="purpose"in t&&t.purpose==="payment",n="purpose"in o&&o.purpose==="payment";return s&&!n?-1:!s&&n?1:0})}var vo="https://app.blockstack.org";typeof window!="undefined"&&(window.__CONNECT_VERSION__="__VERSION__");var Uo=()=>{let e=navigator.userAgent;return /android/i.test(e)||/iPad|iPhone|iPod/.test(e)?true:/windows phone/i.test(e)},he=async(e,t)=>{var a,c,d,f,i,x;let{onFinish:o,onCancel:s,userSession:n}=e,r=Oe(n);r.isUserSignedIn()&&r.signUserOut();try{let L=await P({provider:t,forceWalletSelect:!0},"getAddresses"),y=r.store.getSessionData();(a=y.userData)!=null||(y.userData={profile:{}}),(d=(c=y.userData).profile)!=null||(c.profile={}),(i=(f=y.userData.profile).stxAddress)!=null||(f.stxAddress={mainnet:"",testnet:""});let j=L.addresses.find(A=>(A==null?void 0:A.symbol)==="STX"||A.address.startsWith("S")).address.toUpperCase(),v=j[1]==="P"||j[1]==="M";Object.assign(y.userData.profile.stxAddress,{[v?"mainnet":"testnet"]:j});let de=(x=L.addresses.find(A=>{var ue;return (ue=A==null?void 0:A.address)!=null&&ue.startsWith("S")?!1:A.purpose==="payment"?!0:we(A==null?void 0:A.address)?L.addresses.every(N=>{var Me;return ((Me=N==null?void 0:N.address)==null?void 0:Me.startsWith("S"))||we(N==null?void 0:N.address)}):!0}))==null?void 0:x.address;de&&(y.userData.profile.btcAddress=de),r.store.setSessionData(y),o==null||o({userSession:r,authResponsePayload:y.userData});}catch(m){console.error("[Connect] Error during auth request",m),s==null||s(m);}},yt="blockstack-session",E=class{constructor(t,o,s,n,r,a){}},T=class{constructor(t){t!=null&&t.appConfig&&(this.appConfig=t.appConfig),typeof window=="undefined"&&typeof self=="undefined"?this.store=new F:this.store=new B;}makeAuthRequestToken(){}generateAndStoreTransitKey(){}getAuthResponseToken(){}isSignInPending(){return false}isUserSignedIn(){return !!this.store.getSessionData().userData}async handlePendingSignIn(){return Promise.resolve(this.loadUserData())}loadUserData(){let t=this.store.getSessionData().userData;if(!t)throw new NoSessionDataError("No user data found. Did the user sign in?");return t}encryptContent(){}decryptContent(){}signUserOut(t){this.store.deleteSessionData(),t&&typeof location!="undefined"&&location.href&&(location.href=t);}},b=class{constructor(t){t&&this.setSessionData(t);}getSessionData(){throw new Error("Abstract class")}setSessionData(t){throw new Error("Abstract class")}deleteSessionData(){throw new Error("Abstract class")}},F=class extends b{constructor(t){super(t),this.sessionData||this.setSessionData({});}getSessionData(){if(!this.sessionData)throw new NoSessionDataError("No session data was found.");return this.sessionData}setSessionData(t){return this.sessionData=t,true}deleteSessionData(){return this.setSessionData({}),true}},B=class extends b{constructor(t){var s;super(t),this.key=typeof((s=t==null?void 0:t.storeOptions)==null?void 0:s.localStorageKey)=="string"?t.storeOptions.localStorageKey:yt,localStorage.getItem(this.key)||this.setSessionData({});}getSessionData(){let t=localStorage.getItem(this.key);if(!t)throw new NoSessionDataError("No session data was found in localStorage");return JSON.parse(t)}setSessionData(t){return localStorage.setItem(this.key,JSON.stringify(t)),true}deleteSessionData(){return localStorage.removeItem(this.key),this.setSessionData({}),true}},Oe=e=>e||new T,zo=async e=>(e=Oe(e),e.isUserSignedIn()?Promise.resolve(e.loadUserData()):Promise.resolve(null));function we(e){let t=["bc1p","tb1p","bcrt1p"],o=[62,62,64],s=t.findIndex(n=>e.startsWith(n));return s===-1?false:e.length===o[s]}var Dt=(s=>(s.ContractCall="contract_call",s.ContractDeploy="smart_contract",s.STXTransfer="token_transfer",s))(Dt||{}),It=(r=>(r.BUFFER="buffer",r.UINT="uint",r.INT="int",r.PRINCIPAL="principal",r.BOOL="bool",r))(It||{});var q=(r=>(r[r.DEFAULT=0]="DEFAULT",r[r.ALL=1]="ALL",r[r.NONE=2]="NONE",r[r.SINGLE=3]="SINGLE",r[r.ANYONECANPAY=128]="ANYONECANPAY",r))(q||{});function g(){return getProviderFromId(getSelectedProviderId())||window.StacksProvider||window.BlockstackProvider}function Nt(){return !!g()}function Re(e){return e?typeof e=="string"?StacksNetwork.fromName(e):"version"in e?e:"url"in e?new StacksMainnet({url:e.url}):e.transactionVersion===TransactionVersion$2.Mainnet?new StacksMainnet({url:e.client.baseUrl}):new StacksTestnet({url:e.client.baseUrl}):new StacksTestnet}function R(e,t){var o,s;return e instanceof t||((s=(o=e==null?void 0:e.constructor)==null?void 0:o.name)==null?void 0:s.toLowerCase())===t.name}function k(e){return e?typeof e=="string"?e:R(e,StacksMainnet)?"mainnet":R(e,StacksTestnet)?"testnet":R(e,StacksDevnet)||R(e,StacksMocknet)?"devnet":"coreApiUrl"in e?e.coreApiUrl:"url"in e?e.url:"transactionVersion"in e?e.transactionVersion===TransactionVersion$2.Mainnet?"mainnet":"testnet":"mainnet":"mainnet"}function D(e){if(typeof e.type=="string")return e;switch(e.type){case ClarityType.BoolFalse:return bool(false);case ClarityType.BoolTrue:return bool(true);case ClarityType.Int:return int(e.value);case ClarityType.UInt:return uint(e.value);case ClarityType.Buffer:return buffer(e.buffer);case ClarityType.StringASCII:return stringAscii(e.data);case ClarityType.StringUTF8:return stringUtf8(e.data);case ClarityType.List:return list(e.list.map(D));case ClarityType.Tuple:return tuple(Object.fromEntries(Object.entries(e.data).map(([o,s])=>[o,D(s)])));case ClarityType.OptionalNone:return none();case ClarityType.OptionalSome:return some(D(e.value));case ClarityType.ResponseErr:return error(D(e.value));case ClarityType.ResponseOk:return ok(D(e.value));case ClarityType.PrincipalContract:return contractPrincipal(stringify(e.address),e.contractName.content);case ClarityType.PrincipalStandard:return standardPrincipal(stringify(e.address));default:let t=e;throw new Error(`Unknown clarity type: ${t}`)}}function ke(e){return M(u({},e),{onFinish:void 0,onCancel:void 0})}function Pt(e){}var jt=async e=>{},wt="stx_updateProfile",H=e=>e,V=e=>e.profile;function ht(e,t=g()){S(wt,H,V)(e,t);}function Ot(e){}var Et=async e=>{},bt="stx_signMessage",K=e=>e,J=e=>e;function Rt(e,t=g()){S(bt,K,J)(e,t);}async function _t(e){}var vt="stx_signStructuredMessage",$=e=>({message:D(e.message),domain:D(e.domain)}),ee=e=>e;function Ut(e,t=g()){if(e.domain.type!==ClarityType.Tuple)throw new Error("Domain must be a tuple");S(vt,$,ee)(e,t);}var ze=e=>{let t=e;if(!t){let o=new E(["store_write"],document.location.href);t=new T({appConfig:o});}return t};function Yt(e){try{return ze(e).loadUserData().appPrivateKey}catch(t){return false}}var Qt=e=>{};function Ft(e){var d;let{stxAddress:t,userSession:o,network:s}=e;if(t)return t;if(!o||!s)return;let n=(d=o==null?void 0:o.loadUserData().profile)==null?void 0:d.stxAddress,r={[ChainId.Mainnet]:"mainnet",[ChainId.Testnet]:"testnet"},a=Re(s);return n==null?void 0:n[r[a.chainId]]}var Bt=async e=>{},Wt=async e=>{},qt=async e=>{},Zt=async e=>{},Xt="stx_callContract",te=e=>{var o;let t=(o=e.functionArgs)==null?void 0:o.map(s=>typeof s=="string"?deserialize(s):D(s)).map(s=>serialize(s));return M(u({},e),{contract:`${e.contractAddress}.${e.contractName}`,functionArgs:t,network:k(e.network),postConditionMode:Ye(e.postConditionMode),postConditions:Ge(e.postConditions),address:e.stxAddress})},oe=e=>({txId:e.txid,txRaw:e.transaction,stacksTransaction:deserializeTransaction(e.transaction)});function Ht(e,t=g()){S(Xt,te,oe)(e,t);}var Vt="stx_deployContract",se=e=>M(u({},e),{name:e.contractName,clarityCode:e.codeBody,network:k(e.network),postConditionMode:Ye(e.postConditionMode),postConditions:Ge(e.postConditions),address:e.stxAddress}),ne=e=>({txId:e.txid,txRaw:e.transaction,stacksTransaction:deserializeTransaction(e.transaction)});function Kt(e,t=g()){S(Vt,se,ne)(e,t);}var Jt="stx_transferStx",re=e=>M(u({},e),{amount:e.amount.toString(),network:k(e.network),address:e.stxAddress}),ae=e=>({txId:e.txid,txRaw:e.transaction,stacksTransaction:deserializeTransaction(e.transaction)});function $t(e,t=g()){S(Jt,re,ae)(e,t);}var eo="stx_signTransaction",ie=e=>M(u({},e),{transaction:e.txHex}),ce=e=>M(u({},e),{stacksTransaction:deserializeTransaction(e.transaction)});function to(e,t=g()){S(eo,ie,ce)(e,t);}function Ge(e){if(typeof e!="undefined")return e.map(t=>typeof t=="string"?t:typeof t.type=="string"?M(u({},t),{amount:"amount"in t?t.amount.toString():void 0}):bytesToHex$2(serializePostCondition(t)))}function Ye(e){if(typeof e!="undefined"){if(typeof e=="string")return e;switch(e){case PostConditionMode$1.Allow:return "allow";case PostConditionMode$1.Deny:return "deny";default:let t=e;throw new Error(`Unknown post condition mode: ${t}. Should be one of: 'allow', 'deny'`)}}}function C(e,t,o){return (s,n)=>{let r=t(ke(s)),a=s;P({provider:n},e,r).then(c=>{var f;let d=o(c);(f=a.onFinish)==null||f.call(a,d);}).catch(c=>{var d;console.error(c),(d=a.onCancel)==null||d.call(a,c);});}}var oo=he,Ps=C("stx_transferStx",re,ae),js=C("stx_callContract",te,oe),ws=C("stx_deployContract",se,ne),hs=C("stx_signTransaction",ie,ce),Os=C("stx_updateProfile",H,V),Es=C("stx_signMessage",K,J),bs=C("stx_signStructuredMessage",$,ee),Rs=oo;function ro(e){}var ao=async e=>{},io="signPsbt",co=e=>{var t;return {psbt:base64.encode(hexToBytes$2(e.hex)),signInputs:typeof e.signAtIndex=="number"?[e.signAtIndex]:e.signAtIndex,allowedSighash:(t=e.allowedSighash)==null?void 0:t.map(o=>q[o])}},uo=e=>({hex:bytesToHex$2(base64.decode(e.psbt))});function Mo(e,t=g()){S(io,co,uo)(e,t);}

const closeIconSvg = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0ibTcgNyAxMCAxME0xNyA3IDcgMTciIHN0cm9rZT0iIzI0MjYyOSIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjwvc3ZnPg==';

const isChrome = () => {
  const isChromium = !!window['chrome'];
  const winNav = window.navigator;
  const vendorName = winNav.vendor;
  const isOpera = typeof window.opr !== 'undefined';
  const isIEedge = winNav.userAgent.includes('Edge');
  const isIOSChrome = /CriOS/.exec(winNav.userAgent);
  const isMobile = winNav.userAgent.includes('Mobile');
  if (isIOSChrome) {
    return false;
  }
  else if (isChromium !== null &&
    typeof isChromium !== 'undefined' &&
    vendorName === 'Google Inc.' &&
    isOpera === false &&
    isIEedge === false &&
    isMobile === false) {
    return true;
  }
  else {
    return false;
  }
};
const getBrowser = () => {
  if (isChrome()) {
    return 'Chrome';
  }
  else if (window.navigator.userAgent.includes('Firefox')) {
    return 'Firefox';
  }
  return null;
};
const getPlatform = () => {
  if (!window.navigator.userAgent.includes('Mobile'))
    return null;
  if (window.navigator.userAgent.includes('iPhone')) {
    return 'IOS';
  }
  else
    return 'Android';
};

const modalCss = "*,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-scroll-snap-strictness:proximity;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;border:0 solid #e5e7eb;box-sizing:border-box}::backdrop{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-scroll-snap-strictness:proximity;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:rgba(59,130,246,.5);--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;}/*! tailwindcss v3.4.14 | MIT License | https://tailwindcss.com*/:after,:before{--tw-content:\"\"}:host,html{-webkit-text-size-adjust:100%;font-feature-settings:normal;-webkit-tap-highlight-color:transparent;font-family:ui-sans-serif,system-ui,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;font-variation-settings:normal;line-height:1.5;-moz-tab-size:4;tab-size:4}body{line-height:inherit;margin:0}hr{border-top-width:1px;color:inherit;height:0}abbr:where([title]){text-decoration:underline dotted}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}b,strong{font-weight:bolder}code,kbd,pre,samp{font-feature-settings:normal;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace;font-size:1em;font-variation-settings:normal}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}table{border-collapse:collapse;border-color:inherit;text-indent:0}button,input,optgroup,select,textarea{font-feature-settings:inherit;color:inherit;font-family:inherit;font-size:100%;font-variation-settings:inherit;font-weight:inherit;letter-spacing:inherit;line-height:inherit;margin:0;padding:0}button,select{text-transform:none}button,input:where([type=button]),input:where([type=reset]),input:where([type=submit]){-webkit-appearance:button;background-color:transparent;background-image:none}:-moz-focusring{outline:auto}:-moz-ui-invalid{box-shadow:none}progress{vertical-align:baseline}::-webkit-inner-spin-button,::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}summary{display:list-item}blockquote,dd,dl,fieldset,figure,h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}fieldset,legend{padding:0}menu,ol,ul{list-style:none;margin:0;padding:0}dialog{padding:0}textarea{resize:vertical}input::placeholder,textarea::placeholder{color:#9ca3af;opacity:1}[role=button],button{cursor:pointer}:disabled{cursor:default}audio,canvas,embed,iframe,img,object,svg,video{display:block;vertical-align:middle}img,video{height:auto;max-width:100%}[hidden]:where(:not([hidden=until-found])){display:none}:host{all:initial}.modal-container{color:#74777d;font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol}.modal-body{-ms-overflow-style:none;scrollbar-width:none}.modal-body::-webkit-scrollbar{display:none}.sr-only{clip:rect(0,0,0,0);border-width:0;height:1px;margin:-1px;overflow:hidden;padding:0;position:absolute;white-space:nowrap;width:1px}.static{position:static}.fixed{position:fixed}.inset-0{inset:0}.z-\\[8999\\]{z-index:8999}.z-\\[9000\\]{z-index:9000}.mx-auto{margin-left:auto;margin-right:auto}.mb-4{margin-bottom:1rem}.mb-5{margin-bottom:1.25rem}.mt-4{margin-top:1rem}.mt-6{margin-top:1.5rem}.box-border{box-sizing:border-box}.flex{display:flex}.aspect-square{aspect-ratio:1/1}.h-full{height:100%}.max-h-\\[calc\\(100\\%-24px\\)\\]{max-height:calc(100% - 24px)}.w-full{width:100%}.max-w-full{max-width:100%}.flex-1{flex:1 1 0%}.basis-9{flex-basis:2.25rem}.cursor-default{cursor:default}.cursor-pointer{cursor:pointer}.flex-col{flex-direction:column}.items-end{align-items:flex-end}.items-center{align-items:center}.justify-between{justify-content:space-between}.gap-3{gap:.75rem}.space-x-\\[5px\\]>:not([hidden])~:not([hidden]){--tw-space-x-reverse:0;margin-left:calc(5px*(1 - var(--tw-space-x-reverse)));margin-right:calc(5px*var(--tw-space-x-reverse))}.space-y-3>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(.75rem*var(--tw-space-y-reverse));margin-top:calc(.75rem*(1 - var(--tw-space-y-reverse)))}.space-y-\\[10px\\]>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(10px*var(--tw-space-y-reverse));margin-top:calc(10px*(1 - var(--tw-space-y-reverse)))}.overflow-hidden{overflow:hidden}.overflow-y-scroll{overflow-y:scroll}.rounded-2xl{border-radius:1rem}.rounded-\\[10px\\]{border-radius:10px}.rounded-full{border-radius:9999px}.rounded-xl{border-radius:.75rem}.rounded-b-none{border-bottom-left-radius:0;border-bottom-right-radius:0}.border{border-width:1px}.border-\\[\\#333\\]{--tw-border-opacity:1;border-color:rgb(51 51 51/var(--tw-border-opacity))}.border-\\[\\#EFEFF2\\]{--tw-border-opacity:1;border-color:rgb(239 239 242/var(--tw-border-opacity))}.bg-\\[\\#00000040\\]{background-color:#00000040}.bg-\\[\\#323232\\]{--tw-bg-opacity:1;background-color:rgb(50 50 50/var(--tw-bg-opacity))}.bg-gray-200{--tw-bg-opacity:1;background-color:rgb(229 231 235/var(--tw-bg-opacity))}.bg-gray-700{--tw-bg-opacity:1;background-color:rgb(55 65 81/var(--tw-bg-opacity))}.bg-transparent{background-color:transparent}.bg-white{--tw-bg-opacity:1;background-color:rgb(255 255 255/var(--tw-bg-opacity))}.p-1{padding:.25rem}.p-6{padding:1.5rem}.p-\\[14px\\]{padding:14px}.px-3{padding-left:.75rem;padding-right:.75rem}.px-4{padding-left:1rem;padding-right:1rem}.py-1\\.5{padding-bottom:.375rem;padding-top:.375rem}.py-2{padding-bottom:.5rem;padding-top:.5rem}.align-text-bottom{vertical-align:text-bottom}.text-\\[9px\\]{font-size:9px}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.text-xs{font-size:.75rem;line-height:1rem}.font-medium{font-weight:500}.leading-snug{line-height:1.375}.text-\\[\\#242629\\]{--tw-text-opacity:1;color:rgb(36 38 41/var(--tw-text-opacity))}.text-\\[\\#EFEFEF\\]{--tw-text-opacity:1;color:rgb(239 239 239/var(--tw-text-opacity))}.text-gray-500{--tw-text-opacity:1;color:rgb(107 114 128/var(--tw-text-opacity))}.shadow{--tw-shadow:0 1px 3px 0 rgba(0,0,0,.1),0 1px 2px -1px rgba(0,0,0,.1);--tw-shadow-colored:0 1px 3px 0 var(--tw-shadow-color),0 1px 2px -1px var(--tw-shadow-color)}.shadow,.shadow-\\[0_1px_2px_0_\\#0000000A\\]{box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.shadow-\\[0_1px_2px_0_\\#0000000A\\]{--tw-shadow:0 1px 2px 0 #0000000a;--tw-shadow-colored:0 1px 2px 0 var(--tw-shadow-color)}.shadow-\\[0_4px_5px_0_\\#00000005\\2c 0_16px_40px_0_\\#00000014\\]{--tw-shadow:0 4px 5px 0 #00000005,0 16px 40px 0 #00000014;--tw-shadow-colored:0 4px 5px 0 var(--tw-shadow-color),0 16px 40px 0 var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline-\\[\\#FFBD7A\\]{outline-color:#ffbd7a}.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.transition-all{transition-duration:.15s;transition-property:all;transition-timing-function:cubic-bezier(.4,0,.2,1)}.transition-colors{transition-duration:.15s;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke;transition-timing-function:cubic-bezier(.4,0,.2,1)}@keyframes enter{0%{opacity:var(--tw-enter-opacity,1);transform:translate3d(var(--tw-enter-translate-x,0),var(--tw-enter-translate-y,0),0) scale3d(var(--tw-enter-scale,1),var(--tw-enter-scale,1),var(--tw-enter-scale,1)) rotate(var(--tw-enter-rotate,0))}}@keyframes exit{to{opacity:var(--tw-exit-opacity,1);transform:translate3d(var(--tw-exit-translate-x,0),var(--tw-exit-translate-y,0),0) scale3d(var(--tw-exit-scale,1),var(--tw-exit-scale,1),var(--tw-exit-scale,1)) rotate(var(--tw-exit-rotate,0))}}.animate-in{--tw-enter-opacity:initial;--tw-enter-scale:initial;--tw-enter-rotate:initial;--tw-enter-translate-x:initial;--tw-enter-translate-y:initial;animation-duration:.15s;animation-name:enter}.fade-in{--tw-enter-opacity:0}.slide-in-from-bottom{--tw-enter-translate-y:100%}.hover\\:bg-\\[\\#0C0C0D\\]:hover{--tw-bg-opacity:1;background-color:rgb(12 12 13/var(--tw-bg-opacity))}.hover\\:bg-gray-100:hover{--tw-bg-opacity:1;background-color:rgb(243 244 246/var(--tw-bg-opacity))}.hover\\:text-\\[\\#242629\\]:hover{--tw-text-opacity:1;color:rgb(36 38 41/var(--tw-text-opacity))}.hover\\:text-white:hover{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity))}.hover\\:underline:hover{text-decoration-line:underline}.hover\\:shadow-\\[0_1px_2px_0_\\#00000010\\]:hover{--tw-shadow:0 1px 2px 0 #00000010;--tw-shadow-colored:0 1px 2px 0 var(--tw-shadow-color)}.hover\\:shadow-\\[0_1px_2px_0_\\#00000010\\]:hover,.hover\\:shadow-\\[0_8px_16px_0_\\#00000020\\]:hover{box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.hover\\:shadow-\\[0_8px_16px_0_\\#00000020\\]:hover{--tw-shadow:0 8px 16px 0 #00000020;--tw-shadow-colored:0 8px 16px 0 var(--tw-shadow-color)}.focus\\:underline:focus{text-decoration-line:underline}.focus\\:outline:focus{outline-style:solid}.focus\\:outline-\\[3px\\]:focus{outline-width:3px}.active\\:scale-95:active{--tw-scale-x:.95;--tw-scale-y:.95;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}@media (min-width:768px){.md\\:max-h-\\[calc\\(100\\%-48px\\)\\]{max-height:calc(100% - 48px)}.md\\:w-\\[400px\\]{width:400px}.md\\:items-center{align-items:center}.md\\:justify-center{justify-content:center}.md\\:rounded-b-2xl{border-bottom-left-radius:1rem;border-bottom-right-radius:1rem}.md\\:zoom-in-50{--tw-enter-scale:.5}.md\\:slide-in-from-bottom-0{--tw-enter-translate-y:0px}}";

const Modal = class {
  constructor(hostRef) {
    registerInstance(this, hostRef);
    this.defaultProviders = undefined;
    this.installedProviders = undefined;
    this.callback = undefined;
    this.cancelCallback = undefined;
  }
  handleSelectProvider(providerId) {
    this.callback(providerId);
  }
  handleCloseModal() {
    this.cancelCallback();
  }
  // todo: nice to have:
  // getComment(provider: WebBTCProvider, browser: string, isMobile?: string) {
  //   if (!provider) return null;
  //   const hasExtension = this.getBrowserUrl(provider);
  //   const hasMobile = this.getMobileUrl(provider);
  //   if (isMobile && hasExtension && !hasMobile) return 'Extension Only';
  //   if (!isMobile && !hasExtension && hasMobile) return 'Mobile Only';
  //   if (!isMobile && !browser) return 'Current browser not supported';
  //   return null;
  // }
  getBrowserUrl(provider) {
    var _a;
    return (_a = provider.chromeWebStoreUrl) !== null && _a !== void 0 ? _a : provider.mozillaAddOnsUrl;
  }
  getMobileUrl(provider) {
    var _a;
    return (_a = provider.iOSAppStoreUrl) !== null && _a !== void 0 ? _a : provider.googlePlayStoreUrl;
  }
  getInstallUrl(provider, browser, platform) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
    if (platform === 'IOS') {
      return (_b = (_a = provider.iOSAppStoreUrl) !== null && _a !== void 0 ? _a : this.getBrowserUrl(provider)) !== null && _b !== void 0 ? _b : provider.webUrl;
    }
    else if (browser === 'Chrome') {
      return (_d = (_c = provider.chromeWebStoreUrl) !== null && _c !== void 0 ? _c : this.getMobileUrl(provider)) !== null && _d !== void 0 ? _d : provider.webUrl;
    }
    else if (browser === 'Firefox') {
      return (_f = (_e = provider.mozillaAddOnsUrl) !== null && _e !== void 0 ? _e : this.getMobileUrl(provider)) !== null && _f !== void 0 ? _f : provider.webUrl;
    }
    else if (platform === 'Android') {
      return (_h = (_g = provider.googlePlayStoreUrl) !== null && _g !== void 0 ? _g : this.getBrowserUrl(provider)) !== null && _h !== void 0 ? _h : provider.webUrl;
    }
    else {
      return (_k = (_j = this.getBrowserUrl(provider)) !== null && _j !== void 0 ? _j : provider.webUrl) !== null && _k !== void 0 ? _k : this.getMobileUrl(provider);
    }
  }
  render() {
    const browser = getBrowser();
    const mobile = getPlatform();
    const notInstalledProviders = this.defaultProviders.filter(p => this.installedProviders.findIndex(i => i.id === p.id) === -1 // keep providers NOT already in installed list
    );
    const hasInstalled = this.installedProviders.length > 0;
    const hasMore = notInstalledProviders.length > 0;
    return (h$1("div", { class: "modal-container animate-in fade-in fixed inset-0 z-[8999] box-border flex h-full w-full items-end bg-[#00000040] md:items-center md:justify-center" }, h$1("div", { class: "fixed inset-0 z-[8999]", onClick: () => this.handleCloseModal() }), h$1("div", { class: "modal-body animate-in md:zoom-in-50 slide-in-from-bottom md:slide-in-from-bottom-0 z-[9000] box-border flex max-h-[calc(100%-24px)] w-full max-w-full cursor-default flex-col overflow-y-scroll rounded-2xl rounded-b-none bg-white p-6 text-sm leading-snug shadow-[0_4px_5px_0_#00000005,0_16px_40px_0_#00000014] md:max-h-[calc(100%-48px)] md:w-[400px] md:rounded-b-2xl" }, h$1("div", { class: "flex flex-col space-y-[10px]" }, h$1("div", { class: "flex items-center" }, h$1("div", { class: "flex-1 text-xl font-medium text-[#242629]" }, "Connect a wallet"), h$1("button", { class: "rounded-full bg-transparent p-1 transition-colors hover:bg-gray-100 active:scale-95", onClick: () => this.handleCloseModal() }, h$1("span", { class: "sr-only" }, "Close popup"), h$1("img", { src: closeIconSvg }))), hasInstalled ? (h$1("p", null, "Select the wallet you want to connect to.")) : (h$1("p", null, "You don't have any wallets in your browser that support this app. You need to install a wallet to proceed."))), !mobile && !browser && (h$1("div", { class: "mx-auto mt-4 rounded-xl bg-gray-200 px-3 py-1.5 text-sm font-medium text-gray-500" }, "Unfortunately, your browser isn't supported")), hasInstalled && (h$1("div", { class: "mt-6" }, h$1("p", { class: "mb-4 text-sm font-medium" }, "Installed wallets"), h$1("ul", { class: "space-y-3" }, this.installedProviders.map((provider) => (h$1("li", { class: "flex items-center gap-3 rounded-[10px] border border-[#EFEFF2] p-[14px]" }, h$1("div", { class: "aspect-square basis-9 overflow-hidden" }, h$1("img", { src: provider.icon, class: "h-full w-full rounded-[10px] bg-gray-700" })), h$1("div", { class: "flex-1" }, h$1("div", { class: "text-sm font-medium text-[#242629]" }, provider.name), provider.webUrl && (h$1("a", { href: provider.webUrl, class: "text-sm", rel: "noopener noreferrer" }, new URL(provider.webUrl).hostname))), h$1("button", { class: "rounded-[10px] border border-[#333] bg-[#323232] px-4 py-2 text-sm font-medium text-[#EFEFEF] shadow-[0_1px_2px_0_#0000000A] outline-[#FFBD7A] transition-all hover:bg-[#0C0C0D] hover:text-white hover:shadow-[0_8px_16px_0_#00000020] focus:outline focus:outline-[3px] active:scale-95", onClick: () => this.handleSelectProvider(provider.id) }, "Connect"))))))), hasMore && (h$1("div", { class: "mt-6" }, hasInstalled ? (h$1("p", { class: "mb-4 text-sm font-medium" }, "Other wallets")) : (h$1("div", { class: "mb-5 flex justify-between" }, h$1("p", { class: "text-sm font-medium" }, "Recommended wallets"), h$1("a", { class: "flex cursor-pointer items-center space-x-[5px] text-xs transition-colors hover:text-[#242629] hover:underline focus:underline", href: "https://docs.hiro.so/what-is-a-wallet", rel: "noopener noreferrer", target: "_blank" }, h$1("svg", { xmlns: "http://www.w3.org/2000/svg", width: "14", height: "14", viewBox: "0 0 16 16", fill: "none" }, h$1("path", { stroke: "#74777D", "stroke-linecap": "round", "stroke-linejoin": "round", "stroke-width": "1.2", d: "M8.006 15a7 7 0 1 0 0-14 7 7 0 0 0 0 14Z" }), h$1("path", { stroke: "#74777D", "stroke-linecap": "round", "stroke-linejoin": "round", "stroke-width": "1.2", d: "M5.97 5.9a2.1 2.1 0 0 1 4.08.7c0 1.4-2.1 2.1-2.1 2.1M8.006 11.5h.01" })), h$1("p", null, "What is a wallet?\u2009", h$1("span", { class: "align-text-bottom text-[9px]" }, "\u2197"))))), h$1("ul", { class: "space-y-3" }, notInstalledProviders.map((provider) => (h$1("li", { class: "flex items-center gap-3 rounded-[10px] border border-[#EFEFF2] p-[14px]" }, h$1("div", { class: "aspect-square basis-9 overflow-hidden" }, h$1("img", { src: provider.icon, class: "h-full w-full rounded-[10px] bg-gray-700" })), h$1("div", { class: "flex-1" }, h$1("div", { class: "text-sm font-medium text-[#242629]" }, provider.name), provider.webUrl && (h$1("a", { href: provider.webUrl, class: "text-sm", rel: "noopener noreferrer" }, new URL(provider.webUrl).hostname))), this.getInstallUrl(provider, browser, mobile) && (h$1("a", { class: "rounded-[10px] border border-[#EFEFF2] px-4 py-2 text-sm font-medium shadow-[0_1px_2px_0_#0000000A] outline-[#FFBD7A] transition-colors hover:text-[#242629] hover:shadow-[0_1px_2px_0_#00000010] focus:outline focus:outline-[3px] active:scale-95", href: this.getInstallUrl(provider, browser, mobile), rel: "noopener noreferrer", target: "_blank" }, provider.id === 'AsignaProvider' ? 'Open' : 'Install', " \u2192")))))))))));
  }
  static get assetsDirs() { return ["assets"]; }
  get modalEl() { return getElement(this); }
};
Modal.style = modalCss;

var connectModal_entry = /*#__PURE__*/Object.freeze({
    __proto__: null,
    connect_modal: Modal
});

export { E as AppConfig, It as ContractCallArgumentType, De as DEFAULT_PROVIDERS, F as InstanceDataStore, I as JsonRpcError, fe as JsonRpcErrorCode, yt as LOCALSTORAGE_SESSION_KEY, B as LocalStorageStore, b as SessionDataStore, q as SignatureHash, Dt as TransactionTypes, T as UserSession, he as authenticate, me as clearLocalStorage, clearSelectedProviderId, Mt as connect, vo as defaultAuthURL, et as disconnect, Pt as getDefaultProfileUpdateRequestOptions, ro as getDefaultPsbtRequestOptions, Ot as getDefaultSignatureRequestOptions, Qt as getKeys, G as getLocalStorage, Oe as getOrCreateUserSession, getProvider as getSelectedProvider, getSelectedProviderId, g as getStacksProvider, Ft as getStxAddress, zo as getUserData, ze as getUserSession, Yt as hasAppPrivateKey, we as isAddressTaproot, tt as isConnected, Uo as isMobile, isProviderSelected, Nt as isStacksWalletInstalled, Bt as makeContractCallToken, Wt as makeContractDeployToken, jt as makeProfileUpdateToken, ao as makePsbtToken, qt as makeSTXTransferToken, Zt as makeSignTransaction, Ht as openContractCall, Kt as openContractDeploy, ht as openProfileUpdateRequestPopup, Mo as openPsbtRequestPopup, $t as openSTXTransfer, to as openSignTransaction, Rt as openSignatureRequestPopup, Ut as openStructuredDataSignatureRequestPopup, P as request, O as requestRaw, setSelectedProviderId, Rs as showBlockstackConnect, oo as showConnect, js as showContractCall, ws as showContractDeploy, Os as showProfileUpdate, Ps as showSTXTransfer, Es as showSignMessage, bs as showSignStructuredMessage, hs as showSignTransaction, Et as signMessage, _t as signStructuredMessage };
//# sourceMappingURL=stacks-connect.bundle.js.map
