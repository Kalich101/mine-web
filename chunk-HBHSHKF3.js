import {a as d, b as w, d as Q, f as _t, i as s, j as Ct, k as Ht} from "./chunk-7LMP3FNB.js";
var m = crypto
  , C = e => e instanceof CryptoKey;
var Ar = (e, t) => s(void 0, null, function*() {
    let r = `SHA-${e.slice(-3)}`;
    return new Uint8Array(yield m.subtle.digest(r, t))
})
  , Je = Ar;
var A = new TextEncoder
  , H = new TextDecoder
  , Pe = 2 ** 32;
function I(...e) {
    let t = e.reduce( (o, {length: a}) => o + a, 0)
      , r = new Uint8Array(t)
      , n = 0;
    for (let o of e)
        r.set(o, n),
        n += o.length;
    return r
}
function Wt(e, t) {
    return I(A.encode(e), new Uint8Array([0]), t)
}
function Ye(e, t, r) {
    if (t < 0 || t >= Pe)
        throw new RangeError(`value must be >= 0 and <= ${Pe - 1}. Received ${t}`);
    e.set([t >>> 24, t >>> 16, t >>> 8, t & 255], r)
}
function ve(e) {
    let t = Math.floor(e / Pe)
      , r = e % Pe
      , n = new Uint8Array(8);
    return Ye(n, t, 0),
    Ye(n, r, 4),
    n
}
function Te(e) {
    let t = new Uint8Array(4);
    return Ye(t, e),
    t
}
function Ie(e) {
    return I(Te(e.length), e)
}
function Jt(e, t, r) {
    return s(this, null, function*() {
        let n = Math.ceil((t >> 3) / 32)
          , o = new Uint8Array(n * 32);
        for (let a = 0; a < n; a++) {
            let i = new Uint8Array(4 + e.length + r.length);
            i.set(Te(a + 1)),
            i.set(e, 4),
            i.set(r, 4 + e.length),
            o.set(yield Je("sha256", i), a * 32)
        }
        return o.slice(0, t >> 3)
    })
}
var Oe = e => {
    let t = e;
    typeof t == "string" && (t = A.encode(t));
    let r = 32768
      , n = [];
    for (let o = 0; o < t.length; o += r)
        n.push(String.fromCharCode.apply(null, t.subarray(o, o + r)));
    return btoa(n.join(""))
}
  , b = e => Oe(e).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
  , qe = e => {
    let t = atob(e)
      , r = new Uint8Array(t.length);
    for (let n = 0; n < t.length; n++)
        r[n] = t.charCodeAt(n);
    return r
}
  , K = e => {
    let t = e;
    t instanceof Uint8Array && (t = H.decode(t)),
    t = t.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    try {
        return qe(t)
    } catch {
        throw new TypeError("The input to be decoded is not correctly encoded.")
    }
}
;
var je = {};
_t(je, {
    JOSEAlgNotAllowed: () => ie,
    JOSEError: () => T,
    JOSENotSupported: () => y,
    JWEDecryptionFailed: () => j,
    JWEInvalid: () => c,
    JWKInvalid: () => Ze,
    JWKSInvalid: () => De,
    JWKSMultipleMatchingKeys: () => ae,
    JWKSNoMatchingKey: () => he,
    JWKSTimeout: () => Qe,
    JWSInvalid: () => S,
    JWSSignatureVerificationFailed: () => me,
    JWTClaimValidationFailed: () => R,
    JWTExpired: () => Re,
    JWTInvalid: () => J
});
var T = ( () => {
    class e extends Error {
        constructor(r, n) {
            super(r, n),
            this.code = "ERR_JOSE_GENERIC",
            this.name = this.constructor.name,
            Error.captureStackTrace?.(this, this.constructor)
        }
    }
    return e.code = "ERR_JOSE_GENERIC",
    e
}
)()
  , R = ( () => {
    class e extends T {
        constructor(r, n, o="unspecified", a="unspecified") {
            super(r, {
                cause: {
                    claim: o,
                    reason: a,
                    payload: n
                }
            }),
            this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED",
            this.claim = o,
            this.reason = a,
            this.payload = n
        }
    }
    return e.code = "ERR_JWT_CLAIM_VALIDATION_FAILED",
    e
}
)()
  , Re = ( () => {
    class e extends T {
        constructor(r, n, o="unspecified", a="unspecified") {
            super(r, {
                cause: {
                    claim: o,
                    reason: a,
                    payload: n
                }
            }),
            this.code = "ERR_JWT_EXPIRED",
            this.claim = o,
            this.reason = a,
            this.payload = n
        }
    }
    return e.code = "ERR_JWT_EXPIRED",
    e
}
)()
  , ie = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JOSE_ALG_NOT_ALLOWED"
        }
    }
    return e.code = "ERR_JOSE_ALG_NOT_ALLOWED",
    e
}
)()
  , y = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JOSE_NOT_SUPPORTED"
        }
    }
    return e.code = "ERR_JOSE_NOT_SUPPORTED",
    e
}
)()
  , j = ( () => {
    class e extends T {
        constructor(r="decryption operation failed", n) {
            super(r, n),
            this.code = "ERR_JWE_DECRYPTION_FAILED"
        }
    }
    return e.code = "ERR_JWE_DECRYPTION_FAILED",
    e
}
)()
  , c = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JWE_INVALID"
        }
    }
    return e.code = "ERR_JWE_INVALID",
    e
}
)()
  , S = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JWS_INVALID"
        }
    }
    return e.code = "ERR_JWS_INVALID",
    e
}
)()
  , J = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JWT_INVALID"
        }
    }
    return e.code = "ERR_JWT_INVALID",
    e
}
)()
  , Ze = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JWK_INVALID"
        }
    }
    return e.code = "ERR_JWK_INVALID",
    e
}
)()
  , De = ( () => {
    class e extends T {
        constructor() {
            super(...arguments),
            this.code = "ERR_JWKS_INVALID"
        }
    }
    return e.code = "ERR_JWKS_INVALID",
    e
}
)()
  , he = ( () => {
    class e extends T {
        constructor(r="no applicable key found in the JSON Web Key Set", n) {
            super(r, n),
            this.code = "ERR_JWKS_NO_MATCHING_KEY"
        }
    }
    return e.code = "ERR_JWKS_NO_MATCHING_KEY",
    e
}
)()
  , ae = class extends T {
    constructor(t="multiple matching keys found in the JSON Web Key Set", r) {
        super(t, r),
        this.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS"
    }
}
;
ae.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
var Qe = ( () => {
    class e extends T {
        constructor(r="request timed out", n) {
            super(r, n),
            this.code = "ERR_JWKS_TIMEOUT"
        }
    }
    return e.code = "ERR_JWKS_TIMEOUT",
    e
}
)()
  , me = ( () => {
    class e extends T {
        constructor(r="signature verification failed", n) {
            super(r, n),
            this.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED"
        }
    }
    return e.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
    e
}
)();
var G = m.getRandomValues.bind(m);
function et(e) {
    switch (e) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
        return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
        return 128;
    default:
        throw new y(`Unsupported JWE Algorithm: ${e}`)
    }
}
var vt = e => G(new Uint8Array(et(e) >> 3));
var br = (e, t) => {
    if (t.length << 3 !== et(e))
        throw new c("Invalid Initialization Vector length")
}
  , Ue = br;
var Kr = (e, t) => {
    let r = e.byteLength << 3;
    if (r !== t)
        throw new c(`Invalid Content Encryption Key length. Expected ${t} bits, got ${r} bits`)
}
  , se = Kr;
var xr = (e, t) => {
    if (!(e instanceof Uint8Array))
        throw new TypeError("First argument must be a buffer");
    if (!(t instanceof Uint8Array))
        throw new TypeError("Second argument must be a buffer");
    if (e.length !== t.length)
        throw new TypeError("Input buffers must have the same length");
    let r = e.length
      , n = 0
      , o = -1;
    for (; ++o < r; )
        n |= e[o] ^ t[o];
    return n === 0
}
  , Tt = xr;
function O(e, t="algorithm.name") {
    return new TypeError(`CryptoKey does not support this operation, its ${t} must be ${e}`)
}
function V(e, t) {
    return e.name === t
}
function Me(e) {
    return parseInt(e.name.slice(4), 10)
}
function _r(e) {
    switch (e) {
    case "ES256":
        return "P-256";
    case "ES384":
        return "P-384";
    case "ES512":
        return "P-521";
    default:
        throw new Error("unreachable")
    }
}
function It(e, t) {
    if (t.length && !t.some(r => e.usages.includes(r))) {
        let r = "CryptoKey does not support this operation, its usages must include ";
        if (t.length > 2) {
            let n = t.pop();
            r += `one of ${t.join(", ")}, or ${n}.`
        } else
            t.length === 2 ? r += `one of ${t[0]} or ${t[1]}.` : r += `${t[0]}.`;
        throw new TypeError(r)
    }
}
function Ot(e, t, ...r) {
    switch (t) {
    case "HS256":
    case "HS384":
    case "HS512":
        {
            if (!V(e.algorithm, "HMAC"))
                throw O("HMAC");
            let n = parseInt(t.slice(2), 10);
            if (Me(e.algorithm.hash) !== n)
                throw O(`SHA-${n}`, "algorithm.hash");
            break
        }
    case "RS256":
    case "RS384":
    case "RS512":
        {
            if (!V(e.algorithm, "RSASSA-PKCS1-v1_5"))
                throw O("RSASSA-PKCS1-v1_5");
            let n = parseInt(t.slice(2), 10);
            if (Me(e.algorithm.hash) !== n)
                throw O(`SHA-${n}`, "algorithm.hash");
            break
        }
    case "PS256":
    case "PS384":
    case "PS512":
        {
            if (!V(e.algorithm, "RSA-PSS"))
                throw O("RSA-PSS");
            let n = parseInt(t.slice(2), 10);
            if (Me(e.algorithm.hash) !== n)
                throw O(`SHA-${n}`, "algorithm.hash");
            break
        }
    case "EdDSA":
        {
            if (e.algorithm.name !== "Ed25519" && e.algorithm.name !== "Ed448")
                throw O("Ed25519 or Ed448");
            break
        }
    case "ES256":
    case "ES384":
    case "ES512":
        {
            if (!V(e.algorithm, "ECDSA"))
                throw O("ECDSA");
            let n = _r(t);
            if (e.algorithm.namedCurve !== n)
                throw O(n, "algorithm.namedCurve");
            break
        }
    default:
        throw new TypeError("CryptoKey does not support this operation")
    }
    It(e, r)
}
function D(e, t, ...r) {
    switch (t) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
        {
            if (!V(e.algorithm, "AES-GCM"))
                throw O("AES-GCM");
            let n = parseInt(t.slice(1, 4), 10);
            if (e.algorithm.length !== n)
                throw O(n, "algorithm.length");
            break
        }
    case "A128KW":
    case "A192KW":
    case "A256KW":
        {
            if (!V(e.algorithm, "AES-KW"))
                throw O("AES-KW");
            let n = parseInt(t.slice(1, 4), 10);
            if (e.algorithm.length !== n)
                throw O(n, "algorithm.length");
            break
        }
    case "ECDH":
        {
            switch (e.algorithm.name) {
            case "ECDH":
            case "X25519":
            case "X448":
                break;
            default:
                throw O("ECDH, X25519, or X448")
            }
            break
        }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
        if (!V(e.algorithm, "PBKDF2"))
            throw O("PBKDF2");
        break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
        {
            if (!V(e.algorithm, "RSA-OAEP"))
                throw O("RSA-OAEP");
            let n = parseInt(t.slice(9), 10) || 1;
            if (Me(e.algorithm.hash) !== n)
                throw O(`SHA-${n}`, "algorithm.hash");
            break
        }
    default:
        throw new TypeError("CryptoKey does not support this operation")
    }
    It(e, r)
}
function Rt(e, t, ...r) {
    if (r = r.filter(Boolean),
    r.length > 2) {
        let n = r.pop();
        e += `one of type ${r.join(", ")}, or ${n}.`
    } else
        r.length === 2 ? e += `one of type ${r[0]} or ${r[1]}.` : e += `of type ${r[0]}.`;
    return t == null ? e += ` Received ${t}` : typeof t == "function" && t.name ? e += ` Received function ${t.name}` : typeof t == "object" && t != null && t.constructor?.name && (e += ` Received an instance of ${t.constructor.name}`),
    e
}
var _ = (e, ...t) => Rt("Key must be ", e, ...t);
function tt(e, t, ...r) {
    return Rt(`Key for the ${e} algorithm must be `, t, ...r)
}
var rt = e => C(e) ? !0 : e?.[Symbol.toStringTag] === "KeyObject"
  , x = ["CryptoKey"];
function Cr(e, t, r, n, o, a) {
    return s(this, null, function*() {
        if (!(t instanceof Uint8Array))
            throw new TypeError(_(t, "Uint8Array"));
        let i = parseInt(e.slice(1, 4), 10), f = yield m.subtle.importKey("raw", t.subarray(i >> 3), "AES-CBC", !1, ["decrypt"]), h = yield m.subtle.importKey("raw", t.subarray(0, i >> 3), {
            hash: `SHA-${i << 1}`,
            name: "HMAC"
        }, !1, ["sign"]), p = I(a, n, r, ve(a.length << 3)), l = new Uint8Array((yield m.subtle.sign("HMAC", h, p)).slice(0, i >> 3)), u;
        try {
            u = Tt(o, l)
        } catch {}
        if (!u)
            throw new j;
        let P;
        try {
            P = new Uint8Array(yield m.subtle.decrypt({
                iv: n,
                name: "AES-CBC"
            }, f, r))
        } catch {}
        if (!P)
            throw new j;
        return P
    })
}
function Hr(e, t, r, n, o, a) {
    return s(this, null, function*() {
        let i;
        t instanceof Uint8Array ? i = yield m.subtle.importKey("raw", t, "AES-GCM", !1, ["decrypt"]) : (D(t, e, "decrypt"),
        i = t);
        try {
            return new Uint8Array(yield m.subtle.decrypt({
                additionalData: a,
                iv: n,
                name: "AES-GCM",
                tagLength: 128
            }, i, I(r, o)))
        } catch {
            throw new j
        }
    })
}
var Wr = (e, t, r, n, o, a) => s(void 0, null, function*() {
    if (!C(t) && !(t instanceof Uint8Array))
        throw new TypeError(_(t, ...x, "Uint8Array"));
    if (!n)
        throw new c("JWE Initialization Vector missing");
    if (!o)
        throw new c("JWE Authentication Tag missing");
    switch (Ue(e, n),
    e) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
        return t instanceof Uint8Array && se(t, parseInt(e.slice(-3), 10)),
        Cr(e, t, r, n, o, a);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
        return t instanceof Uint8Array && se(t, parseInt(e.slice(1, 4), 10)),
        Hr(e, t, r, n, o, a);
    default:
        throw new y("Unsupported JWE Content Encryption Algorithm")
    }
})
  , Ne = Wr;
var Jr = (...e) => {
    let t = e.filter(Boolean);
    if (t.length === 0 || t.length === 1)
        return !0;
    let r;
    for (let n of t) {
        let o = Object.keys(n);
        if (!r || r.size === 0) {
            r = new Set(o);
            continue
        }
        for (let a of o) {
            if (r.has(a))
                return !1;
            r.add(a)
        }
    }
    return !0
}
  , U = Jr;
function Pr(e) {
    return typeof e == "object" && e !== null
}
function E(e) {
    if (!Pr(e) || Object.prototype.toString.call(e) !== "[object Object]")
        return !1;
    if (Object.getPrototypeOf(e) === null)
        return !0;
    let t = e;
    for (; Object.getPrototypeOf(t) !== null; )
        t = Object.getPrototypeOf(t);
    return Object.getPrototypeOf(e) === t
}
var vr = [{
    hash: "SHA-256",
    name: "HMAC"
}, !0, ["sign"]]
  , ce = vr;
function Dt(e, t) {
    if (e.algorithm.length !== parseInt(t.slice(1, 4), 10))
        throw new TypeError(`Invalid key size for alg: ${t}`)
}
function Ut(e, t, r) {
    if (C(e))
        return D(e, t, r),
        e;
    if (e instanceof Uint8Array)
        return m.subtle.importKey("raw", e, "AES-KW", !0, [r]);
    throw new TypeError(_(e, ...x, "Uint8Array"))
}
var ye = (e, t, r) => s(void 0, null, function*() {
    let n = yield Ut(t, e, "wrapKey");
    Dt(n, e);
    let o = yield m.subtle.importKey("raw", r, ...ce);
    return new Uint8Array(yield m.subtle.wrapKey("raw", o, n, "AES-KW"))
})
  , we = (e, t, r) => s(void 0, null, function*() {
    let n = yield Ut(t, e, "unwrapKey");
    Dt(n, e);
    let o = yield m.subtle.unwrapKey("raw", r, n, "AES-KW", ...ce);
    return new Uint8Array(yield m.subtle.exportKey("raw", o))
});
function Le(i, f, h, p) {
    return s(this, arguments, function*(e, t, r, n, o=new Uint8Array(0), a=new Uint8Array(0)) {
        if (!C(e))
            throw new TypeError(_(e, ...x));
        if (D(e, "ECDH"),
        !C(t))
            throw new TypeError(_(t, ...x));
        D(t, "ECDH", "deriveBits");
        let l = I(Ie(A.encode(r)), Ie(o), Ie(a), Te(n)), u;
        e.algorithm.name === "X25519" ? u = 256 : e.algorithm.name === "X448" ? u = 448 : u = Math.ceil(parseInt(e.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
        let P = new Uint8Array(yield m.subtle.deriveBits({
            name: e.algorithm.name,
            public: e
        }, t, u));
        return Jt(P, n, l)
    })
}
function Mt(e) {
    return s(this, null, function*() {
        if (!C(e))
            throw new TypeError(_(e, ...x));
        return m.subtle.generateKey(e.algorithm, !0, ["deriveBits"])
    })
}
function ke(e) {
    if (!C(e))
        throw new TypeError(_(e, ...x));
    return ["P-256", "P-384", "P-521"].includes(e.algorithm.namedCurve) || e.algorithm.name === "X25519" || e.algorithm.name === "X448"
}
function nt(e) {
    if (!(e instanceof Uint8Array) || e.length < 8)
        throw new c("PBES2 Salt Input must be 8 or more octets")
}
function Tr(e, t) {
    if (e instanceof Uint8Array)
        return m.subtle.importKey("raw", e, "PBKDF2", !1, ["deriveBits"]);
    if (C(e))
        return D(e, t, "deriveBits", "deriveKey"),
        e;
    throw new TypeError(_(e, ...x, "Uint8Array"))
}
function Lt(e, t, r, n) {
    return s(this, null, function*() {
        nt(e);
        let o = Wt(t, e)
          , a = parseInt(t.slice(13, 16), 10)
          , i = {
            hash: `SHA-${t.slice(8, 11)}`,
            iterations: r,
            name: "PBKDF2",
            salt: o
        }
          , f = {
            length: a,
            name: "AES-KW"
        }
          , h = yield Tr(n, t);
        if (h.usages.includes("deriveBits"))
            return new Uint8Array(yield m.subtle.deriveBits(i, h, a));
        if (h.usages.includes("deriveKey"))
            return m.subtle.deriveKey(i, h, f, !1, ["wrapKey", "unwrapKey"]);
        throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"')
    })
}
var kt = (a, i, f, ...h) => s(void 0, [a, i, f, ...h], function*(e, t, r, n=2048, o=G(new Uint8Array(16))) {
    let p = yield Lt(o, e, n, t);
    return {
        encryptedKey: yield ye(e.slice(-6), p, r),
        p2c: n,
        p2s: b(o)
    }
})
  , $t = (e, t, r, n, o) => s(void 0, null, function*() {
    let a = yield Lt(o, e, n, t);
    return we(e.slice(-6), a, r)
});
function de(e) {
    switch (e) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
        return "RSA-OAEP";
    default:
        throw new y(`alg ${e} is not supported either by JOSE or your javascript runtime`)
    }
}
var ee = (e, t) => {
    if (e.startsWith("RS") || e.startsWith("PS")) {
        let {modulusLength: r} = t.algorithm;
        if (typeof r != "number" || r < 2048)
            throw new TypeError(`${e} requires key modulusLength to be 2048 bits or larger`)
    }
}
;
var Bt = (e, t, r) => s(void 0, null, function*() {
    if (!C(t))
        throw new TypeError(_(t, ...x));
    if (D(t, e, "encrypt", "wrapKey"),
    ee(e, t),
    t.usages.includes("encrypt"))
        return new Uint8Array(yield m.subtle.encrypt(de(e), t, r));
    if (t.usages.includes("wrapKey")) {
        let n = yield m.subtle.importKey("raw", r, ...ce);
        return new Uint8Array(yield m.subtle.wrapKey("raw", n, t, de(e)))
    }
    throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation')
})
  , Ft = (e, t, r) => s(void 0, null, function*() {
    if (!C(t))
        throw new TypeError(_(t, ...x));
    if (D(t, e, "decrypt", "unwrapKey"),
    ee(e, t),
    t.usages.includes("decrypt"))
        return new Uint8Array(yield m.subtle.decrypt(de(e), t, r));
    if (t.usages.includes("unwrapKey")) {
        let n = yield m.subtle.unwrapKey("raw", r, t, de(e), ...ce);
        return new Uint8Array(yield m.subtle.exportKey("raw", n))
    }
    throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation')
});
function k(e) {
    return E(e) && typeof e.kty == "string"
}
function Gt(e) {
    return e.kty !== "oct" && typeof e.d == "string"
}
function Vt(e) {
    return e.kty !== "oct" && typeof e.d > "u"
}
function zt(e) {
    return k(e) && e.kty === "oct" && typeof e.k == "string"
}
function Or(e) {
    let t, r;
    switch (e.kty) {
    case "RSA":
        {
            switch (e.alg) {
            case "PS256":
            case "PS384":
            case "PS512":
                t = {
                    name: "RSA-PSS",
                    hash: `SHA-${e.alg.slice(-3)}`
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "RS256":
            case "RS384":
            case "RS512":
                t = {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: `SHA-${e.alg.slice(-3)}`
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "RSA-OAEP":
            case "RSA-OAEP-256":
            case "RSA-OAEP-384":
            case "RSA-OAEP-512":
                t = {
                    name: "RSA-OAEP",
                    hash: `SHA-${parseInt(e.alg.slice(-3), 10) || 1}`
                },
                r = e.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
                break;
            default:
                throw new y('Invalid or unsupported JWK "alg" (Algorithm) Parameter value')
            }
            break
        }
    case "EC":
        {
            switch (e.alg) {
            case "ES256":
                t = {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "ES384":
                t = {
                    name: "ECDSA",
                    namedCurve: "P-384"
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "ES512":
                t = {
                    name: "ECDSA",
                    namedCurve: "P-521"
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "ECDH-ES":
            case "ECDH-ES+A128KW":
            case "ECDH-ES+A192KW":
            case "ECDH-ES+A256KW":
                t = {
                    name: "ECDH",
                    namedCurve: e.crv
                },
                r = e.d ? ["deriveBits"] : [];
                break;
            default:
                throw new y('Invalid or unsupported JWK "alg" (Algorithm) Parameter value')
            }
            break
        }
    case "OKP":
        {
            switch (e.alg) {
            case "EdDSA":
                t = {
                    name: e.crv
                },
                r = e.d ? ["sign"] : ["verify"];
                break;
            case "ECDH-ES":
            case "ECDH-ES+A128KW":
            case "ECDH-ES+A192KW":
            case "ECDH-ES+A256KW":
                t = {
                    name: e.crv
                },
                r = e.d ? ["deriveBits"] : [];
                break;
            default:
                throw new y('Invalid or unsupported JWK "alg" (Algorithm) Parameter value')
            }
            break
        }
    default:
        throw new y('Invalid or unsupported JWK "kty" (Key Type) Parameter value')
    }
    return {
        algorithm: t,
        keyUsages: r
    }
}
var Rr = e => s(void 0, null, function*() {
    if (!e.alg)
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
    let {algorithm: t, keyUsages: r} = Or(e)
      , n = [t, e.ext ?? !1, e.key_ops ?? r]
      , o = d({}, e);
    return delete o.alg,
    delete o.use,
    m.subtle.importKey("jwk", o, ...n)
})
  , $e = Rr;
var Xt = e => K(e), pe, fe, Yt = e => e?.[Symbol.toStringTag] === "KeyObject", Be = (e, t, r, n, o=!1) => s(void 0, null, function*() {
    let a = e.get(t);
    if (a?.[n])
        return a[n];
    let i = yield $e(w(d({}, r), {
        alg: n
    }));
    return o && Object.freeze(t),
    a ? a[n] = i : e.set(t, {
        [n]: i
    }),
    i
}), Dr = (e, t) => {
    if (Yt(e)) {
        let r = e.export({
            format: "jwk"
        });
        return delete r.d,
        delete r.dp,
        delete r.dq,
        delete r.p,
        delete r.q,
        delete r.qi,
        r.k ? Xt(r.k) : (fe || (fe = new WeakMap),
        Be(fe, e, r, t))
    }
    return k(e) ? e.k ? K(e.k) : (fe || (fe = new WeakMap),
    Be(fe, e, e, t, !0)) : e
}
, Ur = (e, t) => {
    if (Yt(e)) {
        let r = e.export({
            format: "jwk"
        });
        return r.k ? Xt(r.k) : (pe || (pe = new WeakMap),
        Be(pe, e, r, t))
    }
    return k(e) ? e.k ? K(e.k) : (pe || (pe = new WeakMap),
    Be(pe, e, e, t, !0)) : e
}
, te = {
    normalizePublicKey: Dr,
    normalizePrivateKey: Ur
};
function Ee(e) {
    switch (e) {
    case "A128GCM":
        return 128;
    case "A192GCM":
        return 192;
    case "A256GCM":
    case "A128CBC-HS256":
        return 256;
    case "A192CBC-HS384":
        return 384;
    case "A256CBC-HS512":
        return 512;
    default:
        throw new y(`Unsupported JWE Algorithm: ${e}`)
    }
}
var M = e => G(new Uint8Array(Ee(e) >> 3));
var ot = (e, t) => {
    let r = (e.match(/.{1,64}/g) || []).join(`
`);
    return `-----BEGIN ${t}-----
${r}
-----END ${t}-----`
}
;
var Qt = (e, t, r) => s(void 0, null, function*() {
    if (!C(r))
        throw new TypeError(_(r, ...x));
    if (!r.extractable)
        throw new TypeError("CryptoKey is not extractable");
    if (r.type !== e)
        throw new TypeError(`key is not a ${e} key`);
    return ot(Oe(new Uint8Array(yield m.subtle.exportKey(t, r))), `${e.toUpperCase()} KEY`)
})
  , jt = e => Qt("public", "spki", e)
  , er = e => Qt("private", "pkcs8", e)
  , z = (e, t, r=0) => {
    r === 0 && (t.unshift(t.length),
    t.unshift(6));
    let n = e.indexOf(t[0], r);
    if (n === -1)
        return !1;
    let o = e.subarray(n, n + t.length);
    return o.length !== t.length ? !1 : o.every( (a, i) => a === t[i]) || z(e, t, n + 1)
}
  , qt = e => {
    switch (!0) {
    case z(e, [42, 134, 72, 206, 61, 3, 1, 7]):
        return "P-256";
    case z(e, [43, 129, 4, 0, 34]):
        return "P-384";
    case z(e, [43, 129, 4, 0, 35]):
        return "P-521";
    case z(e, [43, 101, 110]):
        return "X25519";
    case z(e, [43, 101, 111]):
        return "X448";
    case z(e, [43, 101, 112]):
        return "Ed25519";
    case z(e, [43, 101, 113]):
        return "Ed448";
    default:
        throw new y("Invalid or unsupported EC Key Curve or OKP Key Sub Type")
    }
}
  , tr = (e, t, r, n, o) => s(void 0, null, function*() {
    let a, i, f = new Uint8Array(atob(r.replace(e, "")).split("").map(p => p.charCodeAt(0))), h = t === "spki";
    switch (n) {
    case "PS256":
    case "PS384":
    case "PS512":
        a = {
            name: "RSA-PSS",
            hash: `SHA-${n.slice(-3)}`
        },
        i = h ? ["verify"] : ["sign"];
        break;
    case "RS256":
    case "RS384":
    case "RS512":
        a = {
            name: "RSASSA-PKCS1-v1_5",
            hash: `SHA-${n.slice(-3)}`
        },
        i = h ? ["verify"] : ["sign"];
        break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
        a = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(n.slice(-3), 10) || 1}`
        },
        i = h ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
        break;
    case "ES256":
        a = {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        i = h ? ["verify"] : ["sign"];
        break;
    case "ES384":
        a = {
            name: "ECDSA",
            namedCurve: "P-384"
        },
        i = h ? ["verify"] : ["sign"];
        break;
    case "ES512":
        a = {
            name: "ECDSA",
            namedCurve: "P-521"
        },
        i = h ? ["verify"] : ["sign"];
        break;
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW":
        {
            let p = qt(f);
            a = p.startsWith("P-") ? {
                name: "ECDH",
                namedCurve: p
            } : {
                name: p
            },
            i = h ? [] : ["deriveBits"];
            break
        }
    case "EdDSA":
        a = {
            name: qt(f)
        },
        i = h ? ["verify"] : ["sign"];
        break;
    default:
        throw new y('Invalid or unsupported "alg" (Algorithm) value')
    }
    return m.subtle.importKey(t, f, a, o?.extractable ?? !1, i)
})
  , rr = (e, t, r) => tr(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, "pkcs8", e, t, r)
  , at = (e, t, r) => tr(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, "spki", e, t, r);
function Zt(e) {
    let t = []
      , r = 0;
    for (; r < e.length; ) {
        let n = nr(e.subarray(r));
        t.push(n),
        r += n.byteLength
    }
    return t
}
function nr(e) {
    let t = 0
      , r = e[0] & 31;
    if (t++,
    r === 31) {
        for (r = 0; e[t] >= 128; )
            r = r * 128 + e[t] - 128,
            t++;
        r = r * 128 + e[t] - 128,
        t++
    }
    let n = 0;
    if (e[t] < 128)
        n = e[t],
        t++;
    else if (n === 128) {
        for (n = 0; e[t + n] !== 0 || e[t + n + 1] !== 0; ) {
            if (n > e.byteLength)
                throw new TypeError("invalid indefinite form length");
            n++
        }
        let a = t + n + 2;
        return {
            byteLength: a,
            contents: e.subarray(t, t + n),
            raw: e.subarray(0, a)
        }
    } else {
        let a = e[t] & 127;
        t++,
        n = 0;
        for (let i = 0; i < a; i++)
            n = n * 256 + e[t],
            t++
    }
    let o = t + n;
    return {
        byteLength: o,
        contents: e.subarray(t, o),
        raw: e.subarray(0, o)
    }
}
function Mr(e) {
    let t = Zt(Zt(nr(e).contents)[0].contents);
    return Oe(t[t[0].raw[0] === 160 ? 6 : 5].raw)
}
function Nr(e) {
    let t = e.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, "")
      , r = qe(t);
    return ot(Mr(r), "PUBLIC KEY")
}
var or = (e, t, r) => {
    let n;
    try {
        n = Nr(e)
    } catch (o) {
        throw new TypeError("Failed to parse the X.509 certificate",{
            cause: o
        })
    }
    return at(n, t, r)
}
;
function Lr(e, t, r) {
    return s(this, null, function*() {
        if (typeof e != "string" || e.indexOf("-----BEGIN PUBLIC KEY-----") !== 0)
            throw new TypeError('"spki" must be SPKI formatted string');
        return at(e, t, r)
    })
}
function kr(e, t, r) {
    return s(this, null, function*() {
        if (typeof e != "string" || e.indexOf("-----BEGIN CERTIFICATE-----") !== 0)
            throw new TypeError('"x509" must be X.509 formatted string');
        return or(e, t, r)
    })
}
function $r(e, t, r) {
    return s(this, null, function*() {
        if (typeof e != "string" || e.indexOf("-----BEGIN PRIVATE KEY-----") !== 0)
            throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
        return rr(e, t, r)
    })
}
function $(e, t) {
    return s(this, null, function*() {
        if (!E(e))
            throw new TypeError("JWK must be an object");
        switch (t || (t = e.alg),
        e.kty) {
        case "oct":
            if (typeof e.k != "string" || !e.k)
                throw new TypeError('missing "k" (Key Value) Parameter value');
            return K(e.k);
        case "RSA":
            if (e.oth !== void 0)
                throw new y('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
        case "EC":
        case "OKP":
            return $e(w(d({}, e), {
                alg: t
            }));
        default:
            throw new y('Unsupported "kty" (Key Type) Parameter value')
        }
    })
}
var ue = e => e?.[Symbol.toStringTag]
  , it = (e, t, r) => {
    if (t.use !== void 0 && t.use !== "sig")
        throw new TypeError("Invalid key for this operation, when present its use must be sig");
    if (t.key_ops !== void 0 && t.key_ops.includes?.(r) !== !0)
        throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${r}`);
    if (t.alg !== void 0 && t.alg !== e)
        throw new TypeError(`Invalid key for this operation, when present its alg must be ${e}`);
    return !0
}
  , Br = (e, t, r, n) => {
    if (!(t instanceof Uint8Array)) {
        if (n && k(t)) {
            if (zt(t) && it(e, t, r))
                return;
            throw new TypeError('JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present')
        }
        if (!rt(t))
            throw new TypeError(tt(e, t, ...x, "Uint8Array", n ? "JSON Web Key" : null));
        if (t.type !== "secret")
            throw new TypeError(`${ue(t)} instances for symmetric algorithms must be of type "secret"`)
    }
}
  , Fr = (e, t, r, n) => {
    if (n && k(t))
        switch (r) {
        case "sign":
            if (Gt(t) && it(e, t, r))
                return;
            throw new TypeError("JSON Web Key for this operation be a private JWK");
        case "verify":
            if (Vt(t) && it(e, t, r))
                return;
            throw new TypeError("JSON Web Key for this operation be a public JWK")
        }
    if (!rt(t))
        throw new TypeError(tt(e, t, ...x, n ? "JSON Web Key" : null));
    if (t.type === "secret")
        throw new TypeError(`${ue(t)} instances for asymmetric algorithms must not be of type "secret"`);
    if (r === "sign" && t.type === "public")
        throw new TypeError(`${ue(t)} instances for asymmetric algorithm signing must be of type "private"`);
    if (r === "decrypt" && t.type === "public")
        throw new TypeError(`${ue(t)} instances for asymmetric algorithm decryption must be of type "private"`);
    if (t.algorithm && r === "verify" && t.type === "private")
        throw new TypeError(`${ue(t)} instances for asymmetric algorithm verifying must be of type "public"`);
    if (t.algorithm && r === "encrypt" && t.type === "private")
        throw new TypeError(`${ue(t)} instances for asymmetric algorithm encryption must be of type "public"`)
}
;
function ar(e, t, r, n) {
    t.startsWith("HS") || t === "dir" || t.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(t) ? Br(t, r, n, e) : Fr(t, r, n, e)
}
var Fe = ar.bind(void 0, !1)
  , Se = ar.bind(void 0, !0);
function Gr(e, t, r, n, o) {
    return s(this, null, function*() {
        if (!(r instanceof Uint8Array))
            throw new TypeError(_(r, "Uint8Array"));
        let a = parseInt(e.slice(1, 4), 10)
          , i = yield m.subtle.importKey("raw", r.subarray(a >> 3), "AES-CBC", !1, ["encrypt"])
          , f = yield m.subtle.importKey("raw", r.subarray(0, a >> 3), {
            hash: `SHA-${a << 1}`,
            name: "HMAC"
        }, !1, ["sign"])
          , h = new Uint8Array(yield m.subtle.encrypt({
            iv: n,
            name: "AES-CBC"
        }, i, t))
          , p = I(o, n, h, ve(o.length << 3))
          , l = new Uint8Array((yield m.subtle.sign("HMAC", f, p)).slice(0, a >> 3));
        return {
            ciphertext: h,
            tag: l,
            iv: n
        }
    })
}
function Vr(e, t, r, n, o) {
    return s(this, null, function*() {
        let a;
        r instanceof Uint8Array ? a = yield m.subtle.importKey("raw", r, "AES-GCM", !1, ["encrypt"]) : (D(r, e, "encrypt"),
        a = r);
        let i = new Uint8Array(yield m.subtle.encrypt({
            additionalData: o,
            iv: n,
            name: "AES-GCM",
            tagLength: 128
        }, a, t))
          , f = i.slice(-16);
        return {
            ciphertext: i.slice(0, -16),
            tag: f,
            iv: n
        }
    })
}
var zr = (e, t, r, n, o) => s(void 0, null, function*() {
    if (!C(r) && !(r instanceof Uint8Array))
        throw new TypeError(_(r, ...x, "Uint8Array"));
    switch (n ? Ue(e, n) : n = vt(e),
    e) {
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
        return r instanceof Uint8Array && se(r, parseInt(e.slice(-3), 10)),
        Gr(e, t, r, n, o);
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
        return r instanceof Uint8Array && se(r, parseInt(e.slice(1, 4), 10)),
        Vr(e, t, r, n, o);
    default:
        throw new y("Unsupported JWE Content Encryption Algorithm")
    }
})
  , Ge = zr;
function ir(e, t, r, n) {
    return s(this, null, function*() {
        let o = e.slice(0, 7)
          , a = yield Ge(o, r, t, n, new Uint8Array(0));
        return {
            encryptedKey: a.ciphertext,
            iv: b(a.iv),
            tag: b(a.tag)
        }
    })
}
function sr(e, t, r, n, o) {
    return s(this, null, function*() {
        let a = e.slice(0, 7);
        return Ne(a, t, r, n, o, new Uint8Array(0))
    })
}
function Xr(e, t, r, n, o) {
    return s(this, null, function*() {
        switch (Fe(e, t, "decrypt"),
        t = (yield te.normalizePrivateKey?.(t, e)) || t,
        e) {
        case "dir":
            {
                if (r !== void 0)
                    throw new c("Encountered unexpected JWE Encrypted Key");
                return t
            }
        case "ECDH-ES":
            if (r !== void 0)
                throw new c("Encountered unexpected JWE Encrypted Key");
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
            {
                if (!E(n.epk))
                    throw new c('JOSE Header "epk" (Ephemeral Public Key) missing or invalid');
                if (!ke(t))
                    throw new y("ECDH with the provided key is not allowed or not supported by your javascript runtime");
                let a = yield $(n.epk, e), i, f;
                if (n.apu !== void 0) {
                    if (typeof n.apu != "string")
                        throw new c('JOSE Header "apu" (Agreement PartyUInfo) invalid');
                    try {
                        i = K(n.apu)
                    } catch {
                        throw new c("Failed to base64url decode the apu")
                    }
                }
                if (n.apv !== void 0) {
                    if (typeof n.apv != "string")
                        throw new c('JOSE Header "apv" (Agreement PartyVInfo) invalid');
                    try {
                        f = K(n.apv)
                    } catch {
                        throw new c("Failed to base64url decode the apv")
                    }
                }
                let h = yield Le(a, t, e === "ECDH-ES" ? n.enc : e, e === "ECDH-ES" ? Ee(n.enc) : parseInt(e.slice(-5, -2), 10), i, f);
                if (e === "ECDH-ES")
                    return h;
                if (r === void 0)
                    throw new c("JWE Encrypted Key missing");
                return we(e.slice(-6), h, r)
            }
        case "RSA1_5":
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
            {
                if (r === void 0)
                    throw new c("JWE Encrypted Key missing");
                return Ft(e, t, r)
            }
        case "PBES2-HS256+A128KW":
        case "PBES2-HS384+A192KW":
        case "PBES2-HS512+A256KW":
            {
                if (r === void 0)
                    throw new c("JWE Encrypted Key missing");
                if (typeof n.p2c != "number")
                    throw new c('JOSE Header "p2c" (PBES2 Count) missing or invalid');
                let a = o?.maxPBES2Count || 1e4;
                if (n.p2c > a)
                    throw new c('JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds');
                if (typeof n.p2s != "string")
                    throw new c('JOSE Header "p2s" (PBES2 Salt) missing or invalid');
                let i;
                try {
                    i = K(n.p2s)
                } catch {
                    throw new c("Failed to base64url decode the p2s")
                }
                return $t(e, t, r, n.p2c, i)
            }
        case "A128KW":
        case "A192KW":
        case "A256KW":
            {
                if (r === void 0)
                    throw new c("JWE Encrypted Key missing");
                return we(e, t, r)
            }
        case "A128GCMKW":
        case "A192GCMKW":
        case "A256GCMKW":
            {
                if (r === void 0)
                    throw new c("JWE Encrypted Key missing");
                if (typeof n.iv != "string")
                    throw new c('JOSE Header "iv" (Initialization Vector) missing or invalid');
                if (typeof n.tag != "string")
                    throw new c('JOSE Header "tag" (Authentication Tag) missing or invalid');
                let a;
                try {
                    a = K(n.iv)
                } catch {
                    throw new c("Failed to base64url decode the iv")
                }
                let i;
                try {
                    i = K(n.tag)
                } catch {
                    throw new c("Failed to base64url decode the tag")
                }
                return sr(e, t, r, a, i)
            }
        default:
            throw new y('Invalid or unsupported "alg" (JWE Algorithm) header value')
        }
    })
}
var cr = Xr;
function Yr(e, t, r, n, o) {
    if (o.crit !== void 0 && n?.crit === void 0)
        throw new e('"crit" (Critical) Header Parameter MUST be integrity protected');
    if (!n || n.crit === void 0)
        return new Set;
    if (!Array.isArray(n.crit) || n.crit.length === 0 || n.crit.some(i => typeof i != "string" || i.length === 0))
        throw new e('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
    let a;
    r !== void 0 ? a = new Map([...Object.entries(r), ...t.entries()]) : a = t;
    for (let i of n.crit) {
        if (!a.has(i))
            throw new y(`Extension Header Parameter "${i}" is not recognized`);
        if (o[i] === void 0)
            throw new e(`Extension Header Parameter "${i}" is missing`);
        if (a.get(i) && n[i] === void 0)
            throw new e(`Extension Header Parameter "${i}" MUST be integrity protected`)
    }
    return new Set(n.crit)
}
var N = Yr;
var qr = (e, t) => {
    if (t !== void 0 && (!Array.isArray(t) || t.some(r => typeof r != "string")))
        throw new TypeError(`"${e}" option must be an array of strings`);
    if (t)
        return new Set(t)
}
  , ge = qr;
function Ae(e, t, r) {
    return s(this, null, function*() {
        if (!E(e))
            throw new c("Flattened JWE must be an object");
        if (e.protected === void 0 && e.header === void 0 && e.unprotected === void 0)
            throw new c("JOSE Header missing");
        if (e.iv !== void 0 && typeof e.iv != "string")
            throw new c("JWE Initialization Vector incorrect type");
        if (typeof e.ciphertext != "string")
            throw new c("JWE Ciphertext missing or incorrect type");
        if (e.tag !== void 0 && typeof e.tag != "string")
            throw new c("JWE Authentication Tag incorrect type");
        if (e.protected !== void 0 && typeof e.protected != "string")
            throw new c("JWE Protected Header incorrect type");
        if (e.encrypted_key !== void 0 && typeof e.encrypted_key != "string")
            throw new c("JWE Encrypted Key incorrect type");
        if (e.aad !== void 0 && typeof e.aad != "string")
            throw new c("JWE AAD incorrect type");
        if (e.header !== void 0 && !E(e.header))
            throw new c("JWE Shared Unprotected Header incorrect type");
        if (e.unprotected !== void 0 && !E(e.unprotected))
            throw new c("JWE Per-Recipient Unprotected Header incorrect type");
        let n;
        if (e.protected)
            try {
                let F = K(e.protected);
                n = JSON.parse(H.decode(F))
            } catch {
                throw new c("JWE Protected Header is invalid")
            }
        if (!U(n, e.header, e.unprotected))
            throw new c("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
        let o = d(d(d({}, n), e.header), e.unprotected);
        if (N(c, new Map, r?.crit, n, o),
        o.zip !== void 0)
            throw new y('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
        let {alg: a, enc: i} = o;
        if (typeof a != "string" || !a)
            throw new c("missing JWE Algorithm (alg) in JWE Header");
        if (typeof i != "string" || !i)
            throw new c("missing JWE Encryption Algorithm (enc) in JWE Header");
        let f = r && ge("keyManagementAlgorithms", r.keyManagementAlgorithms)
          , h = r && ge("contentEncryptionAlgorithms", r.contentEncryptionAlgorithms);
        if (f && !f.has(a) || !f && a.startsWith("PBES2"))
            throw new ie('"alg" (Algorithm) Header Parameter value not allowed');
        if (h && !h.has(i))
            throw new ie('"enc" (Encryption Algorithm) Header Parameter value not allowed');
        let p;
        if (e.encrypted_key !== void 0)
            try {
                p = K(e.encrypted_key)
            } catch {
                throw new c("Failed to base64url decode the encrypted_key")
            }
        let l = !1;
        typeof t == "function" && (t = yield t(n, e),
        l = !0);
        let u;
        try {
            u = yield cr(a, t, p, o, r)
        } catch (F) {
            if (F instanceof TypeError || F instanceof c || F instanceof y)
                throw F;
            u = M(i)
        }
        let P, v;
        if (e.iv !== void 0)
            try {
                P = K(e.iv)
            } catch {
                throw new c("Failed to base64url decode the iv")
            }
        if (e.tag !== void 0)
            try {
                v = K(e.tag)
            } catch {
                throw new c("Failed to base64url decode the tag")
            }
        let g = A.encode(e.protected ?? ""), W;
        e.aad !== void 0 ? W = I(g, A.encode("."), A.encode(e.aad)) : W = g;
        let Z;
        try {
            Z = K(e.ciphertext)
        } catch {
            throw new c("Failed to base64url decode the ciphertext")
        }
        let B = {
            plaintext: yield Ne(i, u, Z, P, v, W)
        };
        if (e.protected !== void 0 && (B.protectedHeader = n),
        e.aad !== void 0)
            try {
                B.additionalAuthenticatedData = K(e.aad)
            } catch {
                throw new c("Failed to base64url decode the aad")
            }
        return e.unprotected !== void 0 && (B.sharedUnprotectedHeader = e.unprotected),
        e.header !== void 0 && (B.unprotectedHeader = e.header),
        l ? w(d({}, B), {
            key: t
        }) : B
    })
}
function st(e, t, r) {
    return s(this, null, function*() {
        if (e instanceof Uint8Array && (e = H.decode(e)),
        typeof e != "string")
            throw new c("Compact JWE must be a string or Uint8Array");
        let {0: n, 1: o, 2: a, 3: i, 4: f, length: h} = e.split(".");
        if (h !== 5)
            throw new c("Invalid Compact JWE");
        let p = yield Ae({
            ciphertext: i,
            iv: a || void 0,
            protected: n,
            tag: f || void 0,
            encrypted_key: o || void 0
        }, t, r)
          , l = {
            plaintext: p.plaintext,
            protectedHeader: p.protectedHeader
        };
        return typeof t == "function" ? w(d({}, l), {
            key: p.key
        }) : l
    })
}
function Zr(e, t, r) {
    return s(this, null, function*() {
        if (!E(e))
            throw new c("General JWE must be an object");
        if (!Array.isArray(e.recipients) || !e.recipients.every(E))
            throw new c("JWE Recipients missing or incorrect type");
        if (!e.recipients.length)
            throw new c("JWE Recipients has no members");
        for (let n of e.recipients)
            try {
                return yield Ae({
                    aad: e.aad,
                    ciphertext: e.ciphertext,
                    encrypted_key: n.encrypted_key,
                    header: n.header,
                    iv: e.iv,
                    protected: e.protected,
                    tag: e.tag,
                    unprotected: e.unprotected
                }, t, r)
            } catch {}
        throw new j
    })
}
var Ve = Symbol();
var Qr = e => s(void 0, null, function*() {
    if (e instanceof Uint8Array)
        return {
            kty: "oct",
            k: b(e)
        };
    if (!C(e))
        throw new TypeError(_(e, ...x, "Uint8Array"));
    if (!e.extractable)
        throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
    let i = yield m.subtle.exportKey("jwk", e)
      , {ext: t, key_ops: r, alg: n, use: o} = i;
    return Q(i, ["ext", "key_ops", "alg", "use"])
})
  , dr = Qr;
function jr(e) {
    return s(this, null, function*() {
        return jt(e)
    })
}
function en(e) {
    return s(this, null, function*() {
        return er(e)
    })
}
function ct(e) {
    return s(this, null, function*() {
        return dr(e)
    })
}
function tn(a, i, f, h) {
    return s(this, arguments, function*(e, t, r, n, o={}) {
        var P, v;
        let p, l, u;
        switch (Fe(e, r, "encrypt"),
        r = (yield te.normalizePublicKey?.(r, e)) || r,
        e) {
        case "dir":
            {
                u = r;
                break
            }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
            {
                if (!ke(r))
                    throw new y("ECDH with the provided key is not allowed or not supported by your javascript runtime");
                let {apu: g, apv: W} = o
                  , {epk: Z} = o;
                Z || (Z = (yield Mt(r)).privateKey);
                let {x: bt, y: B, crv: F, kty: Kt} = yield ct(Z)
                  , xt = yield Le(r, Z, e === "ECDH-ES" ? t : e, e === "ECDH-ES" ? Ee(t) : parseInt(e.slice(-5, -2), 10), g, W);
                if (l = {
                    epk: {
                        x: bt,
                        crv: F,
                        kty: Kt
                    }
                },
                Kt === "EC" && (l.epk.y = B),
                g && (l.apu = b(g)),
                W && (l.apv = b(W)),
                e === "ECDH-ES") {
                    u = xt;
                    break
                }
                u = n || M(t);
                let gr = e.slice(-6);
                p = yield ye(gr, xt, u);
                break
            }
        case "RSA1_5":
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
            {
                u = n || M(t),
                p = yield Bt(e, r, u);
                break
            }
        case "PBES2-HS256+A128KW":
        case "PBES2-HS384+A192KW":
        case "PBES2-HS512+A256KW":
            {
                u = n || M(t);
                let {p2c: g, p2s: W} = o;
                P = yield kt(e, r, u, g, W),
                {encryptedKey: p} = P,
                l = Q(P, ["encryptedKey"]);
                break
            }
        case "A128KW":
        case "A192KW":
        case "A256KW":
            {
                u = n || M(t),
                p = yield ye(e, r, u);
                break
            }
        case "A128GCMKW":
        case "A192GCMKW":
        case "A256GCMKW":
            {
                u = n || M(t);
                let {iv: g} = o;
                v = yield ir(e, r, u, g),
                {encryptedKey: p} = v,
                l = Q(v, ["encryptedKey"]);
                break
            }
        default:
            throw new y('Invalid or unsupported "alg" (JWE Algorithm) header value')
        }
        return {
            cek: u,
            encryptedKey: p,
            parameters: l
        }
    })
}
var ze = tn;
var X = class {
    constructor(t) {
        if (!(t instanceof Uint8Array))
            throw new TypeError("plaintext must be an instance of Uint8Array");
        this._plaintext = t
    }
    setKeyManagementParameters(t) {
        if (this._keyManagementParameters)
            throw new TypeError("setKeyManagementParameters can only be called once");
        return this._keyManagementParameters = t,
        this
    }
    setProtectedHeader(t) {
        if (this._protectedHeader)
            throw new TypeError("setProtectedHeader can only be called once");
        return this._protectedHeader = t,
        this
    }
    setSharedUnprotectedHeader(t) {
        if (this._sharedUnprotectedHeader)
            throw new TypeError("setSharedUnprotectedHeader can only be called once");
        return this._sharedUnprotectedHeader = t,
        this
    }
    setUnprotectedHeader(t) {
        if (this._unprotectedHeader)
            throw new TypeError("setUnprotectedHeader can only be called once");
        return this._unprotectedHeader = t,
        this
    }
    setAdditionalAuthenticatedData(t) {
        return this._aad = t,
        this
    }
    setContentEncryptionKey(t) {
        if (this._cek)
            throw new TypeError("setContentEncryptionKey can only be called once");
        return this._cek = t,
        this
    }
    setInitializationVector(t) {
        if (this._iv)
            throw new TypeError("setInitializationVector can only be called once");
        return this._iv = t,
        this
    }
    encrypt(t, r) {
        return s(this, null, function*() {
            if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader)
                throw new c("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
            if (!U(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader))
                throw new c("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
            let n = d(d(d({}, this._protectedHeader), this._unprotectedHeader), this._sharedUnprotectedHeader);
            if (N(c, new Map, r?.crit, this._protectedHeader, n),
            n.zip !== void 0)
                throw new y('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
            let {alg: o, enc: a} = n;
            if (typeof o != "string" || !o)
                throw new c('JWE "alg" (Algorithm) Header Parameter missing or invalid');
            if (typeof a != "string" || !a)
                throw new c('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
            let i;
            if (this._cek && (o === "dir" || o === "ECDH-ES"))
                throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${o}`);
            let f;
            {
                let W;
                ({cek: f, encryptedKey: i, parameters: W} = yield ze(o, a, t, this._cek, this._keyManagementParameters)),
                W && (r && Ve in r ? this._unprotectedHeader ? this._unprotectedHeader = d(d({}, this._unprotectedHeader), W) : this.setUnprotectedHeader(W) : this._protectedHeader ? this._protectedHeader = d(d({}, this._protectedHeader), W) : this.setProtectedHeader(W))
            }
            let h, p, l;
            this._protectedHeader ? p = A.encode(b(JSON.stringify(this._protectedHeader))) : p = A.encode(""),
            this._aad ? (l = b(this._aad),
            h = I(p, A.encode("."), A.encode(l))) : h = p;
            let {ciphertext: u, tag: P, iv: v} = yield Ge(a, this._plaintext, f, this._iv, h)
              , g = {
                ciphertext: b(u)
            };
            return v && (g.iv = b(v)),
            P && (g.tag = b(P)),
            i && (g.encrypted_key = b(i)),
            l && (g.aad = l),
            this._protectedHeader && (g.protected = H.decode(p)),
            this._sharedUnprotectedHeader && (g.unprotected = this._sharedUnprotectedHeader),
            this._unprotectedHeader && (g.header = this._unprotectedHeader),
            g
        })
    }
}
;
var dt = class {
    constructor(t, r, n) {
        this.parent = t,
        this.key = r,
        this.options = n
    }
    setUnprotectedHeader(t) {
        if (this.unprotectedHeader)
            throw new TypeError("setUnprotectedHeader can only be called once");
        return this.unprotectedHeader = t,
        this
    }
    addRecipient(...t) {
        return this.parent.addRecipient(...t)
    }
    encrypt(...t) {
        return this.parent.encrypt(...t)
    }
    done() {
        return this.parent
    }
}
  , pt = class {
    constructor(t) {
        this._recipients = [],
        this._plaintext = t
    }
    addRecipient(t, r) {
        let n = new dt(this,t,{
            crit: r?.crit
        });
        return this._recipients.push(n),
        n
    }
    setProtectedHeader(t) {
        if (this._protectedHeader)
            throw new TypeError("setProtectedHeader can only be called once");
        return this._protectedHeader = t,
        this
    }
    setSharedUnprotectedHeader(t) {
        if (this._unprotectedHeader)
            throw new TypeError("setSharedUnprotectedHeader can only be called once");
        return this._unprotectedHeader = t,
        this
    }
    setAdditionalAuthenticatedData(t) {
        return this._aad = t,
        this
    }
    encrypt() {
        return s(this, null, function*() {
            if (!this._recipients.length)
                throw new c("at least one recipient must be added");
            if (this._recipients.length === 1) {
                let[o] = this._recipients
                  , a = yield new X(this._plaintext).setAdditionalAuthenticatedData(this._aad).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(o.unprotectedHeader).encrypt(o.key, d({}, o.options))
                  , i = {
                    ciphertext: a.ciphertext,
                    iv: a.iv,
                    recipients: [{}],
                    tag: a.tag
                };
                return a.aad && (i.aad = a.aad),
                a.protected && (i.protected = a.protected),
                a.unprotected && (i.unprotected = a.unprotected),
                a.encrypted_key && (i.recipients[0].encrypted_key = a.encrypted_key),
                a.header && (i.recipients[0].header = a.header),
                i
            }
            let t;
            for (let o = 0; o < this._recipients.length; o++) {
                let a = this._recipients[o];
                if (!U(this._protectedHeader, this._unprotectedHeader, a.unprotectedHeader))
                    throw new c("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
                let i = d(d(d({}, this._protectedHeader), this._unprotectedHeader), a.unprotectedHeader)
                  , {alg: f} = i;
                if (typeof f != "string" || !f)
                    throw new c('JWE "alg" (Algorithm) Header Parameter missing or invalid');
                if (f === "dir" || f === "ECDH-ES")
                    throw new c('"dir" and "ECDH-ES" alg may only be used with a single recipient');
                if (typeof i.enc != "string" || !i.enc)
                    throw new c('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
                if (!t)
                    t = i.enc;
                else if (t !== i.enc)
                    throw new c('JWE "enc" (Encryption Algorithm) Header Parameter must be the same for all recipients');
                if (N(c, new Map, a.options.crit, this._protectedHeader, i),
                i.zip !== void 0)
                    throw new y('JWE "zip" (Compression Algorithm) Header Parameter is not supported.')
            }
            let r = M(t)
              , n = {
                ciphertext: "",
                iv: "",
                recipients: [],
                tag: ""
            };
            for (let o = 0; o < this._recipients.length; o++) {
                let a = this._recipients[o]
                  , i = {};
                n.recipients.push(i);
                let h = d(d(d({}, this._protectedHeader), this._unprotectedHeader), a.unprotectedHeader).alg.startsWith("PBES2") ? 2048 + o : void 0;
                if (o === 0) {
                    let u = yield new X(this._plaintext).setAdditionalAuthenticatedData(this._aad).setContentEncryptionKey(r).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(a.unprotectedHeader).setKeyManagementParameters({
                        p2c: h
                    }).encrypt(a.key, w(d({}, a.options), {
                        [Ve]: !0
                    }));
                    n.ciphertext = u.ciphertext,
                    n.iv = u.iv,
                    n.tag = u.tag,
                    u.aad && (n.aad = u.aad),
                    u.protected && (n.protected = u.protected),
                    u.unprotected && (n.unprotected = u.unprotected),
                    i.encrypted_key = u.encrypted_key,
                    u.header && (i.header = u.header);
                    continue
                }
                let {encryptedKey: p, parameters: l} = yield ze(a.unprotectedHeader?.alg || this._protectedHeader?.alg || this._unprotectedHeader?.alg, t, a.key, r, {
                    p2c: h
                });
                i.encrypted_key = b(p),
                (a.unprotectedHeader || l) && (i.header = d(d({}, a.unprotectedHeader), l))
            }
            return n
        })
    }
}
;
function be(e, t) {
    let r = `SHA-${e.slice(-3)}`;
    switch (e) {
    case "HS256":
    case "HS384":
    case "HS512":
        return {
            hash: r,
            name: "HMAC"
        };
    case "PS256":
    case "PS384":
    case "PS512":
        return {
            hash: r,
            name: "RSA-PSS",
            saltLength: e.slice(-3) >> 3
        };
    case "RS256":
    case "RS384":
    case "RS512":
        return {
            hash: r,
            name: "RSASSA-PKCS1-v1_5"
        };
    case "ES256":
    case "ES384":
    case "ES512":
        return {
            hash: r,
            name: "ECDSA",
            namedCurve: t.namedCurve
        };
    case "EdDSA":
        return {
            name: t.name
        };
    default:
        throw new y(`alg ${e} is not supported either by JOSE or your javascript runtime`)
    }
}
function Ke(e, t, r) {
    return s(this, null, function*() {
        if (r === "sign" && (t = yield te.normalizePrivateKey(t, e)),
        r === "verify" && (t = yield te.normalizePublicKey(t, e)),
        C(t))
            return Ot(t, e, r),
            t;
        if (t instanceof Uint8Array) {
            if (!e.startsWith("HS"))
                throw new TypeError(_(t, ...x));
            return m.subtle.importKey("raw", t, {
                hash: `SHA-${e.slice(-3)}`,
                name: "HMAC"
            }, !1, [r])
        }
        throw new TypeError(_(t, ...x, "Uint8Array", "JSON Web Key"))
    })
}
var rn = (e, t, r, n) => s(void 0, null, function*() {
    let o = yield Ke(e, t, "verify");
    ee(e, o);
    let a = be(e, o.algorithm);
    try {
        return yield m.subtle.verify(a, o, r, n)
    } catch {
        return !1
    }
})
  , pr = rn;
function xe(e, t, r) {
    return s(this, null, function*() {
        if (!E(e))
            throw new S("Flattened JWS must be an object");
        if (e.protected === void 0 && e.header === void 0)
            throw new S('Flattened JWS must have either of the "protected" or "header" members');
        if (e.protected !== void 0 && typeof e.protected != "string")
            throw new S("JWS Protected Header incorrect type");
        if (e.payload === void 0)
            throw new S("JWS Payload missing");
        if (typeof e.signature != "string")
            throw new S("JWS Signature missing or incorrect type");
        if (e.header !== void 0 && !E(e.header))
            throw new S("JWS Unprotected Header incorrect type");
        let n = {};
        if (e.protected)
            try {
                let W = K(e.protected);
                n = JSON.parse(H.decode(W))
            } catch {
                throw new S("JWS Protected Header is invalid")
            }
        if (!U(n, e.header))
            throw new S("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
        let o = d(d({}, n), e.header)
          , a = N(S, new Map([["b64", !0]]), r?.crit, n, o)
          , i = !0;
        if (a.has("b64") && (i = n.b64,
        typeof i != "boolean"))
            throw new S('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
        let {alg: f} = o;
        if (typeof f != "string" || !f)
            throw new S('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        let h = r && ge("algorithms", r.algorithms);
        if (h && !h.has(f))
            throw new ie('"alg" (Algorithm) Header Parameter value not allowed');
        if (i) {
            if (typeof e.payload != "string")
                throw new S("JWS Payload must be a string")
        } else if (typeof e.payload != "string" && !(e.payload instanceof Uint8Array))
            throw new S("JWS Payload must be a string or an Uint8Array instance");
        let p = !1;
        typeof t == "function" ? (t = yield t(n, e),
        p = !0,
        Se(f, t, "verify"),
        k(t) && (t = yield $(t, f))) : Se(f, t, "verify");
        let l = I(A.encode(e.protected ?? ""), A.encode("."), typeof e.payload == "string" ? A.encode(e.payload) : e.payload), u;
        try {
            u = K(e.signature)
        } catch {
            throw new S("Failed to base64url decode the signature")
        }
        if (!(yield pr(f, t, u, l)))
            throw new me;
        let v;
        if (i)
            try {
                v = K(e.payload)
            } catch {
                throw new S("Failed to base64url decode the payload")
            }
        else
            typeof e.payload == "string" ? v = A.encode(e.payload) : v = e.payload;
        let g = {
            payload: v
        };
        return e.protected !== void 0 && (g.protectedHeader = n),
        e.header !== void 0 && (g.unprotectedHeader = e.header),
        p ? w(d({}, g), {
            key: t
        }) : g
    })
}
function ft(e, t, r) {
    return s(this, null, function*() {
        if (e instanceof Uint8Array && (e = H.decode(e)),
        typeof e != "string")
            throw new S("Compact JWS must be a string or Uint8Array");
        let {0: n, 1: o, 2: a, length: i} = e.split(".");
        if (i !== 3)
            throw new S("Invalid Compact JWS");
        let f = yield xe({
            payload: o,
            protected: n,
            signature: a
        }, t, r)
          , h = {
            payload: f.payload,
            protectedHeader: f.protectedHeader
        };
        return typeof t == "function" ? w(d({}, h), {
            key: f.key
        }) : h
    })
}
function nn(e, t, r) {
    return s(this, null, function*() {
        if (!E(e))
            throw new S("General JWS must be an object");
        if (!Array.isArray(e.signatures) || !e.signatures.every(E))
            throw new S("JWS Signatures missing or incorrect type");
        for (let n of e.signatures)
            try {
                return yield xe({
                    header: n.header,
                    payload: e.payload,
                    protected: n.protected,
                    signature: n.signature
                }, t, r)
            } catch {}
        throw new me
    })
}
var L = e => Math.floor(e.getTime() / 1e3);
var on = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i
  , re = e => {
    let t = on.exec(e);
    if (!t || t[4] && t[1])
        throw new TypeError("Invalid time period format");
    let r = parseFloat(t[2]), n = t[3].toLowerCase(), o;
    switch (n) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
        o = Math.round(r);
        break;
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
        o = Math.round(r * 60);
        break;
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
        o = Math.round(r * 3600);
        break;
    case "day":
    case "days":
    case "d":
        o = Math.round(r * 86400);
        break;
    case "week":
    case "weeks":
    case "w":
        o = Math.round(r * 604800);
        break;
    default:
        o = Math.round(r * 31557600);
        break
    }
    return t[1] === "-" || t[4] === "ago" ? -o : o
}
;
var fr = e => e.toLowerCase().replace(/^application\//, "")
  , an = (e, t) => typeof e == "string" ? t.includes(e) : Array.isArray(e) ? t.some(Set.prototype.has.bind(new Set(e))) : !1
  , le = (e, t, r={}) => {
    let n;
    try {
        n = JSON.parse(H.decode(t))
    } catch {}
    if (!E(n))
        throw new J("JWT Claims Set must be a top-level JSON object");
    let {typ: o} = r;
    if (o && (typeof e.typ != "string" || fr(e.typ) !== fr(o)))
        throw new R('unexpected "typ" JWT header value',n,"typ","check_failed");
    let {requiredClaims: a=[], issuer: i, subject: f, audience: h, maxTokenAge: p} = r
      , l = [...a];
    p !== void 0 && l.push("iat"),
    h !== void 0 && l.push("aud"),
    f !== void 0 && l.push("sub"),
    i !== void 0 && l.push("iss");
    for (let g of new Set(l.reverse()))
        if (!(g in n))
            throw new R(`missing required "${g}" claim`,n,g,"missing");
    if (i && !(Array.isArray(i) ? i : [i]).includes(n.iss))
        throw new R('unexpected "iss" claim value',n,"iss","check_failed");
    if (f && n.sub !== f)
        throw new R('unexpected "sub" claim value',n,"sub","check_failed");
    if (h && !an(n.aud, typeof h == "string" ? [h] : h))
        throw new R('unexpected "aud" claim value',n,"aud","check_failed");
    let u;
    switch (typeof r.clockTolerance) {
    case "string":
        u = re(r.clockTolerance);
        break;
    case "number":
        u = r.clockTolerance;
        break;
    case "undefined":
        u = 0;
        break;
    default:
        throw new TypeError("Invalid clockTolerance option type")
    }
    let {currentDate: P} = r
      , v = L(P || new Date);
    if ((n.iat !== void 0 || p) && typeof n.iat != "number")
        throw new R('"iat" claim must be a number',n,"iat","invalid");
    if (n.nbf !== void 0) {
        if (typeof n.nbf != "number")
            throw new R('"nbf" claim must be a number',n,"nbf","invalid");
        if (n.nbf > v + u)
            throw new R('"nbf" claim timestamp check failed',n,"nbf","check_failed")
    }
    if (n.exp !== void 0) {
        if (typeof n.exp != "number")
            throw new R('"exp" claim must be a number',n,"exp","invalid");
        if (n.exp <= v - u)
            throw new Re('"exp" claim timestamp check failed',n,"exp","check_failed")
    }
    if (p) {
        let g = v - n.iat
          , W = typeof p == "number" ? p : re(p);
        if (g - u > W)
            throw new Re('"iat" claim timestamp check failed (too far in the past)',n,"iat","check_failed");
        if (g < 0 - u)
            throw new R('"iat" claim timestamp check failed (it should be in the past)',n,"iat","check_failed")
    }
    return n
}
;
function sn(e, t, r) {
    return s(this, null, function*() {
        let n = yield ft(e, t, r);
        if (n.protectedHeader.crit?.includes("b64") && n.protectedHeader.b64 === !1)
            throw new J("JWTs MUST NOT use unencoded payload");
        let a = {
            payload: le(n.protectedHeader, n.payload, r),
            protectedHeader: n.protectedHeader
        };
        return typeof t == "function" ? w(d({}, a), {
            key: n.key
        }) : a
    })
}
function cn(e, t, r) {
    return s(this, null, function*() {
        let n = yield st(e, t, r)
          , o = le(n.protectedHeader, n.plaintext, r)
          , {protectedHeader: a} = n;
        if (a.iss !== void 0 && a.iss !== o.iss)
            throw new R('replicated "iss" claim header parameter mismatch',o,"iss","mismatch");
        if (a.sub !== void 0 && a.sub !== o.sub)
            throw new R('replicated "sub" claim header parameter mismatch',o,"sub","mismatch");
        if (a.aud !== void 0 && JSON.stringify(a.aud) !== JSON.stringify(o.aud))
            throw new R('replicated "aud" claim header parameter mismatch',o,"aud","mismatch");
        let i = {
            payload: o,
            protectedHeader: a
        };
        return typeof t == "function" ? w(d({}, i), {
            key: n.key
        }) : i
    })
}
var _e = class {
    constructor(t) {
        this._flattened = new X(t)
    }
    setContentEncryptionKey(t) {
        return this._flattened.setContentEncryptionKey(t),
        this
    }
    setInitializationVector(t) {
        return this._flattened.setInitializationVector(t),
        this
    }
    setProtectedHeader(t) {
        return this._flattened.setProtectedHeader(t),
        this
    }
    setKeyManagementParameters(t) {
        return this._flattened.setKeyManagementParameters(t),
        this
    }
    encrypt(t, r) {
        return s(this, null, function*() {
            let n = yield this._flattened.encrypt(t, r);
            return [n.protected, n.encrypted_key, n.iv, n.ciphertext, n.tag].join(".")
        })
    }
}
;
var dn = (e, t, r) => s(void 0, null, function*() {
    let n = yield Ke(e, t, "sign");
    ee(e, n);
    let o = yield m.subtle.sign(be(e, n.algorithm), n, r);
    return new Uint8Array(o)
})
  , ur = dn;
var ne = class {
    constructor(t) {
        if (!(t instanceof Uint8Array))
            throw new TypeError("payload must be an instance of Uint8Array");
        this._payload = t
    }
    setProtectedHeader(t) {
        if (this._protectedHeader)
            throw new TypeError("setProtectedHeader can only be called once");
        return this._protectedHeader = t,
        this
    }
    setUnprotectedHeader(t) {
        if (this._unprotectedHeader)
            throw new TypeError("setUnprotectedHeader can only be called once");
        return this._unprotectedHeader = t,
        this
    }
    sign(t, r) {
        return s(this, null, function*() {
            if (!this._protectedHeader && !this._unprotectedHeader)
                throw new S("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
            if (!U(this._protectedHeader, this._unprotectedHeader))
                throw new S("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
            let n = d(d({}, this._protectedHeader), this._unprotectedHeader)
              , o = N(S, new Map([["b64", !0]]), r?.crit, this._protectedHeader, n)
              , a = !0;
            if (o.has("b64") && (a = this._protectedHeader.b64,
            typeof a != "boolean"))
                throw new S('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            let {alg: i} = n;
            if (typeof i != "string" || !i)
                throw new S('JWS "alg" (Algorithm) Header Parameter missing or invalid');
            Se(i, t, "sign");
            let f = this._payload;
            a && (f = A.encode(b(f)));
            let h;
            this._protectedHeader ? h = A.encode(b(JSON.stringify(this._protectedHeader))) : h = A.encode("");
            let p = I(h, A.encode("."), f)
              , l = yield ur(i, t, p)
              , u = {
                signature: b(l),
                payload: ""
            };
            return a && (u.payload = H.decode(f)),
            this._unprotectedHeader && (u.header = this._unprotectedHeader),
            this._protectedHeader && (u.protected = H.decode(h)),
            u
        })
    }
}
;
var Ce = class {
    constructor(t) {
        this._flattened = new ne(t)
    }
    setProtectedHeader(t) {
        return this._flattened.setProtectedHeader(t),
        this
    }
    sign(t, r) {
        return s(this, null, function*() {
            let n = yield this._flattened.sign(t, r);
            if (n.payload === void 0)
                throw new TypeError("use the flattened module for creating JWS with b64: false");
            return `${n.protected}.${n.payload}.${n.signature}`
        })
    }
}
;
var ut = class {
    constructor(t, r, n) {
        this.parent = t,
        this.key = r,
        this.options = n
    }
    setProtectedHeader(t) {
        if (this.protectedHeader)
            throw new TypeError("setProtectedHeader can only be called once");
        return this.protectedHeader = t,
        this
    }
    setUnprotectedHeader(t) {
        if (this.unprotectedHeader)
            throw new TypeError("setUnprotectedHeader can only be called once");
        return this.unprotectedHeader = t,
        this
    }
    addSignature(...t) {
        return this.parent.addSignature(...t)
    }
    sign(...t) {
        return this.parent.sign(...t)
    }
    done() {
        return this.parent
    }
}
  , lt = class {
    constructor(t) {
        this._signatures = [],
        this._payload = t
    }
    addSignature(t, r) {
        let n = new ut(this,t,r);
        return this._signatures.push(n),
        n
    }
    sign() {
        return s(this, null, function*() {
            if (!this._signatures.length)
                throw new S("at least one signature must be added");
            let t = {
                signatures: [],
                payload: ""
            };
            for (let n = 0; n < this._signatures.length; n++) {
                let o = this._signatures[n]
                  , a = new ne(this._payload);
                a.setProtectedHeader(o.protectedHeader),
                a.setUnprotectedHeader(o.unprotectedHeader);
                let r = yield a.sign(o.key, o.options)
                  , {payload: i} = r
                  , f = Q(r, ["payload"]);
                if (n === 0)
                    t.payload = i;
                else if (t.payload !== i)
                    throw new S("inconsistent use of JWS Unencoded Payload (RFC7797)");
                t.signatures.push(f)
            }
            return t
        })
    }
}
;
function oe(e, t) {
    if (!Number.isFinite(t))
        throw new TypeError(`Invalid ${e} input`);
    return t
}
var Y = class {
    constructor(t={}) {
        if (!E(t))
            throw new TypeError("JWT Claims Set MUST be an object");
        this._payload = t
    }
    setIssuer(t) {
        return this._payload = w(d({}, this._payload), {
            iss: t
        }),
        this
    }
    setSubject(t) {
        return this._payload = w(d({}, this._payload), {
            sub: t
        }),
        this
    }
    setAudience(t) {
        return this._payload = w(d({}, this._payload), {
            aud: t
        }),
        this
    }
    setJti(t) {
        return this._payload = w(d({}, this._payload), {
            jti: t
        }),
        this
    }
    setNotBefore(t) {
        return typeof t == "number" ? this._payload = w(d({}, this._payload), {
            nbf: oe("setNotBefore", t)
        }) : t instanceof Date ? this._payload = w(d({}, this._payload), {
            nbf: oe("setNotBefore", L(t))
        }) : this._payload = w(d({}, this._payload), {
            nbf: L(new Date) + re(t)
        }),
        this
    }
    setExpirationTime(t) {
        return typeof t == "number" ? this._payload = w(d({}, this._payload), {
            exp: oe("setExpirationTime", t)
        }) : t instanceof Date ? this._payload = w(d({}, this._payload), {
            exp: oe("setExpirationTime", L(t))
        }) : this._payload = w(d({}, this._payload), {
            exp: L(new Date) + re(t)
        }),
        this
    }
    setIssuedAt(t) {
        return typeof t > "u" ? this._payload = w(d({}, this._payload), {
            iat: L(new Date)
        }) : t instanceof Date ? this._payload = w(d({}, this._payload), {
            iat: oe("setIssuedAt", L(t))
        }) : typeof t == "string" ? this._payload = w(d({}, this._payload), {
            iat: oe("setIssuedAt", L(new Date) + re(t))
        }) : this._payload = w(d({}, this._payload), {
            iat: oe("setIssuedAt", t)
        }),
        this
    }
}
;
var ht = class extends Y {
    setProtectedHeader(t) {
        return this._protectedHeader = t,
        this
    }
    sign(t, r) {
        return s(this, null, function*() {
            let n = new Ce(A.encode(JSON.stringify(this._payload)));
            if (n.setProtectedHeader(this._protectedHeader),
            Array.isArray(this._protectedHeader?.crit) && this._protectedHeader.crit.includes("b64") && this._protectedHeader.b64 === !1)
                throw new J("JWTs MUST NOT use unencoded payload");
            return n.sign(t, r)
        })
    }
}
;
var mt = class extends Y {
    setProtectedHeader(t) {
        if (this._protectedHeader)
            throw new TypeError("setProtectedHeader can only be called once");
        return this._protectedHeader = t,
        this
    }
    setKeyManagementParameters(t) {
        if (this._keyManagementParameters)
            throw new TypeError("setKeyManagementParameters can only be called once");
        return this._keyManagementParameters = t,
        this
    }
    setContentEncryptionKey(t) {
        if (this._cek)
            throw new TypeError("setContentEncryptionKey can only be called once");
        return this._cek = t,
        this
    }
    setInitializationVector(t) {
        if (this._iv)
            throw new TypeError("setInitializationVector can only be called once");
        return this._iv = t,
        this
    }
    replicateIssuerAsHeader() {
        return this._replicateIssuerAsHeader = !0,
        this
    }
    replicateSubjectAsHeader() {
        return this._replicateSubjectAsHeader = !0,
        this
    }
    replicateAudienceAsHeader() {
        return this._replicateAudienceAsHeader = !0,
        this
    }
    encrypt(t, r) {
        return s(this, null, function*() {
            let n = new _e(A.encode(JSON.stringify(this._payload)));
            return this._replicateIssuerAsHeader && (this._protectedHeader = w(d({}, this._protectedHeader), {
                iss: this._payload.iss
            })),
            this._replicateSubjectAsHeader && (this._protectedHeader = w(d({}, this._protectedHeader), {
                sub: this._payload.sub
            })),
            this._replicateAudienceAsHeader && (this._protectedHeader = w(d({}, this._protectedHeader), {
                aud: this._payload.aud
            })),
            n.setProtectedHeader(this._protectedHeader),
            this._iv && n.setInitializationVector(this._iv),
            this._cek && n.setContentEncryptionKey(this._cek),
            this._keyManagementParameters && n.setKeyManagementParameters(this._keyManagementParameters),
            n.encrypt(t, r)
        })
    }
}
;
var q = (e, t) => {
    if (typeof e != "string" || !e)
        throw new Ze(`${t} missing or invalid`)
}
;
function lr(e, t) {
    return s(this, null, function*() {
        if (!E(e))
            throw new TypeError("JWK must be an object");
        if (t ?? (t = "sha256"),
        t !== "sha256" && t !== "sha384" && t !== "sha512")
            throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
        let r;
        switch (e.kty) {
        case "EC":
            q(e.crv, '"crv" (Curve) Parameter'),
            q(e.x, '"x" (X Coordinate) Parameter'),
            q(e.y, '"y" (Y Coordinate) Parameter'),
            r = {
                crv: e.crv,
                kty: e.kty,
                x: e.x,
                y: e.y
            };
            break;
        case "OKP":
            q(e.crv, '"crv" (Subtype of Key Pair) Parameter'),
            q(e.x, '"x" (Public Key) Parameter'),
            r = {
                crv: e.crv,
                kty: e.kty,
                x: e.x
            };
            break;
        case "RSA":
            q(e.e, '"e" (Exponent) Parameter'),
            q(e.n, '"n" (Modulus) Parameter'),
            r = {
                e: e.e,
                kty: e.kty,
                n: e.n
            };
            break;
        case "oct":
            q(e.k, '"k" (Key Value) Parameter'),
            r = {
                k: e.k,
                kty: e.kty
            };
            break;
        default:
            throw new y('"kty" (Key Type) Parameter missing or unsupported')
        }
        let n = A.encode(JSON.stringify(r));
        return b(yield Je(t, n))
    })
}
function pn(e, t) {
    return s(this, null, function*() {
        t ?? (t = "sha256");
        let r = yield lr(e, t);
        return `urn:ietf:params:oauth:jwk-thumbprint:sha-${t.slice(-3)}:${r}`
    })
}
function fn(e, t) {
    return s(this, null, function*() {
        let r = d(d({}, e), t?.header);
        if (!E(r.jwk))
            throw new S('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
        let n = yield $(w(d({}, r.jwk), {
            ext: !0
        }), r.alg);
        if (n instanceof Uint8Array || n.type !== "public")
            throw new S('"jwk" (JSON Web Key) Header Parameter must be a public key');
        return n
    })
}
function un(e) {
    switch (typeof e == "string" && e.slice(0, 2)) {
    case "RS":
    case "PS":
        return "RSA";
    case "ES":
        return "EC";
    case "Ed":
        return "OKP";
    default:
        throw new y('Unsupported "alg" value for a JSON Web Key Set')
    }
}
function ln(e) {
    return e && typeof e == "object" && Array.isArray(e.keys) && e.keys.every(hn)
}
function hn(e) {
    return E(e)
}
function mr(e) {
    return typeof structuredClone == "function" ? structuredClone(e) : JSON.parse(JSON.stringify(e))
}
var yt = class {
    constructor(t) {
        if (this._cached = new WeakMap,
        !ln(t))
            throw new De("JSON Web Key Set malformed");
        this._jwks = mr(t)
    }
    getKey(t, r) {
        return s(this, null, function*() {
            let {alg: n, kid: o} = d(d({}, t), r?.header)
              , a = un(n)
              , i = this._jwks.keys.filter(p => {
                let l = a === p.kty;
                if (l && typeof o == "string" && (l = o === p.kid),
                l && typeof p.alg == "string" && (l = n === p.alg),
                l && typeof p.use == "string" && (l = p.use === "sig"),
                l && Array.isArray(p.key_ops) && (l = p.key_ops.includes("verify")),
                l && n === "EdDSA" && (l = p.crv === "Ed25519" || p.crv === "Ed448"),
                l)
                    switch (n) {
                    case "ES256":
                        l = p.crv === "P-256";
                        break;
                    case "ES256K":
                        l = p.crv === "secp256k1";
                        break;
                    case "ES384":
                        l = p.crv === "P-384";
                        break;
                    case "ES512":
                        l = p.crv === "P-521";
                        break
                    }
                return l
            }
            )
              , {0: f, length: h} = i;
            if (h === 0)
                throw new he;
            if (h !== 1) {
                let p = new ae
                  , {_cached: l} = this;
                throw p[Symbol.asyncIterator] = function() {
                    return Ht(this, null, function*() {
                        for (let u of i)
                            try {
                                yield yield new Ct(hr(l, u, n))
                            } catch {}
                    })
                }
                ,
                p
            }
            return hr(this._cached, f, n)
        })
    }
}
;
function hr(e, t, r) {
    return s(this, null, function*() {
        let n = e.get(t) || e.set(t, {}).get(t);
        if (n[r] === void 0) {
            let o = yield $(w(d({}, t), {
                ext: !0
            }), r);
            if (o instanceof Uint8Array || o.type !== "public")
                throw new De("JSON Web Key Set members must be public keys");
            n[r] = o
        }
        return n[r]
    })
}
function Xe(e) {
    let t = new yt(e)
      , r = (n, o) => s(this, null, function*() {
        return t.getKey(n, o)
    });
    return Object.defineProperties(r, {
        jwks: {
            value: () => mr(t._jwks),
            enumerable: !0,
            configurable: !1,
            writable: !1
        }
    }),
    r
}
var mn = (e, t, r) => s(void 0, null, function*() {
    let n, o, a = !1;
    typeof AbortController == "function" && (n = new AbortController,
    o = setTimeout( () => {
        a = !0,
        n.abort()
    }
    , t));
    let i = yield fetch(e.href, {
        signal: n ? n.signal : void 0,
        redirect: "manual",
        headers: r.headers
    }).catch(f => {
        throw a ? new Qe : f
    }
    );
    if (o !== void 0 && clearTimeout(o),
    i.status !== 200)
        throw new T("Expected 200 OK from the JSON Web Key Set HTTP response");
    try {
        return yield i.json()
    } catch {
        throw new T("Failed to parse the JSON Web Key Set HTTP response as JSON")
    }
})
  , yr = mn;
function yn() {
    return typeof WebSocketPair < "u" || typeof navigator < "u" && navigator.userAgent === "Cloudflare-Workers" || typeof EdgeRuntime < "u" && EdgeRuntime === "vercel"
}
var wt;
(typeof navigator > "u" || !navigator.userAgent?.startsWith?.("Mozilla/5.0 ")) && (wt = "jose/v5.9.6");
var He = Symbol();
function wn(e, t) {
    return !(typeof e != "object" || e === null || !("uat"in e) || typeof e.uat != "number" || Date.now() - e.uat >= t || !("jwks"in e) || !E(e.jwks) || !Array.isArray(e.jwks.keys) || !Array.prototype.every.call(e.jwks.keys, E))
}
var Et = class {
    constructor(t, r) {
        if (!(t instanceof URL))
            throw new TypeError("url must be an instance of URL");
        this._url = new URL(t.href),
        this._options = {
            agent: r?.agent,
            headers: r?.headers
        },
        this._timeoutDuration = typeof r?.timeoutDuration == "number" ? r?.timeoutDuration : 5e3,
        this._cooldownDuration = typeof r?.cooldownDuration == "number" ? r?.cooldownDuration : 3e4,
        this._cacheMaxAge = typeof r?.cacheMaxAge == "number" ? r?.cacheMaxAge : 6e5,
        r?.[He] !== void 0 && (this._cache = r?.[He],
        wn(r?.[He], this._cacheMaxAge) && (this._jwksTimestamp = this._cache.uat,
        this._local = Xe(this._cache.jwks)))
    }
    coolingDown() {
        return typeof this._jwksTimestamp == "number" ? Date.now() < this._jwksTimestamp + this._cooldownDuration : !1
    }
    fresh() {
        return typeof this._jwksTimestamp == "number" ? Date.now() < this._jwksTimestamp + this._cacheMaxAge : !1
    }
    getKey(t, r) {
        return s(this, null, function*() {
            (!this._local || !this.fresh()) && (yield this.reload());
            try {
                return yield this._local(t, r)
            } catch (n) {
                if (n instanceof he && this.coolingDown() === !1)
                    return yield this.reload(),
                    this._local(t, r);
                throw n
            }
        })
    }
    reload() {
        return s(this, null, function*() {
            this._pendingFetch && yn() && (this._pendingFetch = void 0);
            let t = new Headers(this._options.headers);
            wt && !t.has("User-Agent") && (t.set("User-Agent", wt),
            this._options.headers = Object.fromEntries(t.entries())),
            this._pendingFetch || (this._pendingFetch = yr(this._url, this._timeoutDuration, this._options).then(r => {
                this._local = Xe(r),
                this._cache && (this._cache.uat = Date.now(),
                this._cache.jwks = r),
                this._jwksTimestamp = Date.now(),
                this._pendingFetch = void 0
            }
            ).catch(r => {
                throw this._pendingFetch = void 0,
                r
            }
            )),
            yield this._pendingFetch
        })
    }
}
;
function En(e, t) {
    let r = new Et(e,t)
      , n = (o, a) => s(this, null, function*() {
        return r.getKey(o, a)
    });
    return Object.defineProperties(n, {
        coolingDown: {
            get: () => r.coolingDown(),
            enumerable: !0,
            configurable: !1
        },
        fresh: {
            get: () => r.fresh(),
            enumerable: !0,
            configurable: !1
        },
        reload: {
            value: () => r.reload(),
            enumerable: !0,
            configurable: !1,
            writable: !1
        },
        reloading: {
            get: () => !!r._pendingFetch,
            enumerable: !0,
            configurable: !1
        },
        jwks: {
            value: () => r._local?.jwks(),
            enumerable: !0,
            configurable: !1,
            writable: !1
        }
    }),
    n
}
var Sn = He;
var St = class extends Y {
    encode() {
        let t = b(JSON.stringify({
            alg: "none"
        }))
          , r = b(JSON.stringify(this._payload));
        return `${t}.${r}.`
    }
    static decode(t, r) {
        if (typeof t != "string")
            throw new J("Unsecured JWT must be a string");
        let {0: n, 1: o, 2: a, length: i} = t.split(".");
        if (i !== 3 || a !== "")
            throw new J("Invalid Unsecured JWT");
        let f;
        try {
            if (f = JSON.parse(H.decode(K(n))),
            f.alg !== "none")
                throw new Error
        } catch {
            throw new J("Invalid Unsecured JWT")
        }
        return {
            payload: le(f, K(o), r),
            header: f
        }
    }
}
;
var gt = {};
_t(gt, {
    decode: () => We,
    encode: () => gn
});
var gn = b
  , We = K;
function An(e) {
    let t;
    if (typeof e == "string") {
        let r = e.split(".");
        (r.length === 3 || r.length === 5) && ([t] = r)
    } else if (typeof e == "object" && e)
        if ("protected"in e)
            t = e.protected;
        else
            throw new TypeError("Token does not contain a Protected Header");
    try {
        if (typeof t != "string" || !t)
            throw new Error;
        let r = JSON.parse(H.decode(We(t)));
        if (!E(r))
            throw new Error;
        return r
    } catch {
        throw new TypeError("Invalid Token or Protected Header formatting")
    }
}
function bn(e) {
    if (typeof e != "string")
        throw new J("JWTs must use Compact JWS serialization, JWT must be a string");
    let {1: t, length: r} = e.split(".");
    if (r === 5)
        throw new J("Only JWTs using Compact JWS serialization can be decoded");
    if (r !== 3)
        throw new J("Invalid JWT");
    if (!t)
        throw new J("JWTs must contain a payload");
    let n;
    try {
        n = We(t)
    } catch {
        throw new J("Failed to base64url decode the payload")
    }
    let o;
    try {
        o = JSON.parse(H.decode(n))
    } catch {
        throw new J("Failed to parse the decoded payload as JSON")
    }
    if (!E(o))
        throw new J("Invalid JWT Claims Set");
    return o
}
function wr(e, t) {
    return s(this, null, function*() {
        let r, n, o;
        switch (e) {
        case "HS256":
        case "HS384":
        case "HS512":
            r = parseInt(e.slice(-3), 10),
            n = {
                name: "HMAC",
                hash: `SHA-${r}`,
                length: r
            },
            o = ["sign", "verify"];
            break;
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
            return r = parseInt(e.slice(-3), 10),
            G(new Uint8Array(r >> 3));
        case "A128KW":
        case "A192KW":
        case "A256KW":
            r = parseInt(e.slice(1, 4), 10),
            n = {
                name: "AES-KW",
                length: r
            },
            o = ["wrapKey", "unwrapKey"];
            break;
        case "A128GCMKW":
        case "A192GCMKW":
        case "A256GCMKW":
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
            r = parseInt(e.slice(1, 4), 10),
            n = {
                name: "AES-GCM",
                length: r
            },
            o = ["encrypt", "decrypt"];
            break;
        default:
            throw new y('Invalid or unsupported JWK "alg" (Algorithm) Parameter value')
        }
        return m.subtle.generateKey(n, t?.extractable ?? !1, o)
    })
}
function At(e) {
    let t = e?.modulusLength ?? 2048;
    if (typeof t != "number" || t < 2048)
        throw new y("Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used");
    return t
}
function Er(e, t) {
    return s(this, null, function*() {
        let r, n;
        switch (e) {
        case "PS256":
        case "PS384":
        case "PS512":
            r = {
                name: "RSA-PSS",
                hash: `SHA-${e.slice(-3)}`,
                publicExponent: new Uint8Array([1, 0, 1]),
                modulusLength: At(t)
            },
            n = ["sign", "verify"];
            break;
        case "RS256":
        case "RS384":
        case "RS512":
            r = {
                name: "RSASSA-PKCS1-v1_5",
                hash: `SHA-${e.slice(-3)}`,
                publicExponent: new Uint8Array([1, 0, 1]),
                modulusLength: At(t)
            },
            n = ["sign", "verify"];
            break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
            r = {
                name: "RSA-OAEP",
                hash: `SHA-${parseInt(e.slice(-3), 10) || 1}`,
                publicExponent: new Uint8Array([1, 0, 1]),
                modulusLength: At(t)
            },
            n = ["decrypt", "unwrapKey", "encrypt", "wrapKey"];
            break;
        case "ES256":
            r = {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            n = ["sign", "verify"];
            break;
        case "ES384":
            r = {
                name: "ECDSA",
                namedCurve: "P-384"
            },
            n = ["sign", "verify"];
            break;
        case "ES512":
            r = {
                name: "ECDSA",
                namedCurve: "P-521"
            },
            n = ["sign", "verify"];
            break;
        case "EdDSA":
            {
                n = ["sign", "verify"];
                let o = t?.crv ?? "Ed25519";
                switch (o) {
                case "Ed25519":
                case "Ed448":
                    r = {
                        name: o
                    };
                    break;
                default:
                    throw new y("Invalid or unsupported crv option provided")
                }
                break
            }
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
            {
                n = ["deriveKey", "deriveBits"];
                let o = t?.crv ?? "P-256";
                switch (o) {
                case "P-256":
                case "P-384":
                case "P-521":
                    {
                        r = {
                            name: "ECDH",
                            namedCurve: o
                        };
                        break
                    }
                case "X25519":
                case "X448":
                    r = {
                        name: o
                    };
                    break;
                default:
                    throw new y("Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448")
                }
                break
            }
        default:
            throw new y('Invalid or unsupported JWK "alg" (Algorithm) Parameter value')
        }
        return m.subtle.generateKey(r, t?.extractable ?? !1, n)
    })
}
function Kn(e, t) {
    return s(this, null, function*() {
        return Er(e, t)
    })
}
function xn(e, t) {
    return s(this, null, function*() {
        return wr(e, t)
    })
}
var Sr = "WebCryptoAPI";
var _n = Sr;
export {_e as CompactEncrypt, Ce as CompactSign, fn as EmbeddedJWK, mt as EncryptJWT, X as FlattenedEncrypt, ne as FlattenedSign, pt as GeneralEncrypt, lt as GeneralSign, ht as SignJWT, St as UnsecuredJWT, gt as base64url, lr as calculateJwkThumbprint, pn as calculateJwkThumbprintUri, st as compactDecrypt, ft as compactVerify, Xe as createLocalJWKSet, En as createRemoteJWKSet, _n as cryptoRuntime, bn as decodeJwt, An as decodeProtectedHeader, je as errors, Sn as experimental_jwksCache, ct as exportJWK, en as exportPKCS8, jr as exportSPKI, Ae as flattenedDecrypt, xe as flattenedVerify, Zr as generalDecrypt, nn as generalVerify, Kn as generateKeyPair, xn as generateSecret, $ as importJWK, $r as importPKCS8, Lr as importSPKI, kr as importX509, He as jwksCache, cn as jwtDecrypt, sn as jwtVerify};
