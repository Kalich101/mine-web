var t = Object.create;
var m = Object.defineProperty
  , u = Object.defineProperties
  , v = Object.getOwnPropertyDescriptor
  , w = Object.getOwnPropertyDescriptors
  , x = Object.getOwnPropertyNames
  , l = Object.getOwnPropertySymbols
  , y = Object.getPrototypeOf
  , o = Object.prototype.hasOwnProperty
  , r = Object.prototype.propertyIsEnumerable;
var z = (a, b) => (b = Symbol[a]) ? b : Symbol.for("Symbol." + a);
var n = (a, b, c) => b in a ? m(a, b, {
    enumerable: !0,
    configurable: !0,
    writable: !0,
    value: c
}) : a[b] = c
  , C = (a, b) => {
    for (var c in b ||= {})
        o.call(b, c) && n(a, c, b[c]);
    if (l)
        for (var c of l(b))
            r.call(b, c) && n(a, c, b[c]);
    return a
}
  , D = (a, b) => u(a, w(b));
var E = a => typeof a == "symbol" ? a : a + ""
  , F = (a, b) => {
    var c = {};
    for (var d in a)
        o.call(a, d) && b.indexOf(d) < 0 && (c[d] = a[d]);
    if (a != null && l)
        for (var d of l(a))
            b.indexOf(d) < 0 && r.call(a, d) && (c[d] = a[d]);
    return c
}
;
var G = (a, b) => () => (b || a((b = {
    exports: {}
}).exports, b),
b.exports)
  , H = (a, b) => {
    for (var c in b)
        m(a, c, {
            get: b[c],
            enumerable: !0
        })
}
  , A = (a, b, c, d) => {
    if (b && typeof b == "object" || typeof b == "function")
        for (let f of x(b))
            !o.call(a, f) && f !== c && m(a, f, {
                get: () => b[f],
                enumerable: !(d = v(b, f)) || d.enumerable
            });
    return a
}
;
var I = (a, b, c) => (c = a != null ? t(y(a)) : {},
A(b || !a || !a.__esModule ? m(c, "default", {
    value: a,
    enumerable: !0
}) : c, a));
var J = (a, b, c) => n(a, typeof b != "symbol" ? b + "" : b, c);
var K = (a, b, c) => new Promise( (d, f) => {
    var k = e => {
        try {
            g(c.next(e))
        } catch (h) {
            f(h)
        }
    }
      , i = e => {
        try {
            g(c.throw(e))
        } catch (h) {
            f(h)
        }
    }
      , g = e => e.done ? d(e.value) : Promise.resolve(e.value).then(k, i);
    g((c = c.apply(a, b)).next())
}
)
  , B = function(a, b) {
    this[0] = a,
    this[1] = b
}
  , L = (a, b, c) => {
    var d = (i, g, e, h) => {
        try {
            var p = c[i](g)
              , q = (g = p.value)instanceof B
              , s = p.done;
            Promise.resolve(q ? g[0] : g).then(j => q ? d(i === "return" ? i : "next", g[1] ? {
                done: j.done,
                value: j.value
            } : j, e, h) : e({
                value: j,
                done: s
            })).catch(j => d("throw", j, e, h))
        } catch (j) {
            h(j)
        }
    }
      , f = i => k[i] = g => new Promise( (e, h) => d(i, g, e, h))
      , k = {};
    return c = c.apply(a, b),
    k[z("asyncIterator")] = () => k,
    f("next"),
    f("throw"),
    f("return"),
    k
}
;
export {C as a, D as b, E as c, F as d, G as e, H as f, I as g, J as h, K as i, B as j, L as k};
