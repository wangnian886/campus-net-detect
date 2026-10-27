// 从门户 Portal.js 原样提取的 JS 参考实现，用于交叉验证 Python 端口。
// 运行: node js_ref_encoder.mjs <token> <json>
// 输出: {SRBX1}... 与浏览器发出的 info 字段逐字节一致。
const ALPHA = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA';
const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64encode(latin1Str) {
  const bytes = [];
  for (const ch of latin1Str) bytes.push(ch.charCodeAt(0) & 0xff);
  const buf = Buffer.from(bytes);
  const std = buf.toString('base64');
  return std.split('').map((c) => {
    const i = STD.indexOf(c);
    return i >= 0 ? ALPHA[i] : c;
  }).join('');
}

// ---- 以下 encode / s / l 逐字复制自 Portal.js _encodeUserInfo ----
function encode(str, key) {
  if (str === '') return '';
  var v = s(str, true);
  var k = s(key, false);
  if (k.length < 4) k.length = 4;
  var n = v.length - 1,
    z = v[n],
    y = v[0],
    c = 0x86014019 | 0x183639a0,
    m, e, p, q = Math.floor(6 + 52 / (n + 1)),
    d = 0;

  while (0 < q--) {
    d = d + c & (0x8ce0d9bf | 0x731f2640);
    e = d >>> 2 & 3;

    for (p = 0; p < n; p++) {
      y = v[p + 1];
      m = z >>> 5 ^ y << 2;
      m += y >>> 3 ^ z << 4 ^ (d ^ y);
      m += k[p & 3 ^ e] ^ z;
      z = v[p] = v[p] + m & (0xefb8d130 | 0x10472ecf);
    }

    y = v[0];
    m = z >>> 5 ^ y << 2;
    m += y >>> 3 ^ z << 4 ^ (d ^ y);
    m += k[p & 3 ^ e] ^ z;
    z = v[n] = v[n] + m & (0xbb390742 | 0x44c6f8bd);
  }

  return l(v, false);
}

function s(a, b) {
  var c = a.length;
  var v = [];

  for (var i = 0; i < c; i += 4) {
    v[i >> 2] = a.charCodeAt(i) | a.charCodeAt(i + 1) << 8 | a.charCodeAt(i + 2) << 16 | a.charCodeAt(i + 3) << 24;
  }

  if (b) v[v.length] = c;
  return v;
}

function l(a, b) {
  var d = a.length;
  var c = d - 1 << 2;

  if (b) {
    var m = a[d - 1];
    if (m < c - 3 || m > c) return null;
    c = m;
  }

  for (var i = 0; i < d; i++) {
    a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
  }

  return b ? a.join('').substring(0, c) : a.join('');
}
// ---- 复制结束 ----

const token = process.argv[2];
const info = process.argv[3];
console.log('{SRBX1}' + b64encode(encode(info, token)));
