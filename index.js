/**
 * IZ Earn Device Verify Worker v8
 *
 * Validates initData two ways:
 *  A) HMAC hash with BOT_TOKEN (classic)
 *  B) Ed25519 "signature" with Telegram production public key + bot_id
 *     (Bot API 8.0+; works even if hash path has edge issues)
 *
 * Secrets: BOT_TOKEN, RESULT_SECRET, TURNSTILE_SECRET
 * KV: VERIFY_KV
 */

const INIT_MAX_AGE_SEC = 86400;
const VERIFY_TTL_SEC = 600;
// https://docs.telegram-mini-apps.com/platform/init-data
const TG_PROD_ED25519_HEX =
  "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d";

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return cors(json({
        ok: true,
        service: "iz-device-verify",
        v: 9,
        mode: "strict_initdata_hmac_or_ed25519",
      }));
    }
    if (request.method === "GET" && url.pathname === "/diag") {
      return cors(handleDiag(env, url, request));
    }
    if (request.method === "GET" && url.pathname === "/whoami") {
      return cors(await handleWhoami(env));
    }
    if (request.method === "GET" && url.pathname === "/check") {
      return cors(await handleCheck(request, env, url));
    }
    if (request.method === "POST" && (url.pathname === "/" || url.pathname === "/verify")) {
      try {
        return cors(await handleVerify(request, env));
      } catch (e) {
        return cors(json({
          ok: false,
          reason: "server_error",
          detail: String(e && e.message || e),
        }, 500));
      }
    }
    return cors(json({ ok: false, reason: "not_found" }, 404));
  },
};

function cleanToken(raw) {
  let t = String(raw || "").replace(/^\uFEFF/, "").trim();
  if (
    (t.startsWith('"') && t.endsWith('"')) ||
    (t.startsWith("'") && t.endsWith("'"))
  ) {
    t = t.slice(1, -1).trim();
  }
  return t.replace(/\r|\n/g, "").trim();
}

function toBytes(data) {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new TextEncoder().encode(String(data));
}

function toHex(bytes) {
  return [...toBytes(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const h = String(hex).replace(/\s/g, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.substr(i * 2, 2), 16);
  }
  return out;
}

function b64urlToBytes(s) {
  let b64 = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacSha256(keyData, messageData) {
  const key = await crypto.subtle.importKey(
    "raw",
    toBytes(keyData),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, toBytes(messageData)));
}

/** Parse initData into map of decoded values */
function parseMap(initData) {
  const map = {};
  const params = new URLSearchParams(initData);
  for (const [k, v] of params.entries()) map[k] = v;
  return map;
}

/** Sorted data-check-string excluding hash + signature */
function dataCheckString(map) {
  const pairs = [];
  for (const k of Object.keys(map)) {
    if (k === "hash" || k === "signature") continue;
    pairs.push(k + "=" + map[k]);
  }
  pairs.sort();
  return pairs.join("\n");
}

async function validateHmac(map, botToken) {
  const hash = map.hash;
  if (!hash) return false;
  const dcs = dataCheckString(map);
  const secretKey = await hmacSha256("WebAppData", botToken);
  const computed = toHex(await hmacSha256(secretKey, dcs));
  return computed === String(hash).toLowerCase();
}

/**
 * Third-party Ed25519 validation (Telegram production key).
 * Message = `${botId}:WebAppData\n` + data_check_string
 */
async function validateEd25519(map, botId) {
  const sig = map.signature;
  if (!sig) return false;
  const dcs = dataCheckString(map);
  const message = String(botId) + ":WebAppData\n" + dcs;
  try {
    const pub = await crypto.subtle.importKey(
      "raw",
      hexToBytes(TG_PROD_ED25519_HEX),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      "Ed25519",
      pub,
      b64urlToBytes(sig),
      toBytes(message)
    );
  } catch {
    return false;
  }
}

function finishUser(map, maxAgeSec) {
  const authDate = parseInt(map.auth_date || "0", 10);
  const nowSec = Math.floor(Date.now() / 1000);
  if (!authDate || nowSec - authDate > maxAgeSec) {
    return { ok: false, detail: "expired" };
  }
  if (authDate > nowSec + 120) {
    return { ok: false, detail: "auth_in_future" };
  }
  let userId = "";
  if (map.user) {
    try {
      const user = JSON.parse(map.user);
      if (user && user.id) userId = String(user.id);
    } catch (_) {}
  }
  if (!userId) return { ok: false, detail: "no_user" };
  return { ok: true, userId, authDate };
}

async function validateInitData(initData, botToken, maxAgeSec) {
  const map = parseMap(initData);
  const keys = Object.keys(map).sort();
  const botId = botToken.includes(":") ? botToken.split(":")[0] : "";

  const hmacOk = await validateHmac(map, botToken);
  if (hmacOk) {
    const fin = finishUser(map, maxAgeSec);
    if (fin.ok) return { ...fin, method: "hmac" };
    return fin;
  }

  // Fallback: Telegram Ed25519 signature (present on modern clients)
  if (map.signature && botId) {
    const edOk = await validateEd25519(map, botId);
    if (edOk) {
      const fin = finishUser(map, maxAgeSec);
      if (fin.ok) return { ...fin, method: "ed25519" };
      return fin;
    }
  }

  return {
    ok: false,
    detail: "bad_hash",
    keys: keys.join(","),
    has_signature: !!map.signature,
    has_hash: !!map.hash,
  };
}

async function handleWhoami(env) {
  const token = cleanToken(env.BOT_TOKEN);
  if (!token || token.length < 10) {
    return json({ ok: false, error: "BOT_TOKEN not set" });
  }
  try {
    const r = await fetch("https://api.telegram.org/bot" + token + "/getMe");
    const d = await r.json();
    if (!d || !d.ok) {
      return json({
        ok: false,
        error: "Telegram rejected token",
        description: (d && d.description) || "getMe failed",
      });
    }
    return json({
      ok: true,
      id: d.result.id,
      username: d.result.username || null,
      name: d.result.first_name || null,
      note: "Verify button must be opened from THIS bot only",
    });
  } catch (e) {
    return json({ ok: false, error: String(e && e.message || e) });
  }
}

function handleDiag(env, url, request) {
  const token = cleanToken(env.BOT_TOKEN);
  const secret = cleanToken(env.RESULT_SECRET);
  const given =
    request.headers.get("X-Result-Secret") ||
    url.searchParams.get("secret") ||
    "";
  const botId = token.includes(":") ? token.split(":")[0] : "";
  return json({
    ok: true,
    v: 9,
    bot_token_set: token.length > 10,
    bot_token_length: token.length,
    bot_id: botId || null,
    result_secret_set: secret.length > 5,
    turnstile_set: !!cleanToken(env.TURNSTILE_SECRET),
    kv_bound: !!env.VERIFY_KV,
    auth: secret && given === secret ? "ok" : "basic",
  });
}

async function handleCheck(request, env, url) {
  const secret = cleanToken(env.RESULT_SECRET);
  const given =
    request.headers.get("X-Result-Secret") ||
    url.searchParams.get("secret") ||
    "";
  if (!secret || given !== secret) {
    return json({ ok: false, reason: "unauthorized" }, 401);
  }
  const uid = String(url.searchParams.get("uid") || "").trim();
  if (!uid) return json({ ok: false, reason: "missing_uid" }, 400);
  const kv = env.VERIFY_KV;
  if (!kv) return json({ ok: false, reason: "no_kv" }, 500);
  const raw = await kv.get("verified:" + uid);
  if (!raw) return json({ ok: true, verified: false });
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return json({ ok: true, verified: false });
  }
  const now = Math.floor(Date.now() / 1000);
  if (!data.at || now - data.at > VERIFY_TTL_SEC) {
    return json({ ok: true, verified: false, reason: "expired" });
  }
  return json({
    ok: true,
    verified: true,
    uid,
    fp: data.fp || "",
    ip: data.ip || "",
    at: data.at,
  });
}

async function handleVerify(request, env) {
  const botToken = cleanToken(env.BOT_TOKEN);
  const resultSecret = cleanToken(env.RESULT_SECRET);
  if (!botToken || !resultSecret) {
    return json({
      ok: false,
      reason: "misconfigured",
      detail: "BOT_TOKEN or RESULT_SECRET missing",
    }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, reason: "bad_json" }, 400);
  }

  let initData = String(body.initData || "").trim();
  // Optional base64 transport
  if (body.initDataB64) {
    try {
      initData = atob(String(body.initDataB64));
    } catch (_) {}
  }

  const fingerprint = String(body.fingerprint || body.fp || "").slice(0, 128);
  const turnstileToken = String(body.turnstileToken || body.cf_turnstile_response || "");
  const platform = String(body.platform || "").slice(0, 32);
  const now = Date.now();

  if (!initData || initData.length < 30) {
    return json({
      ok: false,
      reason: "init_data",
      ban: false,
      detail: "missing_use_inline_button",
      init_len: initData.length,
    });
  }

  const initResult = await validateInitData(initData, botToken, INIT_MAX_AGE_SEC);
  if (!initResult.ok) {
    return json({
      ok: false,
      reason: "init_data",
      ban: false,
      detail: initResult.detail,
      init_len: initData.length,
      keys: initResult.keys,
      has_signature: initResult.has_signature,
      has_hash: initResult.has_hash,
      worker_bot_id: botToken.includes(":") ? botToken.split(":")[0] : "?",
    });
  }
  const uid = String(initResult.userId);

  if (env.TURNSTILE_SECRET) {
    const tsSecret = cleanToken(env.TURNSTILE_SECRET);
    if (!turnstileToken) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "missing_token" });
    }
    const tsOk = await verifyTurnstile(turnstileToken, tsSecret, clientIp(request));
    if (!tsOk) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "failed" });
    }
  }

  const ip = clientIp(request);
  if (!ip || ip === "0.0.0.0") {
    return json({ ok: false, reason: "ip", ban: false, detail: "no_ip" });
  }

  const net = await checkVpn(ip, env.PROXYCHECK_KEY || "");
  if (net.vpn) {
    return json({
      ok: false,
      reason: "vpn",
      ban: false,
      ip,
      detail: net.detail || "vpn_or_proxy",
    });
  }

  if (!fingerprint || fingerprint.length < 6) {
    return json({ ok: false, reason: "fingerprint", ban: false, detail: "missing" });
  }

  const kv = env.VERIFY_KV;
  if (kv) {
    const devKey = "dev:" + fingerprint;
    const ipKey = "ip:" + ip;
    const existingDev = await kv.get(devKey);
    if (existingDev && existingDev !== uid) {
      return json({
        ok: false,
        reason: "multi_device",
        ban: true,
        detail: "device_used_by_" + existingDev,
      });
    }
    const existingIp = await kv.get(ipKey);
    if (existingIp && existingIp !== uid) {
      return json({
        ok: false,
        reason: "multi_ip",
        ban: true,
        detail: "ip_used_by_" + existingIp,
      });
    }
    await kv.put(devKey, uid);
    await kv.put(ipKey, uid);
    await kv.put(
      "user:" + uid,
      JSON.stringify({ fp: fingerprint, ip, platform, at: Math.floor(now / 1000) })
    );
    await kv.put(
      "verified:" + uid,
      JSON.stringify({ fp: fingerprint, ip, platform, at: Math.floor(now / 1000) }),
      { expirationTtl: VERIFY_TTL_SEC }
    );
  }

  const exp = Math.floor(now / 1000) + VERIFY_TTL_SEC;
  const payload = ["ok", uid, fingerprint, ip, String(exp)].join("|");
  const sig = toHex(await hmacSha256(resultSecret, payload));
  const token = payload + "|" + sig;

  return json({
    ok: true,
    reason: "pass",
    ban: false,
    uid,
    ip,
    fingerprint,
    exp,
    token,
    method: initResult.method || "hmac",
  });
}

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("True-Client-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    ""
  );
}

async function checkVpn(ip, proxycheckKey) {
  /**
   * Low false-positive VPN check for real users on home Wi‑Fi / mobile data.
   * Block only on STRONG signals (explicit VPN / Tor / SOCKS).
   * Do NOT block on weak "proxy=yes" for Residential / ISP / Business types
   * (those APIs often mis-flag home Wi‑Fi).
   */
  let strongHits = 0;
  const details = [];

  // --- 1) proxycheck.io: only explicit bad types + high risk ---
  try {
    const q = proxycheckKey
      ? `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(proxycheckKey)}&vpn=1&asn=1&risk=1`
      : `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&risk=1`;
    const r = await fetch(q, { cf: { cacheTtl: 120 } });
    if (r.ok) {
      const d = await r.json();
      const node = d && d[ip];
      if (node) {
        const type = String(node.type || "").toLowerCase();
        const risk = Number(node.risk || 0);
        // Explicit network types only — NOT generic proxy=yes on ISP/Residential
        if (type.includes("tor")) {
          strongHits += 2;
          details.push("proxycheck:tor");
        } else if (type === "vpn" || type.includes("vpn")) {
          strongHits += 1;
          details.push("proxycheck:vpn");
        } else if (type.includes("socks") || type === "socks4" || type === "socks5") {
          strongHits += 1;
          details.push("proxycheck:socks");
        } else if (type.includes("http") && type.includes("proxy")) {
          strongHits += 1;
          details.push("proxycheck:http_proxy");
        }
        // Very high risk alone (commercial VPN lists) — threshold 90 to spare home Wi‑Fi
        if (risk >= 90 && (type.includes("vpn") || type.includes("tor") || type.includes("socks"))) {
          strongHits += 1;
          details.push("proxycheck:risk" + risk);
        }
        // Explicitly IGNORE: Residential, Business, Education, Clothing, etc.
      }
    }
  } catch (_) {}

  // --- 2) ip-api.com (HTTP free): proxy flag + not mobile ---
  try {
    const r = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,proxy,hosting,mobile,query`,
      { cf: { cacheTtl: 120 } }
    );
    if (r.ok) {
      const d = await r.json();
      if (d && d.status === "success") {
        // proxy:true on ip-api is relatively strict; still require non-mobile
        if (d.proxy === true && d.mobile !== true) {
          strongHits += 1;
          details.push("ip-api:proxy");
        }
        // hosting alone is NOT enough (CDN/ISP CGNAT false positives)
      }
    }
  } catch (_) {}

  // --- 3) ipwho.is: only vpn/tor true, ignore vague proxy on residential ---
  try {
    const r2 = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { cf: { cacheTtl: 120 } });
    if (r2.ok) {
      const d2 = await r2.json();
      if (d2 && d2.success !== false && d2.security) {
        const s = d2.security;
        if (s.tor === true) {
          strongHits += 2;
          details.push("ipwho:tor");
        } else if (s.vpn === true) {
          strongHits += 1;
          details.push("ipwho:vpn");
        }
        // s.proxy / s.relay alone often false-positive on carrier Wi‑Fi — ignore unless +vpn
      }
    }
  } catch (_) {}

  // --- 4) IPLogs free API (low FP design) — block only vpn_detected ---
  try {
    const r3 = await fetch(`https://api.iplogs.com/v1/${encodeURIComponent(ip)}`, {
      cf: { cacheTtl: 120 },
    });
    if (r3.ok) {
      const d3 = await r3.json();
      const verdict = String((d3 && (d3.verdict || d3.status || d3.result)) || "").toLowerCase();
      if (verdict === "vpn_detected" || verdict === "tor" || d3.is_tor === true) {
        strongHits += 2;
        details.push("iplogs:" + verdict);
      } else if (verdict === "vpn_likely" && d3 && d3.score >= 0.85) {
        strongHits += 1;
        details.push("iplogs:vpn_likely");
      }
      if (d3 && (d3.is_vpn === true || d3.vpn === true) && d3.is_tor !== false) {
        if (d3.is_tor === true) {
          strongHits += 2;
          details.push("iplogs:tor_flag");
        }
      }
    }
  } catch (_) {}

  // Need at least 2 strong points OR a Tor hit (already +2)
  // Single weak API opinion is not enough to block home Wi‑Fi
  if (strongHits >= 2) {
    return { vpn: true, detail: details.join(",") || "consensus" };
  }
  return { vpn: false, detail: details.length ? "weak:" + details.join(",") : "clean" };
}


async function verifyTurnstile(token, secret, ip) {
  try {
    const form = new FormData();
    form.append("secret", secret);
    form.append("response", token);
    if (ip) form.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    if (!r.ok) return false;
    const d = await r.json();
    return !!(d && d.success);
  } catch {
    return false;
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, X-Result-Secret");
  return new Response(res.body, { status: res.status, headers: h });
}
