/**
 * IZ Earn Device Verify Worker v7
 * Fixed Web Crypto HMAC buffer handling (ArrayBuffer / Uint8Array)
 * Algorithm verified against official Telegram sample (Python match)
 *
 * Secrets: BOT_TOKEN, RESULT_SECRET, TURNSTILE_SECRET
 * KV: VERIFY_KV
 */

const INIT_MAX_AGE_SEC = 86400;
const VERIFY_TTL_SEC = 600;

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
        v: 7,
        mode: "strict_initdata",
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
  let t = String(raw || "");
  t = t.replace(/^\uFEFF/, "").trim();
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

async function hmacSha256(keyData, messageData) {
  const key = await crypto.subtle.importKey(
    "raw",
    toBytes(keyData),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, toBytes(messageData));
  return new Uint8Array(sig);
}

function toHex(bytes) {
  return [...toBytes(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
    v: 7,
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

  const initData = String(body.initData || "").trim();
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
      has_hash: initData.indexOf("hash=") >= 0,
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

/**
 * Official algorithm (matches Telegram sample + Python hmac):
 * secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token)
 * hash = hex(HMAC_SHA256(key=secret_key, msg=data_check_string))
 * data_check_string = sorted key=value joined by \n, excluding hash & signature
 */
async function validateInitData(initData, botToken, maxAgeSec) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return { ok: false, detail: "no_hash" };

    const pairs = [];
    for (const [k, v] of params.entries()) {
      if (k === "hash" || k === "signature") continue;
      pairs.push(k + "=" + v);
    }
    pairs.sort();
    const dataCheckString = pairs.join("\n");

    // key = "WebAppData", message = botToken
    const secretKey = await hmacSha256("WebAppData", botToken);
    const computed = toHex(await hmacSha256(secretKey, dataCheckString));

    if (computed !== String(hash).toLowerCase()) {
      // Retry with manual parse (edge decode cases)
      const map = {};
      for (const part of initData.split("&")) {
        const eq = part.indexOf("=");
        if (eq < 0) continue;
        const k = decodeURIComponent(part.slice(0, eq));
        let v = part.slice(eq + 1);
        try {
          v = decodeURIComponent(v.replace(/\+/g, " "));
        } catch (_) {}
        map[k] = v;
      }
      if (map.hash) {
        const pairs2 = [];
        for (const k of Object.keys(map)) {
          if (k === "hash" || k === "signature") continue;
          pairs2.push(k + "=" + map[k]);
        }
        pairs2.sort();
        const dcs2 = pairs2.join("\n");
        const computed2 = toHex(await hmacSha256(secretKey, dcs2));
        if (computed2 === String(map.hash).toLowerCase()) {
          return finishParse(map, maxAgeSec);
        }
      }
      return { ok: false, detail: "bad_hash" };
    }

    const map = {};
    for (const [k, v] of params.entries()) map[k] = v;
    return finishParse(map, maxAgeSec);
  } catch (e) {
    return { ok: false, detail: "validate_error:" + String(e && e.message || e) };
  }
}

function finishParse(map, maxAgeSec) {
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

async function checkVpn(ip, proxycheckKey) {
  try {
    const q = proxycheckKey
      ? `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(proxycheckKey)}&vpn=1&asn=1&risk=1`
      : `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&risk=1`;
    const r = await fetch(q, { cf: { cacheTtl: 60 } });
    if (r.ok) {
      const d = await r.json();
      const node = d && d[ip];
      if (node) {
        const proxy = String(node.proxy || "").toLowerCase();
        const type = String(node.type || "").toLowerCase();
        const risk = Number(node.risk || 0);
        if (proxy === "yes") return { vpn: true, detail: "proxycheck:proxy" };
        if (
          type.includes("vpn") ||
          type.includes("tor") ||
          type.includes("socks") ||
          type.includes("proxy")
        ) {
          return { vpn: true, detail: "proxycheck:" + type };
        }
        if (risk >= 66) return { vpn: true, detail: "proxycheck:risk:" + risk };
      }
    }
  } catch (_) {}
  try {
    const r2 = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { cf: { cacheTtl: 60 } });
    if (r2.ok) {
      const d2 = await r2.json();
      if (d2 && d2.success !== false && d2.security) {
        const s = d2.security;
        if (s.vpn === true || s.proxy === true || s.tor === true || s.relay === true) {
          return { vpn: true, detail: "ipwho" };
        }
      }
    }
  } catch (_) {}
  try {
    const r3 = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, {
      cf: { cacheTtl: 60 },
    });
    if (r3.ok) {
      const d3 = await r3.json();
      if (d3 && (d3.is_vpn === true || d3.is_proxy === true || d3.is_tor === true)) {
        return { vpn: true, detail: "ipapi.is" };
      }
    }
  } catch (_) {}
  return { vpn: false, detail: "clean" };
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
