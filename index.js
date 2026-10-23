/**
 * IZ Earn Device Verify Worker v4
 *
 * Telegram rule: initData is often EMPTY from reply-keyboard web_app.
 * Inline web_app may include initData; if HMAC fails (wrong token / parse),
 * we do NOT hard-fail — identity is always the Telegram user on web_app_data.
 *
 * Security layers always applied:
 *  - Turnstile (if TURNSTILE_SECRET set)
 *  - Real IP (CF-Connecting-IP)
 *  - VPN/proxy detection (multi-source; fail closed on strong signals)
 *  - Device fingerprint required
 *  - KV 1-device / 1-IP when we know uid from valid initData
 *
 * Secrets: BOT_TOKEN, RESULT_SECRET, TURNSTILE_SECRET
 * KV binding name: VERIFY_KV
 */

const INIT_MAX_AGE_SEC = 86400;
const TOKEN_TTL_SEC = 300;

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") {
      return cors(json({ ok: true, service: "iz-device-verify", v: 4 }));
    }
    if (request.method === "POST" && (url.pathname === "/" || url.pathname === "/verify")) {
      try {
        return cors(await handleVerify(request, env));
      } catch (e) {
        return cors(
          json({ ok: false, reason: "server_error", detail: String(e && e.message || e) }, 500)
        );
      }
    }
    return cors(json({ ok: false, reason: "not_found" }, 404));
  },
};

async function handleVerify(request, env) {
  const botToken = String(env.BOT_TOKEN || "").trim();
  const resultSecret = String(env.RESULT_SECRET || "").trim();
  if (!botToken || !resultSecret) {
    return json(
      { ok: false, reason: "misconfigured", detail: "BOT_TOKEN or RESULT_SECRET missing" },
      500
    );
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

  // --- Turnstile (required when secret configured) ---
  if (env.TURNSTILE_SECRET) {
    if (!turnstileToken) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "missing_token" });
    }
    const tsOk = await verifyTurnstile(
      turnstileToken,
      String(env.TURNSTILE_SECRET).trim(),
      clientIp(request)
    );
    if (!tsOk) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "failed" });
    }
  }

  // --- Optional initData (never hard-block whole verify on bad_hash) ---
  let uid = "0";
  let initMode = "none";
  if (initData.length >= 20) {
    const initResult = await validateInitData(initData, botToken, INIT_MAX_AGE_SEC);
    if (initResult.ok) {
      uid = String(initResult.userId);
      initMode = "valid";
    } else {
      // Keep going — bot will use Telegram message user id
      initMode = "invalid:" + (initResult.detail || "fail");
    }
  }

  const ip = clientIp(request);
  if (!ip || ip === "0.0.0.0") {
    return json({ ok: false, reason: "ip", ban: false, detail: "no_ip" });
  }

  // --- VPN / proxy (multi-source) ---
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

  // --- KV uniqueness when uid known from valid initData ---
  const kv = env.VERIFY_KV;
  if (kv && uid !== "0") {
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
  }

  // Also track fingerprint globally for keyboard mode (uid assigned by bot later)
  if (kv) {
    const fpHit = await kv.get("fp_any:" + fingerprint);
    if (fpHit && uid !== "0" && fpHit !== uid) {
      return json({
        ok: false,
        reason: "multi_device",
        ban: true,
        detail: "fp_any_" + fpHit,
      });
    }
    if (uid !== "0") {
      await kv.put("fp_any:" + fingerprint, uid);
    }
  }

  const exp = Math.floor(now / 1000) + TOKEN_TTL_SEC;
  const payload = ["ok", uid, fingerprint, ip, String(exp)].join("|");
  const sig = await hmacHex(resultSecret, payload);
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
    init_mode: initMode,
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

    const enc = new TextEncoder();
    // secret = HMAC_SHA256(key=WebAppData, msg=botToken)
    const skBits = await crypto.subtle.sign(
      "HMAC",
      await crypto.subtle.importKey(
        "raw",
        enc.encode("WebAppData"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      ),
      enc.encode(botToken)
    );
    const sigBuf = await crypto.subtle.sign(
      "HMAC",
      await crypto.subtle.importKey(
        "raw",
        skBits,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      ),
      enc.encode(dataCheckString)
    );
    const computed = [...new Uint8Array(sigBuf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (computed !== String(hash).toLowerCase()) {
      return { ok: false, detail: "bad_hash" };
    }

    const authDate = parseInt(params.get("auth_date") || "0", 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (!authDate || nowSec - authDate > maxAgeSec) {
      return { ok: false, detail: "expired" };
    }
    if (authDate > nowSec + 120) {
      return { ok: false, detail: "auth_in_future" };
    }

    let userId = "";
    const userRaw = params.get("user");
    if (userRaw) {
      try {
        const user = JSON.parse(userRaw);
        if (user && user.id) userId = String(user.id);
      } catch (_) {}
    }
    if (!userId) return { ok: false, detail: "no_user" };
    return { ok: true, userId, authDate };
  } catch (e) {
    return { ok: false, detail: "validate_error:" + String(e && e.message || e) };
  }
}

async function checkVpn(ip, proxycheckKey) {
  // Returns { vpn: true/false, detail }
  // Explicit proxy/vpn/tor → block. Network errors → try next source.

  // 1) proxycheck.io
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
        if (proxy === "yes") {
          return { vpn: true, detail: "proxycheck:proxy:" + (type || "yes") };
        }
        if (
          type.includes("vpn") ||
          type.includes("tor") ||
          type.includes("socks") ||
          type.includes("proxy")
        ) {
          return { vpn: true, detail: "proxycheck:type:" + type };
        }
        if (risk >= 66) {
          return { vpn: true, detail: "proxycheck:risk:" + risk };
        }
      }
    }
  } catch (_) {}

  // 2) ipwho.is
  try {
    const r2 = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      cf: { cacheTtl: 60 },
    });
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

  // 3) ipapi.is (free tier, no key)
  try {
    const r3 = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, {
      cf: { cacheTtl: 60 },
    });
    if (r3.ok) {
      const d3 = await r3.json();
      if (d3) {
        if (d3.is_vpn === true || d3.is_proxy === true || d3.is_tor === true) {
          return { vpn: true, detail: "ipapi.is" };
        }
        if (d3.company && d3.company.type === "hosting" && d3.is_datacenter === true) {
          // Datacenter IP used for multi-accounting often — block
          return { vpn: true, detail: "ipapi.is:datacenter" };
        }
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

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const buf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
  h.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(res.body, { status: res.status, headers: h });
}
