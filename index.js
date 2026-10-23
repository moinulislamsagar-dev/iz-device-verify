/**
 * IZ Earn Device Verify Worker v3
 * - initData HMAC when present (inline button)
 * - keyboard launch: initData may be EMPTY (Telegram rule) → uid=0 in token
 * Secrets: BOT_TOKEN, RESULT_SECRET, TURNSTILE_SECRET
 * KV: VERIFY_KV
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
      return cors(json({ ok: true, service: "iz-device-verify", v: 3 }));
    }
    if (request.method === "POST" && (url.pathname === "/" || url.pathname === "/verify")) {
      try {
        return cors(await handleVerify(request, env));
      } catch (e) {
        return cors(json({ ok: false, reason: "server_error", detail: String(e && e.message || e) }, 500));
      }
    }
    return cors(json({ ok: false, reason: "not_found" }, 404));
  },
};

async function handleVerify(request, env) {
  const botToken = String(env.BOT_TOKEN || "").trim();
  const resultSecret = String(env.RESULT_SECRET || "").trim();
  if (!botToken || !resultSecret) {
    return json({ ok: false, reason: "misconfigured", detail: "BOT_TOKEN or RESULT_SECRET missing" }, 500);
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

  if (env.TURNSTILE_SECRET) {
    if (!turnstileToken) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "missing_token" });
    }
    const tsOk = await verifyTurnstile(turnstileToken, String(env.TURNSTILE_SECRET).trim(), clientIp(request));
    if (!tsOk) {
      return json({ ok: false, reason: "turnstile", ban: false, detail: "failed" });
    }
  }

  let uid = "0";
  if (initData && initData.length >= 20) {
    const initResult = await validateInitData(initData, botToken, INIT_MAX_AGE_SEC);
    if (!initResult.ok) {
      return json({ ok: false, reason: "init_data", ban: false, detail: initResult.detail });
    }
    uid = String(initResult.userId);
  }
  // else: keyboard launch — Telegram leaves initData empty; bot trusts message.from_user

  const ip = clientIp(request);
  if (!ip || ip === "0.0.0.0") {
    return json({ ok: false, reason: "ip", ban: false, detail: "no_ip" });
  }

  const net = await checkVpn(ip, env.PROXYCHECK_KEY || "");
  if (net.vpn) {
    return json({ ok: false, reason: "vpn", ban: false, ip, detail: net.detail || "vpn_or_proxy" });
  }

  if (!fingerprint || fingerprint.length < 6) {
    return json({ ok: false, reason: "fingerprint", ban: false, detail: "missing" });
  }

  const kv = env.VERIFY_KV;
  if (kv && uid !== "0") {
    const devKey = "dev:" + fingerprint;
    const ipKey = "ip:" + ip;
    const existingDev = await kv.get(devKey);
    if (existingDev && existingDev !== uid) {
      return json({ ok: false, reason: "multi_device", ban: true, detail: "device_used_by_" + existingDev });
    }
    const existingIp = await kv.get(ipKey);
    if (existingIp && existingIp !== uid) {
      return json({ ok: false, reason: "multi_ip", ban: true, detail: "ip_used_by_" + existingIp });
    }
    await kv.put(devKey, uid);
    await kv.put(ipKey, uid);
    await kv.put("user:" + uid, JSON.stringify({ fp: fingerprint, ip, platform, at: Math.floor(now / 1000) }));
  }

  // For keyboard mode (uid=0), still bind device by fingerprint only after bot assigns user
  // Bot will write used_devices / used_ips

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
    mode: uid === "0" ? "keyboard" : "initdata",
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
    const map = {};
    for (const part of initData.split("&")) {
      const eq = part.indexOf("=");
      if (eq < 0) continue;
      const k = decodeURIComponent(part.slice(0, eq));
      const v = decodeURIComponent(part.slice(eq + 1).replace(/\+/g, " "));
      map[k] = v;
    }
    const hash = map.hash;
    if (!hash) return { ok: false, detail: "no_hash" };

    const pairs = [];
    for (const k of Object.keys(map)) {
      if (k === "hash" || k === "signature") continue;
      pairs.push(k + "=" + map[k]);
    }
    pairs.sort();
    const dataCheckString = pairs.join("\n");

    const enc = new TextEncoder();
    const secretKey = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.sign(
        "HMAC",
        await crypto.subtle.importKey(
          "raw",
          enc.encode("WebAppData"),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign"]
        ),
        enc.encode(botToken)
      ),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const sigBuf = await crypto.subtle.sign("HMAC", secretKey, enc.encode(dataCheckString));
    const computed = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");

    if (computed !== String(hash).toLowerCase()) {
      return { ok: false, detail: "bad_hash" };
    }

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
  } catch (e) {
    return { ok: false, detail: "validate_error:" + String(e && e.message || e) };
  }
}

async function checkVpn(ip, proxycheckKey) {
  try {
    const q = proxycheckKey
      ? `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(proxycheckKey)}&vpn=1&asn=1`
      : `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1`;
    const r = await fetch(q, { cf: { cacheTtl: 120 } });
    if (r.ok) {
      const d = await r.json();
      const node = d && d[ip];
      if (node) {
        const proxy = String(node.proxy || "").toLowerCase();
        const type = String(node.type || "").toLowerCase();
        if (proxy === "yes") return { vpn: true, detail: "proxycheck:" + (type || "proxy") };
        if (type.includes("vpn") || type.includes("tor") || type.includes("socks")) {
          return { vpn: true, detail: "proxycheck:" + type };
        }
      }
    }
  } catch (_) {}
  try {
    const r2 = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { cf: { cacheTtl: 120 } });
    if (r2.ok) {
      const d2 = await r2.json();
      if (d2 && d2.success !== false && d2.security) {
        if (d2.security.vpn === true || d2.security.proxy === true || d2.security.tor === true) {
          return { vpn: true, detail: "ipwho" };
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
