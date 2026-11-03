/**
 * Movi-Compatible Streaming Media Proxy Worker
 *
 * Features:
 * 1. URL Hiding & AES-256-GCM Encryption: The real video/storage URL is encrypted into an opaque token.
 * 2. Zero-CORS & COEP Support: Injects Access-Control-Allow-Origin: * and Cross-Origin-Resource-Policy: cross-origin.
 * 3. Range Pass-Through (206 Partial Content): Supports instant seeking across multi-GB files.
 * 4. Simulated HEAD for S3/R2: S3 pre-signed URLs reject HEAD with 403; worker automatically translates to GET bytes=0-0.
 * 5. Magic Byte Sniffing: Validates legitimate media containers (MKV, MP4, WebM, TS, etc.).
 */

const DEFAULT_SIG_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const MAGIC_SNIFF_SIZE = 32;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Range, Authorization, X-Requested-With",
  "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type, Content-Disposition",
};

const ALLOWED_CONTENT_TYPES = [
  "video/",
  "audio/",
  "application/octet-stream",
  "application/x-matroska",
  "application/x-mpegurl",
  "application/vnd.apple.mpegurl",
  "application/dash+xml",
];

// --- Cryptographic & Encoding Helpers ---

function b64urlEncode(uint8Array) {
  let bin = "";
  for (let i = 0; i < uint8Array.length; i++) bin += String.fromCharCode(uint8Array[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getAesGcmKey(secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// Encrypt target URL and metadata into an opaque, URL-safe AES-256-GCM token
async function encryptTargetUrl(secret, payload) {
  const key = await getAesGcmKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return b64urlEncode(combined);
}

// Decrypt opaque AES-256-GCM token back to target URL and metadata
async function decryptTargetUrl(secret, token) {
  try {
    const combined = b64urlDecode(token);
    if (combined.length < 28) return null; // 12-byte IV + 16-byte minimum auth tag
    const iv = combined.subarray(0, 12);
    const ciphertext = combined.subarray(12);

    const key = await getAesGcmKey(secret);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  }
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
      ...headers,
    },
  });
}

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1" || host === "::") return true;
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) return true;
  if (host.includes(":")) {
    if (/^f[cd]/.test(host)) return true;
    if (/^fe[89ab]/.test(host)) return true;
    return false;
  }
  const parts = host.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
  }
  return false;
}

function hasSupportedSignature(buf) {
  if (!buf || buf.length < 4) return false;
  const b = buf;
  // MKV / WebM (EBML: 1A 45 DF A3)
  if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return true;
  // ISO BMFF (MP4/MOV/M4A/CMAF)
  if (buf.length >= 8) {
    const isBox = (c1, c2, c3, c4) => b[4] === c1 && b[5] === c2 && b[6] === c3 && b[7] === c4;
    if (isBox(0x66, 0x74, 0x79, 0x70) || isBox(0x73, 0x74, 0x79, 0x70) ||
        isBox(0x6D, 0x6F, 0x6F, 0x66) || isBox(0x6D, 0x6F, 0x6F, 0x76) || isBox(0x6D, 0x64, 0x61, 0x74)) return true;
  }
  // RIFF (AVI / WAV)
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46) return true;
  // MPEG-TS, FLV, OGG, FLAC, HLS
  if (b[0] === 0x47 || (b[0] === 0x46 && b[1] === 0x4C && b[2] === 0x56) ||
      (b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67) ||
      (b[0] === 0x66 && b[1] === 0x4C && b[2] === 0x61 && b[3] === 0x43) ||
      (b[0] === 0x23 && b[1] === 0x45 && b[2] === 0x58 && b[3] === 0x54)) return true;
  // MP3
  if ((b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) || (b[0] === 0xFF && (b[1] & 0xE0) === 0xE0)) return true;

  return false;
}

async function sniffAndPassthrough(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < MAGIC_SNIFF_SIZE) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } catch {
    reader.cancel().catch(() => {});
    return { ok: false, stream: null };
  }
  const prefix = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    prefix.set(c, off);
    off += c.byteLength;
  }
  if (!hasSupportedSignature(prefix)) {
    reader.cancel().catch(() => {});
    return { ok: false, stream: null };
  }
  const { readable, writable } = new TransformStream();
  (async () => {
    const writer = writable.getWriter();
    try {
      await writer.write(prefix);
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        await writer.write(value);
      }
      await writer.close();
    } catch (err) {
      try { await writer.abort(err); } catch {}
    }
  })();
  return { ok: true, stream: readable };
}

function extractFilename(urlStr) {
  try {
    const u = new URL(urlStr);
    const p = u.pathname;
    const base = p.substring(p.lastIndexOf("/") + 1);
    return decodeURIComponent(base.split("?")[0]) || "video.mkv";
  } catch {
    return "video.mkv";
  }
}

// --- Handler: Mint Encrypted Stream Token (Hides the Real URL) ---
async function handleSign(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "Invalid JSON body" }, 400); }
  const targetUrl = typeof body?.url === "string" ? body.url.trim() : "";
  if (!targetUrl) return jsonResponse({ error: "Missing 'url' parameter" }, 400);

  let parsed;
  try { parsed = new URL(targetUrl); } catch { return jsonResponse({ error: "Invalid URL string" }, 400); }
  if (!["http:", "https:"].includes(parsed.protocol)) return jsonResponse({ error: "Only HTTP/HTTPS allowed" }, 400);
  if (isPrivateHost(parsed.hostname)) return jsonResponse({ error: "Private network targets not allowed" }, 403);

  const secret = env.PROXY_SECRET || "default-secret-change-in-wrangler";
  const expiresAt = Date.now() + DEFAULT_SIG_TTL_MS;

  // Encrypt the target URL so it is completely hidden from the client
  const token = await encryptTargetUrl(secret, { url: targetUrl, exp: expiresAt });
  const filename = extractFilename(targetUrl);

  return jsonResponse({
    // Stream URL with clean filename (video player recognizes container format)
    streamUrl: `/stream/${encodeURIComponent(filename)}?token=${token}`,
    // Short opaque stream URL
    rawStreamUrl: `/stream/${token}`,
    token,
    expiresAt,
  });
}

// --- Handler: Stream Video by Decrypting Token or Proxying URL ---
async function handleStream(request, url, env) {
  let targetUrl = "";
  const secret = env.PROXY_SECRET || "default-secret-change-in-wrangler";

  // 1. Try to extract encrypted token from query ?token= or path /stream/<token>
  let token = url.searchParams.get("token") || url.searchParams.get("id");
  if (!token && url.pathname.startsWith("/stream/")) {
    const pathPart = url.pathname.slice("/stream/".length);
    // If path is /stream/myvideo.mkv?token=xxx, token is in query
    // If path is /stream/<token>, extract from path
    if (pathPart && !pathPart.includes("/") && !pathPart.includes(".")) {
      token = pathPart;
    }
  }

  if (token) {
    const decrypted = await decryptTargetUrl(secret, token);
    if (!decrypted || !decrypted.url) {
      return jsonResponse({ error: "Invalid or corrupted stream token" }, 403);
    }
    if (decrypted.exp && Date.now() > decrypted.exp) {
      return jsonResponse({ error: "Stream token has expired" }, 410);
    }
    targetUrl = decrypted.url;
  } else {
    // 2. Fallback to direct raw URL (for backwards compatibility)
    targetUrl = url.searchParams.get("url") || "";
  }

  if (!targetUrl) {
    return jsonResponse({ error: "Missing stream token or URL" }, 400);
  }

  let parsed;
  try { parsed = new URL(targetUrl); } catch { return jsonResponse({ error: "Invalid target URL" }, 400); }
  if (!["http:", "https:"].includes(parsed.protocol)) return jsonResponse({ error: "Invalid protocol" }, 400);
  if (isPrivateHost(parsed.hostname)) return jsonResponse({ error: "Target host not allowed" }, 403);

  const fwdHeaders = new Headers();
  const range = request.headers.get("Range");
  if (range) fwdHeaders.set("Range", range);

  fwdHeaders.set(
    "User-Agent",
    request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
  );

  const isHead = request.method === "HEAD";
  const isSigV4 = parsed.searchParams.has("X-Amz-Signature") || parsed.searchParams.has("X-Amz-Algorithm");

  let upstream;
  let simulatedHead = false;

  try {
    // S3/R2 presigned URLs reject HEAD with 403. Fall back to GET bytes=0-0 to get headers and Content-Range.
    if (isHead && isSigV4) {
      simulatedHead = true;
      fwdHeaders.set("Range", "bytes=0-0");
      upstream = await fetch(targetUrl, {
        method: "GET",
        headers: fwdHeaders,
        redirect: "follow",
      });
    } else {
      upstream = await fetch(targetUrl, {
        method: isHead ? "HEAD" : "GET",
        headers: fwdHeaders,
        redirect: "follow",
      });

      if (isHead && (upstream.status === 403 || upstream.status === 405)) {
        simulatedHead = true;
        fwdHeaders.set("Range", "bytes=0-0");
        upstream = await fetch(targetUrl, {
          method: "GET",
          headers: fwdHeaders,
          redirect: "follow",
        });
      }
    }
  } catch (err) {
    return jsonResponse({ error: "Upstream fetch failed: " + err.message }, 502);
  }

  if (!upstream.ok && upstream.status !== 206) {
    return jsonResponse({ error: `Upstream error HTTP ${upstream.status}` }, upstream.status);
  }

  const outHeaders = new Headers({
    ...CORS_HEADERS,
    "Cross-Origin-Resource-Policy": "cross-origin",
    "Cache-Control": "private, no-store",
  });

  const passHeaders = ["Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"];
  for (const h of passHeaders) {
    const val = upstream.headers.get(h);
    if (val) outHeaders.set(h, val);
  }

  // Answer HEAD with 200 OK and real total Content-Length
  if (simulatedHead) {
    const cr = upstream.headers.get("Content-Range");
    if (cr) {
      const match = /\/\s*(\d+)\s*$/.exec(cr);
      if (match) outHeaders.set("Content-Length", match[1]);
    }
    outHeaders.set("Accept-Ranges", "bytes");
    try { upstream.body?.cancel(); } catch {}
    return new Response(null, { status: 200, headers: outHeaders });
  }

  let body = upstream.body;
  // Sniff magic bytes only when stream starts at 0 AND has enough bytes (>= 32 bytes)
  const zeroRange = range ? /^bytes=0-(\d*)$/i.exec(range.trim()) : null;
  const hasEnoughBytesToSniff =
    !range ||
    (!!zeroRange &&
      (zeroRange[1] === "" || parseInt(zeroRange[1], 10) >= MAGIC_SNIFF_SIZE - 1));

  if (!isHead && hasEnoughBytesToSniff && body) {
    const sniffed = await sniffAndPassthrough(body);
    if (!sniffed.ok) {
      return jsonResponse({ error: "Invalid video or audio container format" }, 415);
    }
    body = sniffed.stream;
  }

  return new Response(isHead ? null : body, {
    status: upstream.status,
    headers: outHeaders,
  });
}

// --- Main Entrypoint ---
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Stream endpoints (Accepts encrypted token or raw URL)
    if (url.pathname === "/proxy" || url.pathname.startsWith("/stream")) {
      return handleStream(request, url, env);
    }

    // Generate encrypted token (Hides the real URL)
    if ((url.pathname === "/api/proxy-sign" || url.pathname === "/api/hide" || url.pathname === "/api/token") && request.method === "POST") {
      return handleSign(request, env);
    }

    // Health / Landing check
    if (url.pathname === "/" || url.pathname === "/health") {
      return jsonResponse({
        status: "ok",
        service: "movi-stream-proxy",
        features: ["url-hiding-aes256", "range-seeking-206", "cors-bypass", "simulated-head"],
        endpoints: {
          hide_url: "POST /api/hide  { url: 'https://...' }  ->  returns /stream/video.mkv?token=...",
          stream: "GET /stream/video.mkv?token=...  or  GET /stream/:token",
        },
      });
    }

    return jsonResponse({ error: "Endpoint not found" }, 404);
  },
};
