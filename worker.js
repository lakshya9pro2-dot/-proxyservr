/**
 * Movi-Compatible Streaming Media Proxy Worker
 *
 * Solves:
 * 1. CORS blocking (Cross-Origin Resource Sharing) on storage buckets (R2, S3, B2, CDNs).
 * 2. Cross-Origin-Embedder-Policy (COEP) requirement for SharedArrayBuffer / FFmpeg WASM.
 * 3. Range requests pass-through (HTTP 206 Partial Content) for seeking & scrubbing multi-GB files.
 * 4. Anti-abuse signed URLs (/api/proxy-sign) with 12h HMAC tokens to prevent bandwidth leeching.
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

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function isPrivateHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host === "::1" || host === "::") return true;
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) return true;
  if (host.includes(":")) {
    if (/^f[cd]/.test(host)) return true; // fc00::/7
    if (/^fe[89ab]/.test(host)) return true; // fe80::/10
    return false;
  }
  const parts = host.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 127) return true; // 127.0.0.0/8
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    if (parts[0] === 0) return true;
  }
  return false;
}

function hasSupportedSignature(buf) {
  if (!buf || buf.length < 4) return false;
  const b = buf;
  // MKV / WebM (EBML: 1A 45 DF A3)
  if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return true;
  // ISO BMFF (MP4/MOV/M4A/CMAF segments)
  if (b.length >= 8) {
    const isBox = (c1, c2, c3, c4) => b[4] === c1 && b[5] === c2 && b[6] === c3 && b[7] === c4;
    if (isBox(0x66, 0x74, 0x79, 0x70)) return true; // ftyp
    if (isBox(0x73, 0x74, 0x79, 0x70)) return true; // styp
    if (isBox(0x6D, 0x6F, 0x6F, 0x66)) return true; // moof
    if (isBox(0x6D, 0x6F, 0x6F, 0x76)) return true; // moov
    if (isBox(0x6D, 0x64, 0x61, 0x74)) return true; // mdat
  }
  // RIFF (AVI / WAV)
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46) return true;
  // MPEG-TS sync byte
  if (b[0] === 0x47) return true;
  // FLV
  if (b[0] === 0x46 && b[1] === 0x4C && b[2] === 0x56) return true;
  // OGG
  if (b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53) return true;
  // FLAC
  if (b[0] === 0x66 && b[1] === 0x4C && b[2] === 0x61 && b[3] === 0x43) return true;
  // HLS M3U
  if (b[0] === 0x23 && b[1] === 0x45 && b[2] === 0x58 && b[3] === 0x54) return true;
  // MP3 (ID3 or sync header)
  if ((b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) || (b[0] === 0xFF && (b[1] & 0xE0) === 0xE0)) return true;

  return false;
}

// Sniff magic bytes on stream without buffering whole payload into memory
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

// --- Handler: Mint Signed URLs (/api/proxy-sign) ---
async function handleSign(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }

  const targetUrl = typeof body?.url === "string" ? body.url.trim() : "";
  if (!targetUrl) return jsonResponse({ error: "Missing 'url' parameter" }, 400);

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return jsonResponse({ error: "Invalid URL string" }, 400);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return jsonResponse({ error: "Only HTTP/HTTPS allowed" }, 400);
  }
  if (isPrivateHost(parsed.hostname)) {
    return jsonResponse({ error: "Private network targets not allowed" }, 403);
  }

  const secret = env.PROXY_SECRET || "default-secret-change-in-wrangler";
  const expiresAt = Date.now() + DEFAULT_SIG_TTL_MS;
  const sig = await hmacSha256Hex(secret, `proxy:${expiresAt}:${targetUrl}`);

  return jsonResponse({
    url: `/proxy?url=${encodeURIComponent(targetUrl)}&exp=${expiresAt}&sig=${sig}`,
    expiresAt,
  });
}

// --- Handler: Stream Video (/proxy) ---
async function handleProxy(request, url, env) {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) return jsonResponse({ error: "Missing ?url= parameter" }, 400);

  // Signature Verification (set REQUIRE_SIGNATURE = "false" to disable)
  const requireSig = env.REQUIRE_SIGNATURE !== "false";
  if (requireSig) {
    const expRaw = url.searchParams.get("exp");
    const sigGiven = url.searchParams.get("sig");
    if (!expRaw || !sigGiven) {
      return jsonResponse({ error: "Missing signature (?exp= and ?sig= required)" }, 403);
    }
    const expiresAt = Number(expRaw);
    if (!Number.isSafeInteger(expiresAt) || Date.now() > expiresAt) {
      return jsonResponse({ error: "Signature expired" }, 410);
    }
    const secret = env.PROXY_SECRET || "default-secret-change-in-wrangler";
    const expectedSig = await hmacSha256Hex(secret, `proxy:${expiresAt}:${targetUrl}`);
    if (!constantTimeEqual(sigGiven, expectedSig)) {
      return jsonResponse({ error: "Invalid signature" }, 403);
    }
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return jsonResponse({ error: "Invalid target URL" }, 400);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return jsonResponse({ error: "Invalid protocol" }, 400);
  }
  if (isPrivateHost(parsed.hostname)) {
    return jsonResponse({ error: "Target host not allowed" }, 403);
  }

  // Forward Range and standard media headers
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
    // S3/R2 presigned URLs are signed for GET only; sending HEAD to them results in 403 Forbidden.
    // If the client wants HEAD on an S3 presigned URL, or if HEAD returns 403/405, fall back to GET bytes=0-0.
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

      // If HEAD failed with 403 or 405 (common for pre-signed URLs or CDNs), retry with GET bytes=0-0
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

  // Content-Type validation
  const contentType = upstream.headers.get("Content-Type") || "";
  const isAllowedType = ALLOWED_CONTENT_TYPES.some((t) => contentType.toLowerCase().startsWith(t));
  if (!isAllowedType && contentType && !contentType.startsWith("application/")) {
    return jsonResponse({ error: "Content type not allowed: " + contentType }, 415);
  }

  // Setup streaming response with CORS headers
  const outHeaders = new Headers({
    ...CORS_HEADERS,
    "Cross-Origin-Resource-Policy": "cross-origin",
    "Cache-Control": "private, no-store",
  });

  // Preserve essential streaming headers
  const passHeaders = ["Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"];
  for (const h of passHeaders) {
    const val = upstream.headers.get(h);
    if (val) outHeaders.set(h, val);
  }

  // If this was a simulated HEAD request using GET bytes=0-0:
  // Extract total file size from Content-Range (e.g., bytes 0-0/2174126278) and set Content-Length!
  if (simulatedHead) {
    const cr = upstream.headers.get("Content-Range");
    if (cr) {
      const match = /\/\s*(\d+)\s*$/.exec(cr);
      if (match) {
        outHeaders.set("Content-Length", match[1]);
      }
    }
    outHeaders.set("Accept-Ranges", "bytes");
    try { upstream.body?.cancel(); } catch {}
    return new Response(null, {
      status: 200,
      headers: outHeaders,
    });
  }

  let body = upstream.body;
  // Sniff magic bytes only if stream starts at 0 AND has enough bytes (>= 32 bytes).
  // A tiny probe like bytes=0-0 or bytes=0-1 is used to detect file size / range support;
  // sniffing it would falsely fail with 415.
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

    // Handle CORS preflight for all endpoints
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (url.pathname === "/proxy") {
      return handleProxy(request, url, env);
    }

    if (url.pathname === "/api/proxy-sign" && request.method === "POST") {
      return handleSign(request, env);
    }

    // Health / Landing check
    if (url.pathname === "/" || url.pathname === "/health") {
      return jsonResponse({
        status: "ok",
        service: "movi-stream-proxy",
        endpoints: {
          sign: "POST /api/proxy-sign  { url: 'https://...' }",
          proxy: "GET /proxy?url=...&exp=...&sig=...",
        },
      });
    }

    return jsonResponse({ error: "Endpoint not found" }, 404);
  },
};
