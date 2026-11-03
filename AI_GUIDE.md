# AI Agent & Developer Integration Guide: Movi Video Stream Proxy

This document is a technical reference for AI coding assistants and developers explaining how to use the streaming video proxy (`https://proxyservr.kineflex-netflex.workers.dev/`).

---

## 1. What This Proxy Does

Browsers block direct playback of video files (MKV, MP4, WebM, etc.) hosted on external cloud storage (Cloudflare R2, AWS S3, Google Cloud Storage, Backblaze) due to:
1. **CORS (Cross-Origin Resource Sharing)**: Storage buckets often lack `Access-Control-Allow-Origin: *`.
2. **COEP (Cross-Origin-Embedder-Policy)**: WebCodecs and WebAssembly FFmpeg demuxers (like `<movi-player>`) require `Cross-Origin-Resource-Policy: cross-origin`.
3. **S3/R2 Pre-signed URL `HEAD` 403 Bug**: Pre-signed URLs are signed strictly for `GET`. When a video player sends a `HEAD` request to detect file size, S3/R2 rejects it with `403 Forbidden`.

This proxy solves all three issues while preserving HTTP `206 Partial Content` byte-range streaming for seeking and scrubbing through multi-gigabyte video files.

---

## 2. API Endpoints

**Base URL**: `https://proxyservr.kineflex-netflex.workers.dev`

### Endpoint 1: `GET /proxy` (Stream Media)
Fetches and streams the remote video while injecting CORS and range headers.

**Query Parameters:**
- `url` (required): The full, URI-encoded target video URL.
- `exp` (optional / required if signature enabled): Unix timestamp (milliseconds) when token expires.
- `sig` (optional / required if signature enabled): HMAC-SHA256 hex signature.

**Example Request:**
```http
GET /proxy?url=https%3A%2F%2Fstorage.example.com%2Fvideo.mkv HTTP/2
Host: proxyservr.kineflex-netflex.workers.dev
Range: bytes=0-1048575
```

**Response Headers Injected:**
```http
HTTP/2 206 Partial Content
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, Content-Type, Content-Disposition
Cross-Origin-Resource-Policy: cross-origin
Accept-Ranges: bytes
Content-Range: bytes 0-1048575/2174126278
Content-Disposition: attachment; filename="video.mkv"
```

---

### Endpoint 2: `POST /api/proxy-sign` (Mint Signed Token)
Generates an authorized proxy URL valid for 12 hours.

**Request:**
```http
POST /api/proxy-sign HTTP/2
Host: proxyservr.kineflex-netflex.workers.dev
Content-Type: application/json

{
  "url": "https://storage.example.com/video.mkv"
}
```

**Response:**
```json
{
  "url": "/proxy?url=https%3A%2F%2Fstorage.example.com%2Fvideo.mkv&exp=1793728376233&sig=dcf6074524dd...",
  "expiresAt": 1793728376233
}
```

---

## 3. How An AI Should Construct Proxy URLs

### Rule 1: Always URI-Encode the Target URL
Target URLs frequently contain `?`, `&`, `=`, and authentication tokens (like AWS SigV4 `X-Amz-Signature`). If you do not encode the entire URL with `encodeURIComponent()`, query parameters get corrupted.

```javascript
// ✅ CORRECT:
const proxyUrl = `https://proxyservr.kineflex-netflex.workers.dev/proxy?url=${encodeURIComponent(rawVideoUrl)}`;

// ❌ WRONG (parameters break):
const proxyUrl = `https://proxyservr.kineflex-netflex.workers.dev/proxy?url=${rawVideoUrl}`;
```

### Rule 2: Do NOT Proxy Adaptive Manifests (`.m3u8` / `.mpd`)
HLS (`.m3u8`) and DASH (`.mpd`) manifests contain relative segment paths (e.g. `segment_001.ts`). Routing the master manifest through `/proxy` breaks relative segment resolution. CDNs hosting HLS/DASH already enable CORS, so load manifests directly:
```javascript
function shouldProxy(url) {
  if (/\.(m3u8|mpd)(\?|$)/i.test(url)) return false; // Load directly
  return true; // Proxy MKV, MP4, WebM, AVI, TS, etc.
}
```

---

## 4. Reusable Integration Code

### JavaScript / TypeScript Helper
```javascript
const PROXY_WORKER = "https://proxyservr.kineflex-netflex.workers.dev";

/**
 * Returns a CORS-safe streaming URL for any media file.
 * Handles both signed and direct proxy modes automatically.
 */
async function getPlaybackUrl(targetUrl) {
  // Adaptive manifests should not be proxied
  if (/\.(m3u8|mpd)(\?|$)/i.test(targetUrl)) {
    return targetUrl;
  }

  try {
    // 1. Attempt to sign the URL (safe for production mode)
    const res = await fetch(`${PROXY_WORKER}/api/proxy-sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl }),
    });

    if (res.ok) {
      const data = await res.json();
      return `${PROXY_WORKER}${data.url}`;
    }
  } catch (err) {
    console.warn("Proxy signing unavailable, falling back to direct proxy URL", err);
  }

  // 2. Fallback to direct unsigned proxy mode
  return `${PROXY_WORKER}/proxy?url=${encodeURIComponent(targetUrl)}`;
}
```

---

## 5. Using with Video Players

### With `<movi-player>` (Supports MKV, AV1, HEVC, HDR):
```html
<script type="module" src="https://unpkg.com/movi-player@latest/dist/element.js"></script>

<movi-player 
  id="player"
  src="https://proxyservr.kineflex-netflex.workers.dev/proxy?url=https%3A%2F%2Fstorage.example.com%2Fvideo.mkv"
  controls 
  autoplay>
</movi-player>
```

### With Standard HTML5 `<video>` (MP4 / WebM):
```html
<video 
  src="https://proxyservr.kineflex-netflex.workers.dev/proxy?url=https%3A%2F%2Fstorage.example.com%2Fvideo.mp4" 
  controls>
</video>
```

### With React / Next.js:
```tsx
import React, { useEffect, useState } from "react";

export function VideoPlayer({ rawUrl }: { rawUrl: string }) {
  const [streamUrl, setStreamUrl] = useState<string>("");

  useEffect(() => {
    const PROXY = "https://proxyservr.kineflex-netflex.workers.dev";
    setStreamUrl(`${PROXY}/proxy?url=${encodeURIComponent(rawUrl)}`);
  }, [rawUrl]);

  if (!streamUrl) return <div>Loading stream...</div>;

  return (
    <movi-player src={streamUrl} controls />
  );
}
```

---

## 6. HTTP Status Code Reference

| Status | Cause | Solution |
| :--- | :--- | :--- |
| **`206 Partial Content`** | Normal streaming response for range requests. | Expected behavior. |
| **`200 OK`** | Response for simulated `HEAD` or complete file fetch. | Expected behavior. |
| **`400 Bad Request`** | Missing `?url=` parameter or invalid URL protocol. | Ensure URL is valid `http://` or `https://` and encoded. |
| **`403 Forbidden`** | Target is a private/local IP (SSRF block) or signature is invalid. | Check that target URL is public and signature matches. |
| **`410 Gone`** | Signed token has expired past its 12-hour TTL. | Re-fetch `/api/proxy-sign` for a fresh token. |
| **`415 Unsupported Media`**| File is not video/audio (magic byte validation failed). | Verify target URL points to a valid media container. |
| **`502 Bad Gateway`** | Upstream origin server is unreachable or timed out. | Check if origin URL is online and accessible. |
