# Movi Streaming Media Proxy Worker

A standalone Cloudflare Worker designed for `<movi-player>` and HTML5 video to stream large video files (MKV, MP4, WebM, etc.) past CORS restrictions with full HTTP Range request support (seeking & scrubbing).

## Files in this folder:
- **`worker.js`**: The Cloudflare Worker script.
- **`wrangler.toml`**: Cloudflare deployment and environment configuration.
- **`package.json`**: NPM scripts for running locally or deploying.
- **`test.html`**: Ready-to-use HTML test page with `<movi-player>`.

---

## Quick Start (Deploying to Cloudflare)

### Option 1: Via Cloudflare Web Dashboard (No CLI needed)
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) > **Workers & Pages** > **Create Application** > **Create Worker**.
2. Give it a name and click **Deploy**.
3. Click **Quick Edit** (or Edit Code), paste the contents of [`worker.js`](worker.js), and click **Save and Deploy**.
4. In **Settings > Variables**, set:
   - `REQUIRE_SIGNATURE` = `false` (for instant direct use without tokens) or `true` (for signed tokens).
   - `PROXY_SECRET` = your secret string.

### Option 2: Via Terminal / Wrangler CLI
```bash
cd video-proxy

# Run locally on http://127.0.0.1:8787
npx wrangler dev

# Deploy to your Cloudflare account
npx wrangler deploy
```

---

## How to Stream Video

### 1. Direct Mode (`REQUIRE_SIGNATURE = "false"`)
Format the URL:
```
https://<your-worker>.workers.dev/proxy?url=<ENCODED_VIDEO_URL>
```
Example in HTML:
```html
<movi-player 
  src="https://<your-worker>.workers.dev/proxy?url=https%3A%2F%2Fexample.com%2Fmovie.mkv" 
  controls>
</movi-player>
```

### 2. Signed Mode (`REQUIRE_SIGNATURE = "true"`)
1. Call `POST /api/proxy-sign`:
```bash
curl -X POST https://<your-worker>.workers.dev/api/proxy-sign \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/movie.mkv"}'
```
Response:
```json
{
  "url": "/proxy?url=https%3A%2F%2Fexample.com%2Fmovie.mkv&exp=1793726362694&sig=f8c486...",
  "expiresAt": 1793726362694
}
```

2. Pass the full URL to the player:
```html
<movi-player src="https://<your-worker>.workers.dev/proxy?url=...&exp=...&sig=..." controls></movi-player>
```
