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

## How to Hide Real Video URLs (AES-256-GCM)

To completely hide your Cloudflare R2 / AWS S3 storage URL from users, DevTools, and page source:

### 1. Mint an Encrypted Stream URL (`POST /api/hide`)
```bash
curl -X POST https://<your-worker>.workers.dev/api/hide \
  -H "Content-Type: application/json" \
  -d '{"url":"https://701ab416771ea1b49a24683d35a33206.r2.cloudflarestorage.com/hub/movie.mkv?sig=..."}'
```

Response:
```json
{
  "streamUrl": "/stream/movie.mkv?token=6SqeR2e309A65hu3J7rfkLo1KOA_hOdQ...",
  "rawStreamUrl": "/stream/6SqeR2e309A65hu3J7rfkLo1KOA_hOdQ...",
  "token": "6SqeR2e309A65hu3J7rfkLo1KOA_hOdQ...",
  "expiresAt": 1793728376233
}
```

### 2. Pass the Hidden Stream URL to the Player:
```html
<movi-player 
  src="https://<your-worker>.workers.dev/stream/movie.mkv?token=6SqeR2e309A65hu3J7rfkLo1KOA_hOdQ..." 
  controls>
</movi-player>
```
**No one can see your real storage bucket URL, S3 credentials, or access keys.** Only the server holding `PROXY_SECRET` can decrypt the token.
