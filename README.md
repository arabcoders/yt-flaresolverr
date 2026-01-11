# yt-flaresolverr

A [yt-dlp](https://github.com/yt-dlp/yt-dlp) plugin that integrates with [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) to automatically bypass Cloudflare protection when downloading videos.

This plugin acts as a custom request handler that detects Cloudflare challenge responses (HTTP 403, 429, or 503 with Cloudflare headers) and automatically solves them using FlareSolverr, allowing yt-dlp to access protected content seamlessly.

## Features

- Automatic Cloudflare challenge detection and solving
- **5-minute solution caching** to minimize redundant FlareSolverr requests
- Support for cookie persistence across requests
- User-Agent rotation from FlareSolverr solutions
- Configurable timeout settings
- Seamless integration with yt-dlp's request handler system

## Requirements

- yt-dlp `2023.01.02` or higher
- A running [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) instance

## Installation

### Using pip

Install directly from the repository:

```bash
python -m pip install -U https://github.com/arabcoders/yt-flaresolverr/archive/main.zip
```

### Manual Installation

1. Download or clone this repository
2. Place the plugin in one of yt-dlp's [supported plugin directories](https://github.com/yt-dlp/yt-dlp#installing-plugins).

For more installation methods, see [installing yt-dlp plugins](https://github.com/yt-dlp/yt-dlp#installing-plugins).

## Configuration

The plugin is configured using environment variables:

### Required Settings

- **`FLARESOLVERR_URL`**: The URL of your FlareSolverr instance (e.g., `http://localhost:8191/v1`)
  
  The plugin will only activate when this environment variable is set.

### Optional Settings

- **`FLARESOLVERR_CLIENT_TIMEOUT`**: Timeout in seconds for the HTTP request to FlareSolverr (default: `60`)
  
  This controls how long to wait for FlareSolverr to respond.

- **`FLARESOLVERR_TIMEOUT_DEFAULT`**: Maximum timeout in seconds for FlareSolverr to solve the challenge (default: `60`)
  
  This is passed to FlareSolverr as `maxTimeout` and controls how long FlareSolverr should spend solving the challenge.

### Example Usage

```bash
# Set the FlareSolverr URL
export FLARESOLVERR_URL="http://localhost:8191/v1"

# Optional: Set custom timeouts
export FLARESOLVERR_CLIENT_TIMEOUT="120"
export FLARESOLVERR_TIMEOUT_DEFAULT="90"

# Use yt-dlp normally
yt-dlp "https://example.com/video"
```

On Windows (PowerShell):
```powershell
$env:FLARESOLVERR_URL = "http://localhost:8191/v1"
yt-dlp "https://example.com/video"
```

## How It Works

1. The plugin registers a custom request handler with yt-dlp
2. When a request receives a Cloudflare challenge response (403, 429, or 503 with Cloudflare headers), it's intercepted
3. The plugin checks if a cached solution exists for the domain (valid for 5 minutes)
4. If cached, it reuses the stored cookies and headers; otherwise, it sends the request to FlareSolverr for solving
5. FlareSolverr returns cookies and headers that bypass the protection
6. The solution is cached for 5 minutes to avoid redundant requests to the same domain
7. The plugin applies these to the original request and retries it
8. The download proceeds normally

## Setting Up FlareSolverr

If you don't have FlareSolverr running, you can start it using Docker:

```bash
docker run -d \
  --name=flaresolverr \
  -p 8191:8191 \
  -e LOG_LEVEL=info \
  --restart unless-stopped \
  ghcr.io/flaresolverr/flaresolverr:latest
```

The service will be available at `http://localhost:8191/v1`.

## Troubleshooting

- **Plugin not activating**: Make sure `FLARESOLVERR_URL` is set and accessible
- **Timeout errors**: Increase `FLARESOLVERR_CLIENT_TIMEOUT` or `FLARESOLVERR_TIMEOUT_DEFAULT`
- **Connection errors**: Verify FlareSolverr is running and the URL is correct
- **Still getting Cloudflare errors**: Some sites may have additional protection; check FlareSolverr logs for details

Enable verbose logging with yt-dlp's `-v` flag to see detailed plugin activity.
