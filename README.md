# 🛡️ Premium Loader v5.1.0

Secure Roblox Script Loader with Full Protection Features.

## Features

- ✅ Challenge-Response Authentication
- ✅ XOR Encryption with Session Keys
- ✅ Roblox User Verification
- ✅ Owner Detection & Auto-Cleanup
- ✅ Tool Detection & Auto-Ban
- ✅ GUI Tracking & Cleanup
- ✅ Rate Limiting
- ✅ Browser Detection
- ✅ Obfuscation Support

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Status |
| GET | `/health` | Health check |
| GET | `/debug` | Debug info |
| GET | `/loader` | Secure 2-step loader |
| GET | `/script` | Legacy endpoint |
| POST | `/api/auth/challenge` | Get challenge |
| POST | `/api/auth/verify` | Verify & get script |
| POST | `/api/ban` | Ban device |

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SCRIPT_SOURCE_URL` | URL to your Lua script | Yes |
| `SCRIPT_ALREADY_OBFUSCATED` | Set to `true` if script is obfuscated | No |
| `WHITELIST_USER_IDS` | Comma-separated user IDs | No |
| `OWNER_USER_IDS` | Comma-separated owner IDs | No |
| `ALLOWED_PLACE_IDS` | Comma-separated place IDs | No |
| `ADMIN_KEY` | Admin API key | Yes |
| `SECRET_KEY` | Encryption secret | Yes |

## Usage

```lua
-- Secure loader (recommended)
loadstring(game:HttpGet("https://your-server.com/loader"))()

-- Legacy loader
loadstring(game:HttpGet("https://your-server.com/script"))()
