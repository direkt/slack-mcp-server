# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**slack-mcp-server** is a Model Context Protocol (MCP) server that provides access to Slack workspaces via various tools and resources. It's built in Go and supports multiple authentication modes (OAuth and stealth modes), multiple transports (stdio, SSE, HTTP), and includes caching for users and channels.

## Development Commands

### Building

```bash
# Build for current platform
make build

# Build for all platforms (darwin, linux, windows; amd64, arm64)
make build-all-platforms

# Clean build artifacts
make clean
```

### Testing

```bash
# Run unit tests only
make test

# Run integration tests only
make test-integration

# Run all tests
make test && make test-integration
```

### Code Maintenance

```bash
# Format code (required before commit)
make format

# Tidy Go modules
make tidy

# Run build, tidy, and format together (recommended)
make build
```

### Release & Publishing

```bash
# Create a release tag (used by CI/CD)
make tag TAG=vX.Y.Z

# Copy binaries to npm packages (for npm distribution)
make npm-copy-binaries

# Publish to npm (requires NPM_TOKEN env var)
make npm-publish

# Build DTX extension (requires dxt tool)
make build-dxt
```

## Architecture

### Core Components

**Provider Layer** (`pkg/provider/`)
- `api.go`: Main `ApiProvider` struct that wraps Slack API clients and manages caching
- `edge/`: Custom Edge API client for stealth mode (bypasses official Slack API)
- Manages two caches: Users cache and Channels cache (both optional but improve functionality)
- Supports both OAuth (`xoxp-` token) and stealth mode (`xoxc-`/`xoxd-` tokens)

**Handler Layer** (`pkg/handler/`)
- `conversations.go`: Implements conversation-related tools (history, replies, add_message, search)
- `channels.go`: Implements channels_list tool
- Each handler converts request parameters into calls to the provider layer

**Server Layer** (`pkg/server/`)
- `server.go`: Sets up MCP server with tools, resources, and middleware
- `auth/`: Authentication middleware that validates API keys for SSE/HTTP transports
- Registers tools via `mcp.NewTool()` with descriptions and parameter schemas
- Exposes resources: `slack://<workspace>/channels` and `slack://<workspace>/users` (CSV format)

**Transport Layer** (`pkg/transport/`)
- Handles HTTP client setup with custom TLS for Enterprise Slack
- Proxy support via `SLACK_MCP_PROXY` environment variable

**Entry Point** (`cmd/slack-mcp-server/main.go`)
- Supports three transport types: stdio (default), sse, http
- Sets up logging with color/JSON formatting based on environment
- Initializes provider and spawns cache refresh goroutines
- Validates `SLACK_MCP_ADD_MESSAGE_TOOL` config at startup

### Authentication Flow

1. **Provider Initialization** (`pkg/provider.New()`)
   - Reads auth tokens from environment variables
   - Creates either OAuth or stealth client depending on token type
   - Supports three auth modes: `xoxp-` (OAuth), `xoxc-`/`xoxd-` (stealth), or both

2. **Cache Warming** (main.go watchers)
   - Spawns goroutines to call `RefreshUsers()` and `RefreshChannels()`
   - Server can handle requests before caches are ready (limited functionality)
   - `IsReady()` returns true once both caches are populated

### Key Data Structures

**ApiProvider** - Manages Slack API access and caches
- `users` / `usersInv`: User maps (ID→User, username→ID)
- `channels` / `channelsInv`: Channel maps (ID→Channel, name→ID)
- `rateLimiter`: Rate limiting for Slack API calls

**Channel** - Represents a Slack channel/DM/MPIM
- `ID`, `Name`, `Topic`, `Purpose`, `MemberCount`
- `IsIM`, `IsMpIM`, `IsPrivate`: Channel type flags
- `User`: User ID for direct messages
- `Members`: Member list (when available)

**Message** (handler) - Represents a message in responses
- Includes user info (ID, name, real name), channel, thread info
- Contains message text, timestamp, reactions, and cursor for pagination

### Tool Implementation Pattern

Each tool in `server.go` follows this pattern:
1. Define MCP tool with `mcp.NewTool()` including description and parameters
2. Create handler in `handler/conversations.go` or `handler/channels.go`
3. Handler extracts/validates parameters, calls provider methods
4. Provider calls underlying Slack API or Edge API
5. Format results and return as structured data

## Key Behaviors & Patterns

### Message Pagination

- Limit can be time-based (`1d`, `7d`, `1m`, `90d`) or count-based (e.g., `50`)
- Cursor-based pagination: use cursor from previous response as `cursor` parameter
- When cursor is provided, limit should be empty
- Last message in response contains `next_cursor` for continuation

### Channel Lookup

- Channels can be referenced by ID (`C1234567890`), name (`#general`), or user handle (`@user_dm`)
- Handler resolves names/handles to IDs via the caches
- Without caches, only ID-based lookups work

### Search Filtering

- Multiple filter parameters can be combined (e.g., channel + user + date)
- Supports date ranges with natural language (`Yesterday`, `July`, etc.)
- Full Slack message URL can be passed as `search_query` to fetch single message

### Resource Types

Two CSV-formatted resources are exposed:
- `slack://<workspace>/channels`: Lists all channels with metadata
- `slack://<workspace>/users`: Lists all users with real names

### Message Posting Safety

- `conversations_add_message` is **disabled by default**
- Enable with `SLACK_MCP_ADD_MESSAGE_TOOL=true` (all channels) or comma-separated channel IDs
- Supports channel whitelisting and blacklisting (`!C123` excludes a channel)
- Optional unfurling control via `SLACK_MCP_ADD_MESSAGE_UNFURLING`

## Environment Variables

Essential:
- `SLACK_MCP_XOXP_TOKEN`: OAuth user token (OR xoxc/xoxd below)
- `SLACK_MCP_XOXC_TOKEN`: Browser session token
- `SLACK_MCP_XOXD_TOKEN`: Browser cookie

Optional:
- `SLACK_MCP_PORT`: SSE/HTTP port (default: 13080)
- `SLACK_MCP_HOST`: Server host (default: 127.0.0.1)
- `SLACK_MCP_API_KEY`: Bearer token for SSE/HTTP transports
- `SLACK_MCP_ADD_MESSAGE_TOOL`: Enable/configure message posting
- `SLACK_MCP_USERS_CACHE`: Path to users cache file (default: `.users_cache.json`)
- `SLACK_MCP_CHANNELS_CACHE`: Path to channels cache file (default: `.channels_cache_v2.json`)
- `SLACK_MCP_LOG_LEVEL`: Log level (debug, info, warn, error, panic, fatal)
- `SLACK_MCP_LOG_FORMAT`: `json` or console (auto-detected by environment)

## Testing Strategy

- **Unit tests**: Test individual handlers and provider methods in isolation (`*_test.go` files)
- **Integration tests**: Use ngrok/test utilities in `pkg/test/util/` for real Slack API testing
- Test naming convention: `TestUnit*` for unit, `TestIntegration*` for integration
- Run specific test: `go test -run "TestUnit.*ConversationHistory" ./...`

## Performance Considerations

- Rate limiting: `pkg/limiter/limits.go` controls API call frequency
- Caching: User and channel caches loaded on startup significantly improve performance
- Pagination: Always use pagination for large result sets
- Time-based limits (e.g., `1d`) may be more efficient than count-based for large channels

## Common Development Tasks

### Adding a New Tool

1. Define tool schema in `pkg/server/server.go` using `mcp.NewTool()`
2. Implement handler method in `pkg/handler/conversations.go` or `pkg/handler/channels.go`
3. Handler should parse parameters, call provider methods, format results
4. Add tests following existing test patterns

### Debugging Tools

```bash
# Inspect the server with MCP Inspector
npx @modelcontextprotocol/inspector go run mcp/mcp-server.go --transport stdio

# View recent logs
tail -n 20 -f ~/Library/Logs/Claude/mcp*.log

# Test with specific environment
SLACK_MCP_LOG_LEVEL=debug SLACK_MCP_XOXP_TOKEN=... go run ./cmd/slack-mcp-server
```

### Working with Caches

- Delete cache files to force refresh: `rm .users_cache.json .channels_cache_v2.json`
- Caches are JSON files, can be inspected directly
- Server starts working before caches are ready (read-only mode)
- Cache paths are configurable via environment variables
