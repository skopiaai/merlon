# Merlon as an MCP server

Merlon speaks the [Model Context Protocol](https://modelcontextprotocol.io), so
any MCP client — Claude Code, Cursor, or your own agent — can run scans, read
findings and enumerate engines by calling tools instead of driving the UI.

This is the same engine that runs behind the web interface. There is no API key,
no cloud call, and nothing leaves the machine: the server runs locally over
stdio and talks only to your local database and the scanners in the image.

> Merlon already *detects* exposed MCP servers on a target (see the `mcpsec`
> engine). This is the other side of that: a deliberate, authenticated one you
> run yourself.

## Run it

```bash
# inside the backend container (or any environment with the app importable)
python -m app.mcp_server
```

It reads newline-delimited JSON-RPC 2.0 on stdin and writes responses to
stdout — the stdio transport MCP clients expect. Nothing is printed except
protocol messages.

## Wire it into Claude Code

Add it to your MCP client configuration. For a containerised install:

```json
{
  "mcpServers": {
    "merlon": {
      "command": "docker",
      "args": ["compose", "exec", "-T", "backend", "python", "-m", "app.mcp_server"]
    }
  }
}
```

Running the backend outside Docker, point `command` at the interpreter that has
the app on its path instead.

## Tools

| Tool | What it does |
| --- | --- |
| `list_engines` | Every detection engine with its description, phase and depth profiles. |
| `list_scan_profiles` | The depth profiles and which engines each runs. |
| `start_scan` | Start a scan against a target. **Requires `authorized: true`.** Returns a scan id. |
| `list_scans` | Recent scans with state and progress. |
| `get_scan` | One scan's state, progress and statistics. |
| `get_findings` | Findings for a scan, most severe first, filterable by severity. |

## The authorization gate is not optional

`start_scan` refuses unless the call passes `authorized: true`, exactly as the
web quick-scan does. This is deliberate and it lives in the tool, not in a
prompt: an agent cannot rephrase its way past it, and a scan is never launched
without the affirmation that protects the operator. The derived scope goes
through the same engagement machinery as every other entry point, so it cannot
widen past the target.

Every other tool only reads. Together that means you can hand this server to an
autonomous agent and the worst it can do without an explicit authorization flag
is read your own scan history.

## Example session

```jsonc
// → initialize
{"jsonrpc":"2.0","id":1,"method":"initialize"}
// ← {"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"merlon",…}}}

// → run a scan you are allowed to run
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
  "name":"start_scan",
  "arguments":{"target":"example.com","authorized":true,"depth":"standard"}}}
// ← {"result":{"content":[{"type":"text","text":"{ \"scan_id\": 7, … }"}]}}

// → read what it found
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
  "name":"get_findings","arguments":{"scan_id":7,"severity":"critical,high"}}}
```
