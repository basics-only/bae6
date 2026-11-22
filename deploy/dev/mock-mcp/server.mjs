// Development-only MCP server over streamable HTTP. It has one tool, `echo`, and no authentication.
import { createServer } from "node:http";

if (process.env.NODE_ENV === "production")
  throw new Error("mock-mcp must not run in production");

async function body(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 65536) throw new Error("too large");
  }
  return JSON.parse(raw || "{}");
}

createServer(async (req, res) => {
  const send = (status, value) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(value === undefined ? "" : JSON.stringify(value));
  };
  if (req.method === "GET" && req.url === "/health/live")
    return send(200, { status: "ok" });
  if (req.method !== "POST" || req.url !== "/mcp") return send(404, {});
  try {
    const { id, method, params } = await body(req);
    if (method === "notifications/initialized") return send(202);
    const result =
      method === "initialize"
        ? {
            protocolVersion: params.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "mock-mcp", version: "0.0.0" },
          }
        : method === "tools/call" && params.name === "echo"
          ? {
              content: [
                {
                  type: "text",
                  text: `echo: ${JSON.stringify(params.arguments)}`,
                },
              ],
            }
          : undefined;
    if (result === undefined)
      return send(200, {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: "unknown" },
      });
    send(200, { jsonrpc: "2.0", id, result });
  } catch {
    send(400, {});
  }
}).listen(Number(process.env.PORT ?? 8080), "0.0.0.0");
