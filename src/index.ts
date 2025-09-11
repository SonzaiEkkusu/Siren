// Cloudflare Workers (Modules) + nodejs_compat
import { connect as tlsConnect, TLSSocket } from "node:tls";

const SNI_HOST = "myip.ipeek.workers.dev";
const REQ_BODY =
  `GET / HTTP/1.1\r\n` +
  `Host: ${SNI_HOST}\r\n` +
  `User-Agent: ProxyScanner/1.0\r\n` +
  `Connection: close\r\n\r\n`;

function parseTarget(pathname: string): { ip: string; port: number } {
  // expects /149.129.250.8:443
  const target = pathname.replace(/^\/+/, "");
  if (!/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(target)) {
    throw new Error("bad target format; use /IP:PORT");
  }
  const [ip, portStr] = target.split(":");
  const port = parseInt(portStr, 10);
  // very light IPv4 octet validation:
  const ok = ip.split(".").every((x) => Number(x) >= 0 && Number(x) <= 255);
  if (!ok || port < 1 || port > 65535) throw new Error("invalid IP or port");
  return { ip, port };
}

async function probe(ip: string, port: number, timeoutMs = 5000) {
  return await new Promise<{ statusLine: string; headers: Record<string, string>; body: string }>((resolve, reject) => {
    const sock: TLSSocket = tlsConnect(
      {
        host: ip,       // connect to this IP
        port,           // and this port
        servername: SNI_HOST, // <-- set SNI to myip.ipeek.workers.dev
        rejectUnauthorized: false, // like curl -k
        ALPNProtocols: ["http/1.1"], // force H1 (scanner kamu pakai HTTP/1.1)
      },
      () => {
        sock.write(REQ_BODY);
      }
    );

    let raw = "";
    const t = setTimeout(() => {
      sock.destroy();
      reject(new Error("socket timeout"));
    }, timeoutMs);

    sock.on("data", (d) => (raw += d.toString()));
    sock.on("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
    sock.on("end", () => {
      clearTimeout(t);
      const [head = "", body = ""] = raw.split("\r\n\r\n");
      const [statusLine = "", ...headerLines] = head.split("\r\n");
      const headers: Record<string, string> = {};
      for (const line of headerLines) {
        const i = line.indexOf(":");
        if (i > -1) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      resolve({ statusLine, headers, body });
    });
  });
}

export default {
  async fetch(req: Request): Promise<Response> {
    try {
      const url = new URL(req.url);
      if (url.pathname === "/") {
        return new Response("Usage: /<IP>:<PORT>  e.g. /149.129.250.8:443\n", { status: 200 });
      }

      const { ip, port } = parseTarget(url.pathname);
      const raw = await probe(ip, port);

      // coba parse body sebagai JSON (kalau sukses, balikin ringkas)
      try {
        const json = JSON.parse(raw.body);
        const out = {
          ok: true,
          target: `${ip}:${port}`,
          result: json,
        };
        return Response.json(out, { status: 200 });
      } catch {
        // kalau bukan JSON dari worker tujuan, balikin raw biar kelihatan
        return new Response(
          JSON.stringify(
            { ok: false, target: `${ip}:${port}`, statusLine: raw.statusLine, headers: raw.headers, body: raw.body.slice(0, 2000) },
            null,
            2
          ),
          { status: 502, headers: { "content-type": "application/json" } }
        );
      }
    } catch (e: any) {
      return new Response(JSON.stringify({ ok: false, error: e?.message || String(e) }, null, 2), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
  },
} satisfies ExportedHandler;
