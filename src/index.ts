// Cloudflare Workers - SNI probe via cloudflare:sockets
// No nodejs_compat, no node:tls

const SNI_HOST = "myip.ipeek.workers.dev";

function parseTarget(pathname: string): { ip: string; port: number } {
  const target = pathname.replace(/^\/+/, ""); // "149.129.250.8:443"
  if (!/^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(target)) {
    throw new Error("bad target format; use /IP:PORT");
  }
  const [ip, portStr] = target.split(":");
  const port = parseInt(portStr, 10);
  const okIP = ip.split(".").every((x) => {
    const n = Number(x);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
  if (!okIP || port < 1 || port > 65535) throw new Error("invalid IP or port");
  return { ip, port };
}

async function probe(ip: string, port: number, timeoutMs = 5000) {
  // 1) buka TCP dulu
  // @ts-ignore - cloudflare runtime
  const tcpSocket = (await import("cloudflare:sockets")).connect({ hostname: ip, port });

  // 2) upgrade ke TLS dengan SNI = myip.ipeek.workers.dev, paksa HTTP/1.1
  const tlsSocket = await tcpSocket.startTls({
    servername: SNI_HOST,
    alpnProtocols: ["http/1.1"],
  });

  // 3) kirim HTTP/1.1 GET / dengan Host header = SNI
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const request =
    `GET / HTTP/1.1\r\n` +
    `Host: ${SNI_HOST}\r\n` +
    `User-Agent: SNI-Probe/1.0\r\n` +
    `Connection: close\r\n\r\n`;

  const writer = tlsSocket.writable.getWriter();
  await writer.write(encoder.encode(request));
  await writer.close(); // biar remote segera kirim respon dan tutup

  // 4) baca semua data sampai socket close / timeout
  const reader = tlsSocket.readable.getReader();
  let raw = "";
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try { reader.releaseLock(); } catch {}
    try { tlsSocket.close(); } catch {}
  }, timeoutMs);

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) raw += decoder.decode(value, { stream: true });
      if (timedOut) throw new Error("socket timeout");
    }
  } finally {
    clearTimeout(timer);
    try { reader.releaseLock(); } catch {}
    try { tlsSocket.close(); } catch {}
  }

  // 5) pisahkan header & body
  const [head = "", body = ""] = raw.split("\r\n\r\n");
  const [statusLine = "", ...headerLines] = head.split("\r\n");
  const headers: Record<string, string> = {};
  for (const line of headerLines) {
    const i = line.indexOf(":");
    if (i > -1) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return { statusLine, headers, body };
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

      // Coba parse body sebagai JSON (target sukses = balas JSON myip worker)
      try {
        const json = JSON.parse(raw.body);
        return Response.json({ ok: true, target: `${ip}:${port}`, result: json });
      } catch {
        // bukan JSON → kirim raw untuk diagnosa
        return new Response(
          JSON.stringify(
            {
              ok: false,
              target: `${ip}:${port}`,
              statusLine: raw.statusLine,
              headers: raw.headers,
              body: raw.body.slice(0, 2000),
            },
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
