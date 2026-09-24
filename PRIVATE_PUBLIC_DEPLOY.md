# Private MyHosting Panel -> Public Project Deploy

This build keeps the MyHosting control panel private on the local machine and exposes only the selected project through a Cloudflare Quick Tunnel.

## What it does

- MyHosting Panel stays on `http://localhost:5000`.
- Static websites get a local loopback origin automatically.
- Node/Proxy websites are exposed through their configured local port.
- Clicking **Deploy Public** starts a Cloudflare Quick Tunnel and shows the public URL in **Websites**.
- Clicking **Unpublish** stops the public tunnel.
- Public deployment state is restored after the panel restarts when possible.

## Required

Install `cloudflared` on the same PC/server as MyHosting Panel and make sure `cloudflared --version` works in a terminal.

If `cloudflared` is not on PATH, set this in `.env`:

```env
CLOUDFLARED_BIN=C:\\cloudflared\\cloudflared.exe
PUBLIC_DEPLOYMENTS=true
PUBLIC_SITE_PORT_START=31000
```

## Deploy

1. Start MyHosting Panel.
2. Login to the private panel.
3. Open **Websites**.
4. Create the project/site.
   - For a static site, use any valid placeholder domain such as `myapp.local`; no real domain/DNS is needed for the Quick Tunnel URL.
   - For a Node/Proxy site, enter the local application port.
5. Click **Deploy Public**.
6. The panel will show a `https://....trycloudflare.com` URL once Cloudflare returns it.

## Important

Cloudflare Quick Tunnels are free and do not require a domain or Cloudflare account, but Cloudflare documents them as testing/development only. The URL is random and can change after the tunnel restarts. They also have a 200 in-flight request limit and do not support Server-Sent Events (SSE).

For stable production hosting later, switch the same project deployment mechanism to a remotely managed Cloudflare Tunnel with a domain, or move the panel/projects to a VPS.
