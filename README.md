# MyHosting Panel v3 - Full Single File

This is the corrected full single-file build. `server.js` contains the panel UI and backend routes.

## Windows/local

1. Extract the ZIP.
2. Open the folder in PowerShell.
3. Copy `.env.example` to `.env`.
4. Set `ADMIN_PASSWORD` and `JWT_SECRET`.
5. Run:

```powershell
npm install
npm start
```

Open `http://localhost:5000`.

## Included

- Login + persistent password hash
- Forgot password/reset flow
- Terms & Conditions
- Website/domain manager
- Local Preview so `test.local` does not need Windows DNS
- File manager: upload, download, edit, create file/folder, delete
- Node.js app manager: create, start, stop, restart, logs
- Database manager: MySQL/MariaDB, PostgreSQL, MongoDB, Redis, SQLite
- Real database connection tests
- Cron manager
- Nginx vhost generation on Linux
- Certbot SSL command on Linux
- System information
- Health endpoint
- Audit log

## Real public hosting

For customer domains, use a Linux VPS with root/sudo access. Point DNS A/AAAA records to the VPS, configure Nginx and HTTPS, and harden the server.

Creating `example.com` in the panel does not magically register the domain or change public DNS.

## Render

The panel can run as a Render Web Service, but this VPS-style file/Nginx architecture does not automatically become a multi-customer Render hosting platform. For Render-native customer deployments, the provisioning layer must use the Render API to create/manage separate services and custom domains.

## Production hardening

Before selling public hosting, add per-customer OS isolation, quotas, resource limits, backups, malware/abuse controls, rate limiting, CSRF protection, 2FA, encrypted secrets, DNS automation, billing and monitoring.
