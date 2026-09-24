/*
  MyHosting Panel — REAL SINGLE-FILE VPS HOSTING PANEL (v2 — fixed)
  Linux VPS + Node.js 18+.

  Install:
    npm init -y
    npm i express bcryptjs cookie-parser jsonwebtoken multer dotenv
    npm i nodemailer mysql2 pg mongodb ioredis better-sqlite3

  Run: node server.js
*/

require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execFile, spawn } = require("child_process");

const app = express();

app.use(express.urlencoded({ extended: true, limit: "20mb" }));
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 5000);

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || "admin@example.com"
).trim().toLowerCase();

const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_LONG_SECRET";

const HOSTING_ROOT = path.resolve(
  process.env.HOSTING_ROOT || path.join(process.cwd(), "hosting")
);

const DATA_ROOT = path.resolve(
  process.env.DATA_ROOT || path.join(process.cwd(), "panel-data")
);

const PANEL_PUBLIC_URL = String(
  process.env.PANEL_PUBLIC_URL || `http://localhost:${PORT}`
).replace(/\/$/, "");

const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

const NGINX_AVAILABLE =
  process.env.NGINX_SITES_AVAILABLE || "/etc/nginx/sites-available";
const NGINX_ENABLED =
  process.env.NGINX_SITES_ENABLED || "/etc/nginx/sites-enabled";
const CERTBOT_EMAIL = process.env.CERTBOT_EMAIL || "";

const SITES_FILE = path.join(DATA_ROOT, "sites.json");
const APPS_FILE = path.join(DATA_ROOT, "apps.json");
const CRON_FILE = path.join(DATA_ROOT, "cron.json");
const DBS_FILE = path.join(DATA_ROOT, "databases.json");
const RESET_FILE = path.join(DATA_ROOT, "reset-tokens.json");
const AUDIT_FILE = path.join(DATA_ROOT, "audit.log");
const ADMIN_HASH_FILE = path.join(DATA_ROOT, "admin-password.hash");
const SECRET_FILE = path.join(DATA_ROOT, ".secret");
const UPLOAD_DIR = path.join(DATA_ROOT, "uploads");
const APP_LOG_DIR = path.join(DATA_ROOT, "app-logs");
const CLOUDFLARED_PATH =
  process.env.CLOUDFLARED_PATH || "cloudflared";

const tunnelProcesses = new Map();
const tunnelUrls = new Map();

function startCloudflareTunnel(appInfo) {
  return new Promise((resolve, reject) => {
    if (tunnelProcesses.has(appInfo.name)) {
      return resolve(tunnelUrls.get(appInfo.name) || "");
    }

    const child = spawn(
      CLOUDFLARED_PATH,
      [
        "tunnel",
        "--protocol",
        "http2",
        "--url",
        `http://127.0.0.1:${appInfo.port}`
      ],
      {
        cwd: process.cwd(),
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      }
    );

    tunnelProcesses.set(appInfo.name, child);

    let output = "";
    let resolved = false;

    const checkUrl = (data) => {
      output += String(data);

      const match = output.match(
        /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i
      );

      if (match && !resolved) {
        resolved = true;

        const url = match[0];
        tunnelUrls.set(appInfo.name, url);

        resolve(url);
      }
    };

    child.stdout.on("data", checkUrl);
    child.stderr.on("data", checkUrl);

    child.on("error", (err) => {
      tunnelProcesses.delete(appInfo.name);
      tunnelUrls.delete(appInfo.name);

      if (!resolved) reject(err);
    });

    child.on("exit", () => {
      tunnelProcesses.delete(appInfo.name);
      tunnelUrls.delete(appInfo.name);
    });

    setTimeout(() => {
      if (!resolved) {
        reject(
          new Error("Cloudflare tunnel URL was not detected.")
        );
      }
    }, 30000);
  });
}

function stopCloudflareTunnel(name) {
  const child = tunnelProcesses.get(name);

  if (!child) return;

  try {
    child.kill();
  } catch {}

  tunnelProcesses.delete(name);
  tunnelUrls.delete(name);
}

for (const d of [DATA_ROOT, HOSTING_ROOT, UPLOAD_DIR, APP_LOG_DIR]) {
  fs.mkdirSync(d, { recursive: true });
}

for (const [file, initial] of [
  [SITES_FILE, "[]"],
  [APPS_FILE, "[]"],
  [CRON_FILE, "[]"],
  [DBS_FILE, "[]"],
  [RESET_FILE, "{}"]
]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, initial);
}

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 250 * 1024 * 1024 }
});

/* =========================================================
   HELPERS
========================================================= */

function readJson(file, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}

function audit(req, action, detail = "") {
  const email = req.user?.email || "-";
  const clean = String(detail).replace(/[\r\n]/g, " ");
  fs.appendFileSync(
    AUDIT_FILE,
    `${new Date().toISOString()} ${email} ${action} ${clean}\n`
  );
}

function esc(value = "") {
  return String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      })[c]
  );
}

function safeName(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "-")
    .replace(/^\.+/, "")
    .slice(0, 180);
}

function validDomain(domain) {
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(
    domain
  );
}

function siteRoot(domain) {
  return path.join(HOSTING_ROOT, safeName(domain));
}

function safeJoin(root, relative = "") {
  const base = path.resolve(root);
  const rel = String(relative || "").replace(/\\/g, "/");
  const target = path.resolve(base, rel);
  if (target !== base && !target.startsWith(base + path.sep)) {
    throw new Error("Invalid path");
  }
  return target;
}

function commandExists(command) {
  return new Promise((resolve) => {
    execFile(
      "sh",
      ["-lc", `command -v ${command}`],
      { timeout: 5000 },
      (err) => resolve(!err)
    );
  });
}

function run(command, args = [], timeout = 120000) {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      { timeout, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          return reject(new Error((stderr || err.message || "").trim()));
        }
        resolve(String(stdout || "").trim());
      }
    );
  });
}

function linux() {
  return process.platform === "linux";
}

/* =========================================================
   ENCRYPTION
========================================================= */

function getPanelSecret() {
  if (fs.existsSync(SECRET_FILE)) {
    return fs.readFileSync(SECRET_FILE, "utf8").trim();
  }
  const s = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 });
  return s;
}

const PANEL_SECRET = getPanelSecret();

function encrypt(text) {
  if (!text) return "";
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(PANEL_SECRET, "hex"),
    iv
  );
  const enc = Buffer.concat([
    cipher.update(String(text), "utf8"),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${tag.toString("hex")}:${enc.toString("hex")}`;
}

function decrypt(payload) {
  if (!payload) return "";
  try {
    const [ivH, tagH, dataH] = String(payload).split(":");
    if (!ivH || !tagH || !dataH) return payload;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      Buffer.from(PANEL_SECRET, "hex"),
      Buffer.from(ivH, "hex")
    );
    decipher.setAuthTag(Buffer.from(tagH, "hex"));
    const dec = Buffer.concat([
      decipher.update(Buffer.from(dataH, "hex")),
      decipher.final()
    ]);
    return dec.toString("utf8");
  } catch {
    return "";
  }
}

/* =========================================================
   ADMIN PASSWORD
========================================================= */

function getAdminPasswordHash() {
  if (fs.existsSync(ADMIN_HASH_FILE)) {
    const hash = fs.readFileSync(ADMIN_HASH_FILE, "utf8").trim();
    if (hash) return hash;
  }
  const hash = bcrypt.hashSync(DEFAULT_ADMIN_PASSWORD, 12);
  fs.writeFileSync(ADMIN_HASH_FILE, hash, { mode: 0o600 });
  return hash;
}

let adminPasswordHash = getAdminPasswordHash();

async function checkLogin(email, password) {
  if (String(email || "").trim().toLowerCase() !== ADMIN_EMAIL) return false;
  return bcrypt.compare(String(password || ""), adminPasswordHash);
}

async function setAdminPassword(password) {
  adminPasswordHash = await bcrypt.hash(password, 12);
  fs.writeFileSync(ADMIN_HASH_FILE, adminPasswordHash, { mode: 0o600 });
}

/* =========================================================
   AUTH
========================================================= */

function makeToken(email) {
  return jwt.sign({ email, role: "admin" }, JWT_SECRET, {
    expiresIn: "12h"
  });
}

function auth(req, res, next) {
  try {
    req.user = jwt.verify(req.cookies.panel_token || "", JWT_SECRET);
    if (req.user.role !== "admin" || req.user.email !== ADMIN_EMAIL) {
      throw new Error("Invalid role");
    }
    next();
  } catch {
    res.redirect("/login");
  }
}

function csrfGuard(req, res, next) {
  // GET/HEAD/OPTIONS requests ko CSRF check ki zarurat nahi
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const origin = req.get("origin");
  const referer = req.get("referer");

  const configuredOrigin = new URL(PANEL_PUBLIC_URL).origin;
  const requestOrigin = `${req.protocol}://${req.get("host")}`;

  const localOrigins = new Set([
    configuredOrigin,
    requestOrigin,
    `http://localhost:${PORT}`,
    `http://127.0.0.1:${PORT}`
  ]);

  if (origin && !localOrigins.has(origin)) {
    return res.status(403).send("CSRF blocked");
  }

  if (!origin && referer) {
    try {
      if (!localOrigins.has(new URL(referer).origin)) {
        return res.status(403).send("CSRF blocked");
      }
    } catch {
      return res.status(403).send("CSRF blocked");
    }
  }

  next();
}

app.use((req, res, next) => {
  if (req.method === "POST" && req.path !== "/login") {
    return csrfGuard(req, res, next);
  }
  next();
});

/* =========================================================
   RESET TOKENS
========================================================= */

function loadResetTokens() {
  return readJson(RESET_FILE, {});
}
function saveResetTokens(map) {
  writeJson(RESET_FILE, map);
}
function pruneExpiredTokens() {
  const tokens = loadResetTokens();
  const now = Date.now();
  let changed = false;
  for (const [k, v] of Object.entries(tokens)) {
    if (v.expires < now) {
      delete tokens[k];
      changed = true;
    }
  }
  if (changed) saveResetTokens(tokens);
}

async function sendReset(email, link) {
  if (process.env.SMTP_HOST) {
    try {
      const nodemailer = require("nodemailer");
      const port = Number(process.env.SMTP_PORT || 587);
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port,
        secure: port === 465,
        auth: process.env.SMTP_USER
          ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
          : undefined
      });
      await transporter.sendMail({
        from: process.env.SMTP_FROM || ADMIN_EMAIL,
        to: email,
        subject: "MyHosting password reset",
        text: `Reset your password: ${link}`
      });
      return "sent";
    } catch (e) {
      console.error("SMTP error:", e.message);
    }
  }
  console.log(`PASSWORD RESET FOR ${email}: ${link}`);
  return "terminal";
}

/* =========================================================
   UI
========================================================= */

const CSS = `
*{box-sizing:border-box}
body{margin:0;font-family:Inter,Arial,sans-serif;background:#0b1220;color:#e5e7eb}
.wrap{max-width:1250px;margin:auto;padding:24px}
.nav{display:flex;justify-content:space-between;align-items:center;gap:20px;background:#111827;padding:14px 18px;border-radius:14px;margin-bottom:20px;flex-wrap:wrap}
.nav a{color:#cbd5e1;text-decoration:none;margin-left:14px}
.brand{font-weight:800;color:#38bdf8;font-size:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.card{background:#111827;border:1px solid #243244;border-radius:14px;padding:18px;margin-bottom:16px}
.btn{display:inline-block;background:#38bdf8;color:#06283d;border:0;border-radius:9px;padding:10px 14px;text-decoration:none;font-weight:700;cursor:pointer}
.btn.red{background:#fb7185}
.btn.gray{background:#334155;color:#fff}
.btn.green{background:#4ade80;color:#052e16}
.input,textarea,select{width:100%;background:#0f172a;color:#fff;border:1px solid #334155;border-radius:8px;padding:11px;margin:6px 0 12px}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:10px;border-bottom:1px solid #263244;text-align:left;vertical-align:top}
.muted{color:#94a3b8}
.err{color:#fda4af}
.ok{color:#86efac}
.small{font-size:12px}
.path{word-break:break-all}
pre{white-space:pre-wrap;background:#020617;padding:12px;border-radius:8px;overflow:auto}
code{color:#93c5fd}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;padding:4px 8px;border-radius:99px;background:#334155;font-size:12px}
`;

function layout(title, body, user = true) {
  return `<!doctype html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} - MyHosting</title>
<style>${CSS}</style>
</head><body>
<div class="wrap">
${
  user
    ? `<div class="nav">
<div class="brand">MyHosting</div>
<div>
<a href="/">Dashboard</a>
<a href="/sites">Websites</a>
<a href="/apps">Node Apps</a>
<a href="/databases">Databases</a>
<a href="/cron">Cron</a>
<a href="/ssl">SSL</a>
<a href="/system">System</a>
<a href="/audit">Audit</a>
<a href="/terms">Terms</a>
<a href="/logout">Logout</a>
</div>
</div>`
    : ""
}
${body}
</div></body></html>`;
}

function errorPage(title, message) {
  return layout(
    title,
    `<div class="card">
<p class="err">${esc(message)}</p>
<a class="btn gray" href="javascript:history.back()">Back</a>
</div>`
  );
}

/* =========================================================
   LOGIN
========================================================= */

app.get("/login", (req, res) =>
  res.send(
    layout(
      "Login",
      `<div style="max-width:440px;margin:80px auto">
<div class="card">
<h1>MyHosting</h1>
<p class="muted">VPS hosting control panel</p>
<form method="post" action="/login">
<label>Email</label>
<input class="input" name="email" type="email" required>
<label>Password</label>
<input class="input" name="password" type="password" required>
<label><input type="checkbox" name="remember"> Remember me for 30 days</label>
<br>
<label><input type="checkbox" name="terms" required> I agree to <a href="/terms">Terms & Conditions</a></label>
<br><br>
<button class="btn">Sign in</button>
</form>
<p><a href="/forgot-password">Forgot password?</a></p>
</div>
</div>`,
      false
    )
  )
);

app.post("/login", async (req, res) => {
  if (req.body.terms !== "on") {
    return res
      .status(400)
      .send(errorPage("Login", "You must accept Terms & Conditions."));
  }
  const ok = await checkLogin(req.body.email, req.body.password);
  if (!ok) {
    return res.status(401).send(errorPage("Login failed", "Invalid credentials."));
  }
  const remember = req.body.remember === "on";
  const maxAge = remember ? 30 * 24 * 60 * 60 * 1000 : 12 * 60 * 60 * 1000;
  res.cookie("panel_token", makeToken(ADMIN_EMAIL), {
    httpOnly: true,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    maxAge
  });
  audit(req, "LOGIN");
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.clearCookie("panel_token");
  res.redirect("/login");
});

/* =========================================================
   FORGOT / RESET
========================================================= */

app.get("/forgot-password", (req, res) =>
  res.send(
    layout(
      "Forgot password",
      `<div style="max-width:520px;margin:60px auto">
<div class="card">
<h2>Forgot Password</h2>
<p class="muted">Enter your admin email.</p>
<form method="post">
<input class="input" name="email" type="email" required>
<button class="btn">Send reset link</button>
</form>
</div>
</div>`,
      false
    )
  )
);

app.post("/forgot-password", async (req, res) => {
  pruneExpiredTokens();

  if (String(req.body.email || "").trim().toLowerCase() !== ADMIN_EMAIL) {
    return res.send(
      layout(
        "Reset",
        `<div class="card">
<p>If the account exists, reset instructions were sent.</p>
<a href="/login">Back to login</a>
</div>`,
        false
      )
    );
  }

  const t = crypto.randomBytes(32).toString("hex");
  const tokens = loadResetTokens();
  tokens[t] = { email: ADMIN_EMAIL, expires: Date.now() + 15 * 60 * 1000 };
  saveResetTokens(tokens);

  const link = `${PANEL_PUBLIC_URL}/reset-password?token=${encodeURIComponent(t)}`;
  const mode = await sendReset(ADMIN_EMAIL, link);

  res.send(
    layout(
      "Reset",
      `<div class="card">
<h2>Reset link generated</h2>
<p>${
        mode === "sent"
          ? "Check your email."
          : "SMTP is not configured; use the link printed in the Node.js terminal."
      }</p>
${mode === "terminal" ? `<pre>${esc(link)}</pre>` : ""}
<a href="/login">Back to login</a>
</div>`,
      false
    )
  );
});

app.get("/reset-password", (req, res) =>
  res.send(
    layout(
      "Reset password",
      `<div style="max-width:520px;margin:60px auto">
<div class="card">
<h2>Set new password</h2>
<form method="post">
<input type="hidden" name="token" value="${esc(req.query.token || "")}">
<input class="input" name="password" type="password" minlength="10" required placeholder="New password">
<input class="input" name="confirm" type="password" minlength="10" required placeholder="Confirm password">
<button class="btn">Update password</button>
</form>
</div>
</div>`,
      false
    )
  )
);

app.post("/reset-password", async (req, res) => {
  pruneExpiredTokens();
  const tokens = loadResetTokens();
  const x = tokens[req.body.token];

  if (!x || x.expires < Date.now()) {
    return res
      .status(400)
      .send(errorPage("Reset expired", "Reset link expired or invalid."));
  }
  if (req.body.password !== req.body.confirm) {
    return res.status(400).send(errorPage("Reset", "Passwords do not match."));
  }
  if (String(req.body.password).length < 10) {
    return res
      .status(400)
      .send(errorPage("Reset", "Use at least 10 characters."));
  }

  await setAdminPassword(req.body.password);
  delete tokens[req.body.token];
  saveResetTokens(tokens);

  res.send(
    layout(
      "Reset complete",
      `<div class="card">
<p class="ok">Password updated and saved persistently.</p>
<a class="btn" href="/login">Login</a>
</div>`,
      false
    )
  );
});

/* =========================================================
   TERMS
========================================================= */

app.get("/terms", (req, res) =>
  res.send(
    layout(
      "Terms",
      `<div class="card">
<h1>Terms & Conditions</h1>
<p>Customers must use hosted services lawfully and must not abuse, attack, spam, distribute malware, or violate third-party rights.</p>
<h2>Acceptable Use</h2>
<p>No illegal content, phishing, malware, credential theft, attacks, or unauthorized access.</p>
<h2>Availability</h2>
<p>Availability depends on the VPS, network, DNS, software, and maintenance.</p>
<h2>Backups</h2>
<p>Customers are responsible for appropriate backups unless a separate backup service is explicitly provided.</p>
<h2>Contact</h2>
<p>Replace this text with your legal/business contact details before public launch.</p>
</div>`
    )
  )
);

/* =========================================================
   DASHBOARD
========================================================= */

app.get("/", auth, (req, res) => {
  const sites = readJson(SITES_FILE);
  const apps = readJson(APPS_FILE);
  const crons = readJson(CRON_FILE);
  const dbs = readJson(DBS_FILE);

  res.send(
    layout(
      "Dashboard",
      `<h1>Dashboard</h1>
<p class="muted">MyHosting VPS operations panel</p>
<div class="grid">
<div class="card"><h3>Websites</h3><h2>${sites.length}</h2></div>
<div class="card"><h3>Node Apps</h3><h2>${apps.length}</h2></div>
<div class="card"><h3>Databases</h3><h2>${dbs.length}</h2></div>
<div class="card"><h3>Cron Jobs</h3><h2>${crons.length}</h2></div>
<div class="card"><h3>Server</h3><h2>${esc(os.hostname())}</h2></div>
</div>
<div class="card">
<h2>Quick actions</h2>
<div class="actions">
<a class="btn" href="/sites/new">Create Website</a>
<a class="btn gray" href="/apps/new">Create Node App</a>
<a class="btn gray" href="/databases/new">Create Database</a>
<a class="btn gray" href="/cron">Cron Jobs</a>
<a class="btn gray" href="/system">System Status</a>
</div>
</div>`
    )
  );
});
/* =========================================================
   LOCAL PREVIEW
========================================================= */

app.get("/preview", auth, (req, res) => {
  const domain = String(req.query.site || "").trim();
  if (!domain) return res.status(400).send("Website not specified");

  const sites = readJson(SITES_FILE);
  const site = sites.find((s) => s.domain === domain);
  if (!site) return res.status(404).send("Website not found");

  const root = path.resolve(site.root);
  if (!fs.existsSync(root)) {
    return res.status(404).send("Website directory does not exist");
  }

  const indexFile = path.join(root, "index.html");
  if (fs.existsSync(indexFile)) return res.sendFile(indexFile);

  const adminFile = path.join(root, "admin.html");
  if (fs.existsSync(adminFile)) return res.sendFile(adminFile);

  return res.status(404).send(`
    <h2>No homepage found</h2>
    <p>Create <b>index.html</b> inside:</p>
    <code>${esc(root)}</code>
  `);
});

/* =========================================================
   WEBSITES
========================================================= */

app.get("/sites", auth, (req, res) => {
  const sites = readJson(SITES_FILE);

  const rows = sites
    .map(
      (site) => `
    <tr>
      <td>
        <strong>${esc(site.domain)}</strong><br>
        <span class="muted small">${esc(site.root)}</span>
      </td>
      <td>${
        site.enabled
          ? `<span class="badge">Enabled</span>`
          : `<span class="badge">Disabled</span>`
      }</td>
      <td>${esc(site.type || "static")}</td>
      <td>
        <div class="actions">
          <a class="btn gray" href="/files?site=${encodeURIComponent(
            site.domain
          )}">File Manager</a>
          <a class="btn gray" href="/preview?site=${encodeURIComponent(
            site.domain
          )}" target="_blank">Open</a>
          <form method="post" action="/sites/${encodeURIComponent(
            site.domain
          )}/toggle" style="display:inline">
            <button class="btn ${site.enabled ? "red" : "green"}">
              ${site.enabled ? "Disable" : "Enable"}
            </button>
          </form>
          <form method="post" action="/sites/${encodeURIComponent(
            site.domain
          )}/delete" style="display:inline" onsubmit="return confirm('Delete this website?')">
            <button class="btn red">Delete</button>
          </form>
        </div>
      </td>
    </tr>
  `
    )
    .join("");

  res.send(
    layout(
      "Websites",
      `
    <div class="actions" style="justify-content:space-between">
      <div>
        <h1>Websites</h1>
        <p class="muted">Manage domains and website files.</p>
      </div>
      <a class="btn" href="/sites/new">+ Create Website</a>
    </div>
    <div class="card">
      ${
        sites.length
          ? `<table class="table">
        <thead><tr><th>Domain</th><th>Status</th><th>Type</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`
          : `<p class="muted">No websites created yet.</p>`
      }
    </div>
    `
    )
  );
});

app.get("/sites/new", auth, (req, res) => {
  res.send(
    layout(
      "Create Website",
      `
    <h1>Create Website</h1>
    <div class="card">
      <form method="post" action="/sites">
        <label>Domain</label>
        <input class="input" name="domain" placeholder="example.com" required>
        <label>Website type</label>
        <select class="input" name="type">
          <option value="static">Static Website</option>
          <option value="node">Node.js Website</option>
          <option value="proxy">Reverse Proxy</option>
        </select>
        <label>Node/Proxy port (required for node/proxy)</label>
        <input class="input" name="port" type="number" placeholder="3000">
        <button class="btn">Create Website</button>
      </form>
    </div>
    `
    )
  );
});

function nginxStaticConfig(domain, root) {
  return `
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    root ${root};
    index index.html index.htm;
    access_log /var/log/nginx/${domain}.access.log;
    error_log /var/log/nginx/${domain}.error.log;
    location / { try_files $uri $uri/ /index.html; }
    location ~ /\\. { deny all; }
}
`;
}

function nginxProxyConfig(domain, port) {
  return `
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};
    access_log /var/log/nginx/${domain}.access.log;
    error_log /var/log/nginx/${domain}.error.log;
    location / {
        proxy_pass http://127.0.0.1:${Number(port)};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`;
}

async function configureNginx(domain, config) {
  if (!linux()) {
    return {
      ok: false,
      message: "Nginx configuration is available on Linux VPS only."
    };
  }
  await fsp.mkdir(NGINX_AVAILABLE, { recursive: true });
  await fsp.mkdir(NGINX_ENABLED, { recursive: true });

  const filename = safeName(domain);
  const available = path.join(NGINX_AVAILABLE, filename);
  const enabled = path.join(NGINX_ENABLED, filename);

  await fsp.writeFile(available, config);
  try {
    await fsp.unlink(enabled);
  } catch {}
  await fsp.symlink(available, enabled).catch(() => {});

  await run("nginx", ["-t"]);
  await run("systemctl", ["reload", "nginx"]);
  return { ok: true };
}

async function reloadNginx() {
  if (!linux()) return;
  try {
    await run("nginx", ["-t"]);
    await run("systemctl", ["reload", "nginx"]);
  } catch (e) {
    console.error("nginx reload failed:", e.message);
  }
}

app.post("/sites", auth, async (req, res) => {
  try {
    const domain = String(req.body.domain || "").trim().toLowerCase();
    const type = String(req.body.type || "static");
    const port = Number(req.body.port || 0);

    if (!validDomain(domain)) {
      return res
        .status(400)
        .send(
          errorPage(
            "Invalid domain",
            "Enter a valid domain such as example.com"
          )
        );
    }

    const sites = readJson(SITES_FILE);
    if (sites.some((x) => x.domain === domain)) {
      return res
        .status(400)
        .send(errorPage("Already exists", "This website already exists."));
    }

    if (
      (type === "proxy" || type === "node") &&
      (!port || port < 1 || port > 65535)
    ) {
      return res
        .status(400)
        .send(
          errorPage(
            "Port required",
            "Node/Proxy website requires a valid port (1-65535)."
          )
        );
    }

    const root = siteRoot(domain);
    await fsp.mkdir(root, { recursive: true });

    const index = path.join(root, "index.html");
    if (!fs.existsSync(index)) {
      await fsp.writeFile(
        index,
        `<!doctype html>
<html><head><meta charset="utf-8"><title>${esc(domain)}</title></head>
<body>
<h1>${esc(domain)}</h1>
<p>Website created successfully by MyHosting.</p>
</body></html>`
      );
    }

    const site = {
      id: crypto.randomUUID(),
      domain,
      root,
      type,
      port: port > 0 ? port : null,
      enabled: true,
      createdAt: new Date().toISOString()
    };

    sites.push(site);
    writeJson(SITES_FILE, sites);

    if (linux()) {
      if (type === "static") {
        await configureNginx(domain, nginxStaticConfig(domain, root));
      } else if (type === "proxy" || type === "node") {
        await configureNginx(domain, nginxProxyConfig(domain, port));
      }
    }

    audit(req, "CREATE_SITE", domain);
    res.redirect("/sites");
  } catch (e) {
    console.error(e);
    res.status(500).send(errorPage("Website error", e.message));
  }
});

app.post("/sites/:domain/toggle", auth, async (req, res) => {
  const domain = req.params.domain;
  const sites = readJson(SITES_FILE);
  const site = sites.find((x) => x.domain === domain);

  if (!site) {
    return res.status(404).send(errorPage("Not found", "Website not found."));
  }

  site.enabled = !site.enabled;
  writeJson(SITES_FILE, sites);

  if (linux()) {
    const filename = safeName(domain);
    const enabled = path.join(NGINX_ENABLED, filename);

    try {
      if (site.enabled) {
        const available = path.join(NGINX_AVAILABLE, filename);
        await fsp.symlink(available, enabled).catch(() => {});
      } else {
        await fsp.unlink(enabled).catch(() => {});
      }
      await reloadNginx();
    } catch (e) {
      console.error("nginx toggle:", e.message);
    }
  }

  audit(req, "TOGGLE_SITE", domain);
  res.redirect("/sites");
});

app.post("/sites/:domain/delete", auth, async (req, res) => {
  const domain = req.params.domain;
  const sites = readJson(SITES_FILE);
  const index = sites.findIndex((x) => x.domain === domain);

  if (index === -1) {
    return res.status(404).send(errorPage("Not found", "Website not found."));
  }

  const site = sites[index];
  sites.splice(index, 1);
  writeJson(SITES_FILE, sites);

  if (linux()) {
    const filename = safeName(domain);
    const available = path.join(NGINX_AVAILABLE, filename);
    const enabled = path.join(NGINX_ENABLED, filename);

    await fsp.unlink(enabled).catch(() => {});
    await fsp.unlink(available).catch(() => {});
    await reloadNginx();
  }

  audit(req, "DELETE_SITE", domain);

  try {
    await fsp.rm(site.root, { recursive: true, force: true });
  } catch {}

  res.redirect("/sites");
});

/* =========================================================
   FILE MANAGER
========================================================= */

function getSiteFromRequest(domain) {
  const sites = readJson(SITES_FILE);
  return sites.find((x) => x.domain === domain);
}

app.get("/files", auth, async (req, res) => {
  try {
    const domain = String(req.query.site || "").trim().toLowerCase();
    const site = getSiteFromRequest(domain);

    if (!site) {
      return res
        .status(404)
        .send(errorPage("Website not found", "Select a valid website."));
    }

    const rel = String(req.query.path || "");
    const current = safeJoin(site.root, rel);

    const entries = await fsp.readdir(current, { withFileTypes: true });

    entries.sort(
      (a, b) =>
        Number(b.isDirectory()) - Number(a.isDirectory()) ||
        a.name.localeCompare(b.name)
    );

    const rows = entries
      .map((entry) => {
        const entryRel = path
          .relative(site.root, path.join(current, entry.name))
          .replace(/\\/g, "/");

        const url = `/files?site=${encodeURIComponent(
          domain
        )}&path=${encodeURIComponent(entryRel)}`;

        return `
        <tr>
          <td>${entry.isDirectory() ? "📁" : "📄"} <a href="${url}">${esc(
          entry.name
        )}</a></td>
          <td>${entry.isDirectory() ? "Directory" : "File"}</td>
          <td>
            ${
              entry.isDirectory()
                ? ""
                : `
                <a class="btn gray" href="/files/download?site=${encodeURIComponent(
                  domain
                )}&path=${encodeURIComponent(entryRel)}">Download</a>
                <a class="btn gray" href="/files/edit?site=${encodeURIComponent(
                  domain
                )}&path=${encodeURIComponent(entryRel)}">Edit</a>
                `
            }
            <form method="post" action="/files/delete" style="display:inline" onsubmit="return confirm('Delete this item?')">
              <input type="hidden" name="site" value="${esc(domain)}">
              <input type="hidden" name="path" value="${esc(entryRel)}">
              <button class="btn red">Delete</button>
            </form>
          </td>
        </tr>
        `;
      })
      .join("");

    const parent = path
      .relative(site.root, path.dirname(current))
      .replace(/\\/g, "/");

    res.send(
      layout(
        "File Manager",
        `
      <div class="actions" style="justify-content:space-between">
        <div>
          <h1>File Manager</h1>
          <p class="muted">${esc(domain)}</p>
        </div>
        <a class="btn" href="/sites">Back</a>
      </div>
      <div class="card">
        <p class="path">Current: <code>/${esc(rel)}</code></p>
        <div class="actions">
          ${
            rel
              ? `<a class="btn gray" href="/files?site=${encodeURIComponent(
                  domain
                )}&path=${encodeURIComponent(parent)}">← Parent</a>`
              : ""
          }
          <form method="post" action="/files/mkdir">
            <input type="hidden" name="site" value="${esc(domain)}">
            <input type="hidden" name="path" value="${esc(rel)}">
            <input class="input" name="name" placeholder="New folder" required>
            <button class="btn">Create Folder</button>
          </form>
          <form method="post" action="/files/create">
            <input type="hidden" name="site" value="${esc(domain)}">
            <input type="hidden" name="path" value="${esc(rel)}">
            <input class="input" name="name" placeholder="new-file.html" required>
            <button class="btn gray">Create File</button>
          </form>
        </div>
      </div>
      <div class="card">
        <form method="post" action="/files/upload" enctype="multipart/form-data">
          <input type="hidden" name="site" value="${esc(domain)}">
          <input type="hidden" name="path" value="${esc(rel)}">
          <input type="file" name="file" required>
          <button class="btn">Upload</button>
        </form>
      </div>
      <div class="card">
        ${
          entries.length
            ? `<table class="table">
              <thead><tr><th>Name</th><th>Type</th><th>Actions</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>`
            : `<p class="muted">Empty directory.</p>`
        }
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("File Manager", e.message));
  }
});

app.post(
  "/files/upload",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) throw new Error("No file selected.");

      const site = getSiteFromRequest(req.body.site);
      if (!site) throw new Error("Website not found.");

      const targetDir = safeJoin(site.root, req.body.path || "");
      await fsp.mkdir(targetDir, { recursive: true });

      const filename = safeName(req.file.originalname);
      if (!filename) throw new Error("Invalid filename.");

      const target = path.join(targetDir, filename);
      await fsp.rename(req.file.path, target);

      audit(req, "UPLOAD_FILE", `${site.domain}/${filename}`);
      res.redirect(
        `/files?site=${encodeURIComponent(
          site.domain
        )}&path=${encodeURIComponent(req.body.path || "")}`
      );
    } catch (e) {
      if (req.file) await fsp.unlink(req.file.path).catch(() => {});
      res.status(400).send(errorPage("Upload failed", e.message));
    }
  }
);

app.post("/files/mkdir", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.body.site);
    if (!site) throw new Error("Website not found.");

    const name = safeName(req.body.name);
    if (!name) throw new Error("Invalid folder name.");

    const target = safeJoin(site.root, path.join(req.body.path || "", name));
    await fsp.mkdir(target, { recursive: false });

    audit(req, "CREATE_FOLDER", `${site.domain}/${name}`);
    res.redirect(
      `/files?site=${encodeURIComponent(
        site.domain
      )}&path=${encodeURIComponent(req.body.path || "")}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Folder error", e.message));
  }
});

app.post("/files/create", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.body.site);
    if (!site) throw new Error("Website not found.");

    const name = safeName(req.body.name);
    if (!name) throw new Error("Invalid file name.");

    const target = safeJoin(site.root, path.join(req.body.path || "", name));
    if (fs.existsSync(target)) throw new Error("File already exists.");

    await fsp.writeFile(target, "");
    audit(req, "CREATE_FILE", `${site.domain}/${name}`);
    res.redirect(
      `/files?site=${encodeURIComponent(
        site.domain
      )}&path=${encodeURIComponent(req.body.path || "")}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Create file", e.message));
  }
});

app.get("/files/download", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.query.site);
    if (!site) return res.status(404).send("Website not found");

    const file = safeJoin(site.root, req.query.path || "");
    const stat = await fsp.stat(file);
    if (!stat.isFile()) throw new Error("Not a file.");

    res.download(file, path.basename(file));
  } catch (e) {
    res.status(400).send(errorPage("Download", e.message));
  }
});

app.get("/files/edit", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.query.site);
    if (!site) throw new Error("Website not found.");

    const file = safeJoin(site.root, req.query.path || "");
    const stat = await fsp.stat(file);
    if (!stat.isFile()) throw new Error("Not a file.");

    const content = await fsp.readFile(file, "utf8");

    res.send(
      layout(
        "Edit File",
        `
        <h1>Edit File</h1>
        <div class="card">
          <p class="path">${esc(req.query.path || "")}</p>
          <form method="post" action="/files/edit">
            <input type="hidden" name="site" value="${esc(
              req.query.site || ""
            )}">
            <input type="hidden" name="path" value="${esc(
              req.query.path || ""
            )}">
            <textarea class="input" name="content" rows="28" style="font-family:monospace">${esc(
              content
            )}</textarea>
            <button class="btn">Save File</button>
          </form>
        </div>
        `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Edit", e.message));
  }
});

app.post("/files/edit", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.body.site);
    if (!site) throw new Error("Website not found.");

    const file = safeJoin(site.root, req.body.path || "");
    const stat = await fsp.stat(file);
    if (!stat.isFile()) throw new Error("Not a file.");

    await fsp.writeFile(file, String(req.body.content || ""), "utf8");
    audit(req, "EDIT_FILE", `${site.domain}/${req.body.path}`);

    res.redirect(
      `/files?site=${encodeURIComponent(
        site.domain
      )}&path=${encodeURIComponent(path.dirname(req.body.path || ""))}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Save failed", e.message));
  }
});

app.post("/files/delete", auth, async (req, res) => {
  try {
    const site = getSiteFromRequest(req.body.site);
    if (!site) throw new Error("Website not found.");

    const target = safeJoin(site.root, req.body.path || "");
    if (path.resolve(target) === path.resolve(site.root)) {
      throw new Error("Cannot delete website root.");
    }

    await fsp.rm(target, { recursive: true, force: true });
    audit(req, "DELETE_FILE", `${site.domain}/${req.body.path}`);

    res.redirect(
      `/files?site=${encodeURIComponent(
        site.domain
      )}&path=${encodeURIComponent(path.dirname(req.body.path || ""))}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Delete failed", e.message));
  }
});

/* =========================================================
   NODE.JS APP MANAGER
========================================================= */

function appByName(name) {
  const apps = readJson(APPS_FILE);
  return apps.find((x) => x.name === name);
}

function appLogPath(name) {
  return path.join(APP_LOG_DIR, `${safeName(name)}.log`);
}

const runningProcesses = new Map();

app.get("/apps", auth, (req, res) => {
  const apps = readJson(APPS_FILE);

  const rows = apps
    .map((a) => {
      const running = runningProcesses.has(a.name);
      return `
      <tr>
        <td><strong>${esc(a.name)}</strong></td>
        <td>${esc(a.entry)}</td>
        <td>${a.port}</td>
        <td>${
          running
            ? `<span class="badge">Running</span>`
            : `<span class="badge">Stopped</span>`
        }</td>
        <td>
          <div class="actions">
            <form method="post" action="/apps/${encodeURIComponent(
              a.name
            )}/start"><button class="btn green">Start</button></form>
            <form method="post" action="/apps/${encodeURIComponent(
              a.name
            )}/stop"><button class="btn red">Stop</button></form>
            <form method="post" action="/apps/${encodeURIComponent(
              a.name
            )}/restart"><button class="btn gray">Restart</button></form>
            <a class="btn gray" href="/apps/${encodeURIComponent(
              a.name
            )}/logs">Logs</a>
            <a class="btn gray" href="/apps/${encodeURIComponent(a.name)}/edit">Edit</a>
            ${
  tunnelUrls.has(a.name)
    ? `
      <a class="btn green"
         href="${tunnelUrls.get(a.name)}"
         target="_blank">
        🌐 Public
      </a>

      <form method="post"
            action="/apps/${encodeURIComponent(a.name)}/public-stop">
        <button class="btn red">Stop Public</button>
      </form>
    `
    : `
      <form method="post"
            action="/apps/${encodeURIComponent(a.name)}/public">
        <button class="btn green">🌐 Public</button>
      </form>
    `
}
            <form method="post" action="/apps/${encodeURIComponent(
              a.name
            )}/delete" onsubmit="return confirm('Delete app?')">
              <button class="btn red">Delete</button>
            </form>
          </div>
        </td>
      </tr>
      `;
    })
    .join("");

  res.send(
    layout(
      "Node Apps",
      `
    <div class="actions" style="justify-content:space-between">
      <div>
        <h1>Node.js Apps</h1>
        <p class="muted">Run Node.js applications on the server.</p>
      </div>
      <a class="btn" href="/apps/new">+ Create App</a>
    </div>
    <div class="card">
      ${
        apps.length
          ? `<table class="table">
            <thead><tr><th>Name</th><th>Entry</th><th>Port</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>`
          : `<p class="muted">No Node.js apps yet.</p>`
      }
    </div>
    `
    )
  );
});

app.get("/apps/new", auth, (req, res) => {
  res.send(
    layout(
      "Create Node App",
      `
      <h1>Create Node.js App</h1>
      <div class="card">
        <form method="post" action="/apps">
          <label>App Name</label>
          <input class="input" name="name" placeholder="myapp" required>
          <label>App Directory</label>
          <input class="input" name="root" placeholder="./hosting/myapp" required>
          <label>Entry File</label>
          <input class="input" name="entry" value="server.js" required>
          <label>Port</label>
          <input class="input" name="port" type="number" value="3000" min="1024" max="65535" required>
          <button class="btn">Create App</button>
        </form>
      </div>
      `
    )
  );
});

app.post("/apps", auth, async (req, res) => {
  try {
    const name = safeName(req.body.name);
    const entry = safeName(req.body.entry || "server.js");
    const port = Number(req.body.port);

    if (!name) throw new Error("Invalid app name.");
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      throw new Error("Invalid port.");
    }

    const apps = readJson(APPS_FILE);
    if (apps.some((x) => x.name === name)) {
      throw new Error("App already exists.");
    }

    let root = String(req.body.root || "").trim();
    if (!root) root = path.join(HOSTING_ROOT, name);
    root = path.resolve(root);

    await fsp.mkdir(root, { recursive: true });

    const entryPath = path.join(root, entry);
    if (!fs.existsSync(entryPath)) {
      await fsp.writeFile(
        entryPath,
        `const http = require("http");
const port = Number(process.env.PORT || ${port});
http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end("<h1>MyHosting Node App</h1>");
}).listen(port, "0.0.0.0", () => {
  console.log("App running on port " + port);
});
`
      );
    }

    apps.push({
      id: crypto.randomUUID(),
      name,
      root,
      entry,
      port,
      createdAt: new Date().toISOString()
    });

    writeJson(APPS_FILE, apps);
    audit(req, "CREATE_NODE_APP", name);
    res.redirect("/apps");
  } catch (e) {
    res.status(400).send(errorPage("Create app", e.message));
  }
});

async function startNodeApp(appInfo) {
  if (runningProcesses.has(appInfo.name)) return;

  const logFile = appLogPath(appInfo.name);
  const output = fs.openSync(logFile, "a");

  const child = spawn(process.execPath, [appInfo.entry], {
    cwd: appInfo.root,
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || "production",
      PORT: String(appInfo.port)
    },
    detached: false,
    stdio: ["ignore", output, output]
  });

  runningProcesses.set(appInfo.name, child);

  const cleanup = () => {
    runningProcesses.delete(appInfo.name);
    try {
      fs.closeSync(output);
    } catch {}
  };

  child.on("exit", cleanup);
  child.on("error", cleanup);
}

async function stopNodeApp(name) {
  const child = runningProcesses.get(name);
  if (!child) return;

  try {
    child.kill("SIGTERM");
  } catch {}

  setTimeout(() => {
    try {
      if (!child.killed) child.kill("SIGKILL");
    } catch {}
  }, 5000);

  runningProcesses.delete(name);
}

app.post("/apps/:name/start", auth, async (req, res) => {
  try {
    const appInfo = appByName(req.params.name);
    if (!appInfo) throw new Error("App not found.");
    await startNodeApp(appInfo);
    audit(req, "START_NODE_APP", appInfo.name);
    res.redirect("/apps");
  } catch (e) {
    res.status(400).send(errorPage("Start app", e.message));
  }
});

app.post("/apps/:name/stop", auth, async (req, res) => {
  try {
    await stopNodeApp(req.params.name);
    audit(req, "STOP_NODE_APP", req.params.name);
    res.redirect("/apps");
  } catch (e) {
    res.status(400).send(errorPage("Stop app", e.message));
  }
});

app.post("/apps/:name/public", auth, async (req, res) => {
  try {
    const appInfo = appByName(req.params.name);

    if (!appInfo) {
      throw new Error("App not found.");
    }

    if (!runningProcesses.has(appInfo.name)) {
      await startNodeApp(appInfo);
    }

    const url = await startCloudflareTunnel(appInfo);

    audit(
      req,
      "START_CLOUDFLARE_TUNNEL",
      `${appInfo.name} ${url}`
    );

    res.redirect("/apps");
  } catch (e) {
    res
      .status(400)
      .send(errorPage("Public Tunnel", e.message));
  }
});

app.post("/apps/:name/public-stop", auth, async (req, res) => {
  try {
    const appInfo = appByName(req.params.name);

    if (!appInfo) {
      throw new Error("App not found.");
    }

    stopCloudflareTunnel(appInfo.name);

    audit(
      req,
      "STOP_CLOUDFLARE_TUNNEL",
      appInfo.name
    );

    res.redirect("/apps");
  } catch (e) {
    res
      .status(400)
      .send(errorPage("Stop Public Tunnel", e.message));
  }
});

app.post("/apps/:name/restart", auth, async (req, res) => {
  try {
    const appInfo = appByName(req.params.name);
    if (!appInfo) throw new Error("App not found.");

    await stopNodeApp(appInfo.name);
    await new Promise((r) => setTimeout(r, 500));
    await startNodeApp(appInfo);

    audit(req, "RESTART_NODE_APP", appInfo.name);
    res.redirect("/apps");
  } catch (e) {
    res.status(400).send(errorPage("Restart app", e.message));
  }
});

app.get("/apps/:name/logs", auth, async (req, res) => {
  const file = appLogPath(req.params.name);
  let content = "";

  try {
    content = await fsp.readFile(file, "utf8");
  } catch {}

  if (content.length > 100000) content = content.slice(-100000);

  res.send(
    layout(
      "Node App Logs",
      `
      <h1>Logs: ${esc(req.params.name)}</h1>
      <div class="card">
        <pre>${esc(content)}</pre>
        <a class="btn gray" href="/apps">Back</a>
      </div>
      `
    )
  );
});
/* ---------- EDIT NODE APP ---------- */

app.get("/apps/:name/edit", auth, (req, res) => {
  const appInfo = appByName(req.params.name);

  if (!appInfo) {
    return res.status(404).send("App not found.");
  }

  res.send(
    layout(
      "Edit Node App",
      `
      <h1>Edit Node.js App</h1>

      <div class="card">
        <form method="post" action="/apps/${encodeURIComponent(appInfo.name)}/edit">

          <label>App Name</label>
          <input
            class="input"
            name="name"
            value="${esc(appInfo.name)}"
            required
          >

          <label>App Directory</label>
          <input
            class="input"
            name="root"
            value="${esc(appInfo.root)}"
            required
          >

          <label>Entry File</label>
          <input
            class="input"
            name="entry"
            value="${esc(appInfo.entry)}"
            required
          >

          <label>Port</label>
          <input
            class="input"
            name="port"
            type="number"
            value="${appInfo.port}"
            min="1024"
            max="65535"
            required
          >

          <br><br>

          <button class="btn">Save Changes</button>
          <a class="btn gray" href="/apps">Cancel</a>

        </form>
      </div>
      `
    )
  );
});


app.post("/apps/:name/edit", auth, async (req, res) => {
  try {
    const apps = readJson(APPS_FILE);

    const appInfo = apps.find((x) => x.name === req.params.name);

    if (!appInfo) {
      throw new Error("App not found.");
    }

    const newName = safeName(req.body.name);
    const newRoot = path.resolve(String(req.body.root || "").trim());
    const newEntry = safeName(req.body.entry || "server.js");
    const newPort = Number(req.body.port);

    if (!newName) {
      throw new Error("Invalid app name.");
    }

    if (!Number.isInteger(newPort) || newPort < 1024 || newPort > 65535) {
      throw new Error("Invalid port.");
    }

    // Check duplicate name
    const duplicate = apps.find(
      (x) => x.name === newName && x.name !== req.params.name
    );

    if (duplicate) {
      throw new Error("Another app already uses this name.");
    }

    // Stop old process before changing configuration
    await stopNodeApp(appInfo.name);

    appInfo.name = newName;
    appInfo.root = newRoot;
    appInfo.entry = newEntry;
    appInfo.port = newPort;

    await fsp.mkdir(appInfo.root, { recursive: true });

    writeJson(APPS_FILE, apps);

    audit(req, "EDIT_NODE_APP", appInfo.name);

    res.redirect("/apps");

  } catch (e) {
    res.status(400).send(
      errorPage("Edit Node App", e.message)
    );
  }
});

app.post("/apps/:name/delete", auth, async (req, res) => {
  try {
    const appInfo = appByName(req.params.name);
    if (!appInfo) throw new Error("App not found.");

    await stopNodeApp(appInfo.name);

    const apps = readJson(APPS_FILE).filter((x) => x.name !== appInfo.name);
    writeJson(APPS_FILE, apps);

    audit(req, "DELETE_NODE_APP", appInfo.name);
    res.redirect("/apps");
  } catch (e) {
    res.status(400).send(errorPage("Delete app", e.message));
  }
});
/* =========================================================
   DATABASE MANAGER
========================================================= */

function readDatabases() {
  return readJson(DBS_FILE);
}

function saveDatabases(data) {
  writeJson(DBS_FILE, data);
}

app.get("/databases", auth, (req, res) => {
  const databases = readDatabases();

  const rows = databases.length
    ? databases
        .map(
          (db) => `
        <tr>
          <td><strong>${esc(db.name)}</strong></td>
          <td>${esc(db.type)}</td>
          <td>${esc(db.host || "localhost")}</td>
          <td>${esc(db.port || "-")}</td>
          <td><span class="badge">${db.status || "Configured"}</span></td>
          <td>
            <div class="actions">
              <form method="post" action="/databases/${encodeURIComponent(
                db.id
              )}/test" style="display:inline">
                <button class="btn green">Test</button>
              </form>
              <form method="post" action="/databases/${encodeURIComponent(
                db.id
              )}/delete" style="display:inline" onsubmit="return confirm('Delete this database?')">
                <button class="btn red">Delete</button>
              </form>
            </div>
          </td>
        </tr>
      `
        )
        .join("")
    : `<tr><td colspan="6" class="muted">No databases configured yet.</td></tr>`;

  res.send(
    layout(
      "Databases",
      `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
        <div>
          <h2>Databases</h2>
          <p class="muted">Manage MySQL, MariaDB, MongoDB, PostgreSQL, Redis and SQLite connections.</p>
        </div>
        <a class="btn" href="/databases/new">Create Database</a>
      </div>
      <div style="overflow:auto;margin-top:20px">
        <table class="table">
          <thead>
            <tr>
              <th>Name</th><th>Type</th><th>Host</th><th>Port</th><th>Status</th><th>Action</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
    `
    )
  );
});

app.get("/databases/new", auth, (req, res) => {
  res.send(
    layout(
      "Create Database",
      `
    <div class="card" style="max-width:700px">
      <h2>Create Database</h2>
      <form method="post" action="/databases">
        <label>Database Name</label>
        <input class="input" name="name" required placeholder="mydatabase">

        <label>Database Type</label>
        <select class="input" name="type" required>
          <option value="mysql">MySQL / MariaDB</option>
          <option value="mongodb">MongoDB</option>
          <option value="postgresql">PostgreSQL</option>
          <option value="redis">Redis</option>
          <option value="sqlite">SQLite</option>
        </select>

        <label>Host</label>
        <input class="input" name="host" value="localhost" required>

        <label>Port (leave blank for default)</label>
        <input class="input" name="port" placeholder="Default port">

        <label>Username</label>
        <input class="input" name="username" placeholder="Database username">

        <label>Password</label>
        <input class="input" type="password" name="password" placeholder="Database password">

        <label>Database / SQLite Path</label>
        <input class="input" name="database" placeholder="database_name or /path/to/file.db">

        <button class="btn" type="submit">Save Database</button>
        <a class="btn gray" href="/databases">Cancel</a>
      </form>
    </div>
    `
    )
  );
});

app.post("/databases", auth, (req, res) => {
  const name = String(req.body.name || "").trim();
  const type = String(req.body.type || "").trim().toLowerCase();
  const host = String(req.body.host || "localhost").trim();
  const port = String(req.body.port || "").trim();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const database = String(req.body.database || "").trim();

  const allowedTypes = [
    "mysql",
    "mariadb",
    "mongodb",
    "postgresql",
    "postgres",
    "redis",
    "sqlite"
  ];

  if (!name) {
    return res
      .status(400)
      .send(errorPage("Database", "Database name is required."));
  }
  if (!allowedTypes.includes(type)) {
    return res
      .status(400)
      .send(errorPage("Database", "Invalid database type."));
  }

  const databases = readDatabases();
  if (databases.some((db) => db.name.toLowerCase() === name.toLowerCase())) {
    return res
      .status(400)
      .send(
        errorPage("Database", "A database with this name already exists.")
      );
  }

  const db = {
    id: crypto.randomUUID(),
    name,
    type,
    host,
    port,
    username,
    password: password ? encrypt(password) : "",
    database,
    status: "Configured",
    createdAt: new Date().toISOString()
  };

  databases.push(db);
  saveDatabases(databases);

  audit(req, "CREATE_DATABASE", name);
  res.redirect("/databases");
});

app.post("/databases/:id/delete", auth, (req, res) => {
  const databases = readDatabases();
  const target = databases.find((x) => x.id === req.params.id);
  const remaining = databases.filter((x) => x.id !== req.params.id);

  saveDatabases(remaining);
  audit(req, "DELETE_DATABASE", target?.name || req.params.id);

  res.redirect("/databases");
});

app.post("/databases/:id/test", auth, async (req, res) => {
  const databases = readDatabases();
  const db = databases.find((x) => x.id === req.params.id);

  if (!db) {
    return res
      .status(404)
      .send(errorPage("Test failed", "Database not found."));
  }

  const password = db.password ? decrypt(db.password) : "";

  try {
    if (db.type === "mysql" || db.type === "mariadb") {
      const mysql = require("mysql2/promise");
      const conn = await mysql.createConnection({
        host: db.host || "localhost",
        port: Number(db.port) || 3306,
        user: db.username,
        password,
        database: db.database || undefined,
        connectTimeout: 5000
      });
      const [r] = await conn.query("SELECT VERSION() AS v");
      await conn.end();
      return renderDbTestResult(res, db, "OK", `MySQL version: ${r[0].v}`);
    }

    if (db.type === "postgres" || db.type === "postgresql") {
      const { Client } = require("pg");
      const c = new Client({
        host: db.host || "localhost",
        port: Number(db.port) || 5432,
        user: db.username,
        password,
        database: db.database || "postgres"
      });
      await c.connect();
      const r = await c.query("SELECT version() AS v");
      await c.end();
      return renderDbTestResult(res, db, "OK", `PostgreSQL: ${r.rows[0].v}`);
    }

    if (db.type === "mongodb") {
      const { MongoClient } = require("mongodb");
      const url = `mongodb://${
        db.username ? `${db.username}:${password}@` : ""
      }${db.host || "localhost"}:${Number(db.port) || 27017}`;
      const client = new MongoClient(url, {
        serverSelectionTimeoutMS: 5000
      });
      await client.connect();
      const info = await client
        .db(db.database || "admin")
        .admin()
        .serverInfo();
      await client.close();
      return renderDbTestResult(
        res,
        db,
        "OK",
        `MongoDB version: ${info.version}`
      );
    }

    if (db.type === "redis") {
      const Redis = require("ioredis");
      const r = new Redis({
        host: db.host || "localhost",
        port: Number(db.port) || 6379,
        password: password || undefined,
        connectTimeout: 5000,
        lazyConnect: true
      });
      await r.connect();
      const info = await r.info("server");
      r.disconnect();
      const v = info.match(/redis_version:(.+)/)?.[1]?.trim();
      return renderDbTestResult(
        res,
        db,
        "OK",
        `Redis version: ${v || "unknown"}`
      );
    }

    if (db.type === "sqlite") {
      if (!db.database) throw new Error("SQLite path missing");
      const Database = require("better-sqlite3");
      const s = new Database(db.database, { fileMustExist: false });
      const v = s.prepare("SELECT sqlite_version() AS v").get();
      s.close();
      return renderDbTestResult(res, db, "OK", `SQLite version: ${v.v}`);
    }

    return renderDbTestResult(res, db, "FAIL", "Unknown database type.");
  } catch (e) {
    return renderDbTestResult(res, db, "FAIL", e.message);
  }
});

function renderDbTestResult(res, db, status, message) {
  res.send(
    layout(
      "Database Test",
      `<div class="card">
        <h2>Connection Test: ${esc(db.name)}</h2>
        <p class="${status === "OK" ? "ok" : "err"}">
          Status: ${esc(status)}
        </p>
        <pre>${esc(message)}</pre>
        <a class="btn gray" href="/databases">Back</a>
      </div>`
    )
  );
}

/* =========================================================
   CRON JOBS
========================================================= */

async function getCrontab() {
  if (!linux()) throw new Error("Cron management requires Linux.");
  try {
    return await run("crontab", ["-l"]);
  } catch {
    return "";
  }
}

async function setCrontab(content) {
  if (!linux()) throw new Error("Cron management requires Linux.");

  return new Promise((resolve, reject) => {
    const child = spawn("crontab", ["-"], {
      stdio: ["pipe", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(stderr || `crontab exited ${code}`));
      }
      resolve(stdout);
    });

    child.stdin.end(content);
  });
}

app.get("/cron", auth, async (req, res) => {
  const jobs = readJson(CRON_FILE);

  res.send(
    layout(
      "Cron Jobs",
      `
      <h1>Cron Jobs</h1>
      <p class="muted">${
        linux()
          ? "Linux crontab integration enabled."
          : "Windows local testing mode. Cron becomes active on Linux VPS."
      }</p>
      <div class="card">
        <form method="post" action="/cron">
          <label>Schedule</label>
          <input class="input" name="schedule" placeholder="*/5 * * * *" required>
          <label>Command</label>
          <input class="input" name="command" placeholder="/usr/bin/node /home/app/task.js" required>
          <button class="btn">Add Cron Job</button>
        </form>
      </div>
      <div class="card">
        <h2>Managed Jobs</h2>
        ${
          jobs.length
            ? `<table class="table">
              <thead><tr><th>Schedule</th><th>Command</th><th>Action</th></tr></thead>
              <tbody>
                ${jobs
                  .map(
                    (job) => `
                  <tr>
                    <td><code>${esc(job.schedule)}</code></td>
                    <td><code>${esc(job.command)}</code></td>
                    <td>
                      <form method="post" action="/cron/${encodeURIComponent(
                        job.id
                      )}/delete">
                        <button class="btn red">Delete</button>
                      </form>
                    </td>
                  </tr>
                `
                  )
                  .join("")}
              </tbody>
            </table>`
            : `<p class="muted">No cron jobs.</p>`
        }
      </div>
      `
    )
  );
});

app.post("/cron", auth, async (req, res) => {
  try {
    const schedule = String(req.body.schedule || "").trim();
    const command = String(req.body.command || "").trim();

    if (!schedule) throw new Error("Schedule required.");
    if (!command) throw new Error("Command required.");
    if (schedule.split(/\s+/).length !== 5) {
      throw new Error("Cron schedule must contain 5 fields.");
    }

    const jobs = readJson(CRON_FILE);
    const job = {
      id: crypto.randomUUID(),
      schedule,
      command,
      createdAt: new Date().toISOString()
    };

    jobs.push(job);
    writeJson(CRON_FILE, jobs);

    if (linux()) {
      let existing = await getCrontab();
      const marker = "# MYHOSTING_PANEL";

      existing = existing
        .split("\n")
        .filter((line) => !line.includes(marker))
        .filter(Boolean)
        .join("\n");

      const managed = jobs.map(
        (j) => `${j.schedule} ${j.command} ${marker}:${j.id}`
      );

      const output =
        [existing, ...managed].filter(Boolean).join("\n") + "\n";

      await setCrontab(output);
    }

    audit(req, "CREATE_CRON", command);
    res.redirect("/cron");
  } catch (e) {
    res.status(400).send(errorPage("Cron error", e.message));
  }
});

app.post("/cron/:id/delete", auth, async (req, res) => {
  try {
    const jobs = readJson(CRON_FILE);
    const job = jobs.find((x) => x.id === req.params.id);
    const remaining = jobs.filter((x) => x.id !== req.params.id);

    writeJson(CRON_FILE, remaining);

    if (linux()) {
      let existing = await getCrontab();
      const marker = "# MYHOSTING_PANEL";

      existing = existing
        .split("\n")
        .filter((line) => !line.includes(marker))
        .filter(Boolean)
        .join("\n");

      const managed = remaining.map(
        (x) => `${x.schedule} ${x.command} ${marker}:${x.id}`
      );

      const output =
        [existing, ...managed].filter(Boolean).join("\n") + "\n";

      await setCrontab(output);
    }

    audit(req, "DELETE_CRON", job?.command || req.params.id);
    res.redirect("/cron");
  } catch (e) {
    res.status(400).send(errorPage("Cron delete", e.message));
  }
});

/* =========================================================
   SSL / CERTBOT
========================================================= */

app.get("/ssl", auth, (req, res) => {
  const sites = readJson(SITES_FILE);

  res.send(
    layout(
      "SSL",
      `
      <h1>SSL Certificates</h1>
      <p class="muted">Let's Encrypt certificates through Certbot.</p>
      <div class="card">
        ${
          sites.length
            ? `<table class="table">
              <thead><tr><th>Domain</th><th>Action</th></tr></thead>
              <tbody>
                ${sites
                  .map(
                    (site) => `
                  <tr>
                    <td>${esc(site.domain)}</td>
                    <td>
                      <form method="post" action="/ssl/${encodeURIComponent(
                        site.domain
                      )}">
                        <button class="btn">Issue / Renew SSL</button>
                      </form>
                    </td>
                  </tr>
                `
                  )
                  .join("")}
              </tbody>
            </table>`
            : `<p class="muted">Create a website first.</p>`
        }
      </div>
      `
    )
  );
});

app.post("/ssl/:domain", auth, async (req, res) => {
  try {
    if (!linux()) throw new Error("Certbot SSL requires a Linux VPS.");

    const domain = req.params.domain;
    if (!validDomain(domain)) throw new Error("Invalid domain.");

    const sites = readJson(SITES_FILE);
    const site = sites.find((x) => x.domain === domain);
    if (!site) throw new Error("Website not found.");

    const available = await commandExists("certbot");
    if (!available) {
      throw new Error("Certbot is not installed. Install certbot first.");
    }

    const args = [
      "--nginx",
      "-d",
      domain,
      "-d",
      `www.${domain}`,
      "--non-interactive",
      "--agree-tos"
    ];

    if (CERTBOT_EMAIL) {
      args.push("--email", CERTBOT_EMAIL);
    } else {
      args.push("--register-unsafely-without-email");
    }

    await run("certbot", args, 180000);

    audit(req, "SSL_ISSUE", domain);

    res.send(
      layout(
        "SSL",
        `<div class="card">
          <h2 class="ok">SSL completed</h2>
          <p>Certificate installed for <strong>${esc(domain)}</strong></p>
          <a class="btn" href="/ssl">Back</a>
        </div>`
      )
    );
  } catch (e) {
    res.status(500).send(errorPage("SSL failed", e.message));
  }
});

/* =========================================================
   SYSTEM
========================================================= */

app.get("/system", auth, async (req, res) => {
  let nginxStatus = "Not available";
  let certbotStatus = "Not available";
  let nginxVersion = "";
  const nodeVersion = process.version;

  if (linux()) {
    try {
      nginxVersion = await run("nginx", ["-v"]);
    } catch (e) {
      nginxVersion = e.message;
    }

    try {
      await run("nginx", ["-t"]);
      nginxStatus = "OK";
    } catch {
      nginxStatus = "Not configured / error";
    }

    try {
      if (await commandExists("certbot")) {
        certbotStatus = "Installed";
      } else {
        certbotStatus = "Not installed";
      }
    } catch {
      certbotStatus = "Unknown";
    }
  }

  const mem = process.memoryUsage();

  res.send(
    layout(
      "System",
      `
      <h1>System Status</h1>
      <div class="grid">
        <div class="card"><h3>Hostname</h3><p>${esc(os.hostname())}</p></div>
        <div class="card"><h3>Platform</h3><p>${esc(process.platform)}</p></div>
        <div class="card"><h3>Architecture</h3><p>${esc(process.arch)}</p></div>
        <div class="card"><h3>Node.js</h3><p>${esc(nodeVersion)}</p></div>
        <div class="card"><h3>Memory</h3><p>${Math.round(
          mem.rss / 1024 / 1024
        )} MB RSS</p></div>
        <div class="card"><h3>CPU</h3><p>${os.cpus().length} cores</p></div>
        <div class="card"><h3>Nginx</h3><p>${esc(nginxStatus)}</p></div>
        <div class="card"><h3>Certbot</h3><p>${esc(certbotStatus)}</p></div>
      </div>
      <div class="card">
        <h2>Details</h2>
        <pre>${esc(
          JSON.stringify(
            {
              hostname: os.hostname(),
              platform: process.platform,
              architecture: process.arch,
              node: process.version,
              uptime: Math.round(os.uptime()),
              totalMemory:
                Math.round(
                  os.totalmem() / 1024 / 1024 / 1024
                ) + " GB",
              freeMemory:
                Math.round(
                  os.freemem() / 1024 / 1024 / 1024
                ) + " GB",
              nginxVersion
            },
            null,
            2
          )
        )}</pre>
      </div>
      `
    )
  );
});

/* =========================================================
   AUDIT LOG
========================================================= */

app.get("/audit", auth, async (req, res) => {
  let logs = "";

  try {
    logs = await fsp.readFile(AUDIT_FILE, "utf8");
  } catch {}

  if (logs.length > 100000) logs = logs.slice(-100000);

  res.send(
    layout(
      "Audit Log",
      `
      <h1>Audit Log</h1>
      <div class="card">
        <pre>${esc(logs)}</pre>
      </div>
      `
    )
  );
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "myhosting-panel",
    time: new Date().toISOString(),
    node: process.version,
    platform: process.platform
  });
});

/* =========================================================
   ADVANCED MONGODB ATLAS — COLLECTION/DOC/QUERY/INDEX MANAGER
   + LIVE STATS + BACKUP/IMPORT + PROFILER
========================================================= */

/* ---------- Helper: Get connected Atlas client ---------- */
async function getAtlasClient(id) {
  const list = readAtlas();
  const c = list.find((x) => x.id === id);
  if (!c) throw new Error("Cluster not found");

  const uri = decrypt(c.connectionString);
  const { MongoClient } = require("mongodb");
  const client = new MongoClient(uri, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000
  });
  await client.connect();
  return { client, cluster: c };
}

/* ---------- ATLAS: LIVE STATS ---------- */
app.get("/atlas/:id/stats", auth, async (req, res) => {
  try {
    const { client, cluster } = await getAtlasClient(req.params.id);
    const admin = client.db(cluster.database || "admin").admin();

    const [serverStatus, dbStats, replStatus] = await Promise.allSettled([
      admin.serverStatus(),
      admin.dbStats(),
      admin.command({ replSetGetStatus: 1 })
    ]);

    const ss = serverStatus.value || {};
    const dbs = dbStats.value || {};

    const html = `
      <h1>Live Stats: ${esc(cluster.name)}</h1>
      <div class="grid">
        <div class="card">
          <h3>Connections</h3>
          <h2>${ss.connections?.current ?? "-"}</h2>
          <p class="muted small">Available: ${ss.connections?.available ?? "-"}</p>
        </div>
        <div class="card">
          <h3>Ops / sec</h3>
          <h2>${ss.opcounters ? ((ss.opcounters.insert||0)+(ss.opcounters.query||0)) : "-"}</h2>
          <p class="muted small">Insert+Query total</p>
        </div>
        <div class="card">
          <h3>Memory (MB)</h3>
          <h2>${ss.mem?.resident ?? "-"}</h2>
          <p class="muted small">Virtual: ${ss.mem?.virtual ?? "-"} MB</p>
        </div>
        <div class="card">
          <h3>Uptime</h3>
          <h2>${ss.uptime ? Math.round(ss.uptime / 3600) + "h" : "-"}</h2>
          <p class="muted small">${ss.uptime ?? "-"} sec</p>
        </div>
        <div class="card">
          <h3>DB Size (MB)</h3>
          <h2>${dbs.dataSize ? Math.round(dbs.dataSize/1024/1024) : "-"}</h2>
          <p class="muted small">Storage: ${dbs.storageSize ? Math.round(dbs.storageSize/1024/1024) : "-"} MB</p>
        </div>
        <div class="card">
          <h3>Collections</h3>
          <h2>${dbs.collections ?? "-"}</h2>
          <p class="muted small">Indexes: ${dbs.indexes ?? "-"}</p>
        </div>
        <div class="card">
          <h3>Version</h3>
          <h2>${esc(ss.version || "-")}</h2>
          <p class="muted small">${esc(ss.host || "-")}</p>
        </div>
        <div class="card">
          <h3>Replication</h3>
          <h2>${
            replStatus.value?.members
              ? replStatus.value.members.length + " nodes"
              : "N/A"
          }</h2>
          <p class="muted small">${
            replStatus.value?.set || "Standalone / Atlas"
          }</p>
        </div>
      </div>
      <div class="card">
        <h3>Raw serverStatus (top 40 keys)</h3>
        <pre>${esc(JSON.stringify(Object.fromEntries(Object.entries(ss).slice(0, 40)), null, 2))}</pre>
        <a class="btn gray" href="/atlas">Back</a>
      </div>
    `;

    await client.close();
    res.send(layout("Atlas Stats", html));
  } catch (e) {
    res.status(400).send(errorPage("Stats failed", e.message));
  }
});

/* ---------- ATLAS: COLLECTION BROWSER ---------- */
app.get("/atlas/:id/db/:db", auth, async (req, res) => {
  try {
    const { client, cluster } = await getAtlasClient(req.params.id);
    const db = client.db(req.params.db);

    const collections = await db.listCollections().toArray();

    const rows = collections
      .map(
        (col) => `
        <tr>
          <td><strong>${esc(col.name)}</strong></td>
          <td>${esc(col.type || "collection")}</td>
          <td>
            <div class="actions">
              <a class="btn gray" href="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          col.name
        )}">Browse Docs</a>
              <a class="btn gray" href="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          col.name
        )}/indexes">Indexes</a>
              <a class="btn gray" href="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          col.name
        )}/export">Export</a>
              <a class="btn gray" href="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          col.name
        )}/import">Import</a>
            </div>
          </td>
        </tr>
      `
      )
      .join("");

    await client.close();

    res.send(
      layout(
        "Atlas Collections",
        `
      <h1>Database: ${esc(req.params.db)}</h1>
      <p class="muted">Cluster: ${esc(cluster.name)} • ${collections.length} collections</p>
      <div class="card">
        <table class="table">
          <thead><tr><th>Collection</th><th>Type</th><th>Actions</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="3" class="muted">No collections</td></tr>'}</tbody>
        </table>
        <br>
        <a class="btn gray" href="/atlas/${encodeURIComponent(
          cluster.id
        )}/browse">Back</a>
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("DB browse failed", e.message));
  }
});

/* ---------- ATLAS: DOCUMENT VIEWER ---------- */
app.get("/atlas/:id/db/:db/col/:col", auth, async (req, res) => {
  try {
    const { client, cluster } = await getAtlasClient(req.params.id);
    const db = client.db(req.params.db);
    const col = db.collection(req.params.col);

    const page = parseInt(req.query.page || "1");
    const limit = 20;
    const skip = (page - 1) * limit;

    const docs = await col.find({}).skip(skip).limit(limit).toArray();
    const total = await col.estimatedDocumentCount();

    const docRows = docs
      .map(
        (d, i) => `
        <tr>
          <td>${skip + i + 1}</td>
          <td><pre style="margin:0;max-height:200px">${esc(
            JSON.stringify(d, null, 2)
          )}</pre></td>
          <td>
            <div class="actions">
              <a class="btn gray" href="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          req.params.col
        )}/doc/${encodeURIComponent(String(d._id))}">Edit</a>
              <form method="post" action="/atlas/${encodeURIComponent(
                cluster.id
              )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          req.params.col
        )}/doc/delete" style="display:inline" onsubmit="return confirm('Delete this document?')">
                <input type="hidden" name="_id" value="${esc(String(d._id))}">
                <button class="btn red">Delete</button>
              </form>
            </div>
          </td>
        </tr>
      `
      )
      .join("");

    const totalPages = Math.ceil(total / limit) || 1;

    await client.close();

    res.send(
      layout(
        "Collection Docs",
        `
      <h1>${esc(req.params.db)} → ${esc(req.params.col)}</h1>
      <p class="muted">${total} documents • Page ${page}/${totalPages}</p>
      <div class="card">
        <table class="table">
          <thead><tr><th style="width:40px">#</th><th>Document</th><th>Actions</th></tr></thead>
          <tbody>${docRows || '<tr><td colspan="3" class="muted">Empty collection</td></tr>'}</tbody>
        </table>
        <br>
        <div class="actions">
          ${
            page > 1
              ? `<a class="btn gray" href="?page=${page - 1}">← Prev</a>`
              : ""
          }
          ${
            page < totalPages
              ? `<a class="btn gray" href="?page=${page + 1}">Next →</a>`
              : ""
          }
          <a class="btn" href="/atlas/${encodeURIComponent(
            cluster.id
          )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          req.params.col
        )}/new">+ New Document</a>
          <a class="btn gray" href="/atlas/${encodeURIComponent(
            cluster.id
          )}/db/${encodeURIComponent(req.params.db)}">Back</a>
        </div>
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Docs failed", e.message));
  }
});

/* ---------- ATLAS: CREATE DOCUMENT ---------- */
app.get("/atlas/:id/db/:db/col/:col/new", auth, (req, res) => {
  res.send(
    layout(
      "New Document",
      `
    <h1>New Document: ${esc(req.params.col)}</h1>
    <div class="card">
      <form method="post" action="/atlas/${encodeURIComponent(
        req.params.id
      )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
        req.params.col
      )}/new">
        <label>JSON Document</label>
        <textarea class="input" name="json" rows="20" style="font-family:monospace">{
  "name": "example",
  "value": 123,
  "createdAt": "2025-01-01T00:00:00Z"
}</textarea>
        <button class="btn">Insert</button>
        <a class="btn gray" href="javascript:history.back()">Cancel</a>
      </form>
    </div>
    `
    )
  );
});

app.post("/atlas/:id/db/:db/col/:col/new", auth, async (req, res) => {
  try {
    const doc = JSON.parse(req.body.json || "{}");
    const { client } = await getAtlasClient(req.params.id);
    await client.db(req.params.db).collection(req.params.col).insertOne(doc);
    await client.close();
    audit(req, "ATLAS_INSERT", `${req.params.db}.${req.params.col}`);
    res.redirect(
      `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
        req.params.db
      )}/col/${encodeURIComponent(req.params.col)}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Insert failed", e.message));
  }
});

/* ---------- ATLAS: EDIT DOCUMENT ---------- */
app.get("/atlas/:id/db/:db/col/:col/doc/:_id", auth, async (req, res) => {
  try {
    const { ObjectId } = require("mongodb");
    const { client } = await getAtlasClient(req.params.id);

    let filter;
    try {
      filter = { _id: new ObjectId(req.params._id) };
    } catch {
      filter = { _id: req.params._id };
    }

    const doc = await client
      .db(req.params.db)
      .collection(req.params.col)
      .findOne(filter);
    await client.close();

    if (!doc) return res.status(404).send("Document not found");

    res.send(
      layout(
        "Edit Document",
        `
      <h1>Edit Document</h1>
      <div class="card">
        <form method="post" action="/atlas/${encodeURIComponent(
          req.params.id
        )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          req.params.col
        )}/doc/${encodeURIComponent(req.params._id)}">
          <label>JSON</label>
          <textarea class="input" name="json" rows="25" style="font-family:monospace">${esc(
            JSON.stringify(doc, null, 2)
          )}</textarea>
          <button class="btn">Save</button>
          <a class="btn gray" href="javascript:history.back()">Cancel</a>
        </form>
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Load failed", e.message));
  }
});

app.post("/atlas/:id/db/:db/col/:col/doc/:_id", auth, async (req, res) => {
  try {
    const { ObjectId } = require("mongodb");
    const { client } = await getAtlasClient(req.params.id);

    const newDoc = JSON.parse(req.body.json || "{}");
    delete newDoc._id;

    let filter;
    try {
      filter = { _id: new ObjectId(req.params._id) };
    } catch {
      filter = { _id: req.params._id };
    }

    await client
      .db(req.params.db)
      .collection(req.params.col)
      .replaceOne(filter, newDoc);
    await client.close();

    audit(req, "ATLAS_UPDATE", `${req.params.db}.${req.params.col}`);
    res.redirect(
      `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
        req.params.db
      )}/col/${encodeURIComponent(req.params.col)}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Update failed", e.message));
  }
});

/* ---------- ATLAS: DELETE DOCUMENT ---------- */
app.post("/atlas/:id/db/:db/col/:col/doc/delete", auth, async (req, res) => {
  try {
    const { ObjectId } = require("mongodb");
    const { client } = await getAtlasClient(req.params.id);

    let filter;
    try {
      filter = { _id: new ObjectId(req.body._id) };
    } catch {
      filter = { _id: req.body._id };
    }

    await client.db(req.params.db).collection(req.params.col).deleteOne(filter);
    await client.close();

    audit(req, "ATLAS_DELETE_DOC", `${req.params.db}.${req.params.col}`);
    res.redirect(
      `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
        req.params.db
      )}/col/${encodeURIComponent(req.params.col)}`
    );
  } catch (e) {
    res.status(400).send(errorPage("Delete failed", e.message));
  }
});

/* ---------- ATLAS: INDEX MANAGER ---------- */
app.get("/atlas/:id/db/:db/col/:col/indexes", auth, async (req, res) => {
  try {
    const { client, cluster } = await getAtlasClient(req.params.id);
    const indexes = await client
      .db(req.params.db)
      .collection(req.params.col)
      .indexes();
    await client.close();

    const rows = indexes
      .map(
        (idx) => `
        <tr>
          <td><code>${esc(idx.name)}</code></td>
          <td><pre style="margin:0">${esc(
            JSON.stringify(idx.key, null, 2)
          )}</pre></td>
          <td>${idx.unique ? "✅ Unique" : "-"}</td>
          <td>${idx.sparse ? "✅ Sparse" : "-"}</td>
          <td>
            ${
              idx.name !== "_id_"
                ? `<form method="post" action="/atlas/${encodeURIComponent(
                    cluster.id
                  )}/db/${encodeURIComponent(
                    req.params.db
                  )}/col/${encodeURIComponent(
                    req.params.col
                  )}/index/drop" style="display:inline" onsubmit="return confirm('Drop index?')">
                    <input type="hidden" name="name" value="${esc(idx.name)}">
                    <button class="btn red">Drop</button>
                  </form>`
                : '<span class="muted small">Protected</span>'
            }
          </td>
        </tr>
      `
      )
      .join("");

    res.send(
      layout(
        "Indexes",
        `
      <h1>Indexes: ${esc(req.params.col)}</h1>
      <div class="card">
        <form method="post" action="/atlas/${encodeURIComponent(
          cluster.id
        )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
          req.params.col
        )}/index/create">
          <h3>Create Index</h3>
          <label>Index Keys (JSON)</label>
          <input class="input" name="keys" value='{"field": 1}' required style="font-family:monospace">
          <label>
            <input type="checkbox" name="unique"> Unique
            &nbsp;&nbsp;
            <input type="checkbox" name="sparse"> Sparse
          </label>
          <br>
          <button class="btn">Create Index</button>
        </form>
      </div>
      <div class="card">
        <table class="table">
          <thead><tr><th>Name</th><th>Keys</th><th>Unique</th><th>Sparse</th><th>Action</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <br>
        <a class="btn gray" href="javascript:history.back()">Back</a>
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Indexes failed", e.message));
  }
});

app.post(
  "/atlas/:id/db/:db/col/:col/index/create",
  auth,
  async (req, res) => {
    try {
      const keys = JSON.parse(req.body.keys || "{}");
      const { client } = await getAtlasClient(req.params.id);

      await client
        .db(req.params.db)
        .collection(req.params.col)
        .createIndex(keys, {
          unique: req.body.unique === "on",
          sparse: req.body.sparse === "on"
        });
      await client.close();

      audit(req, "ATLAS_CREATE_INDEX", `${req.params.db}.${req.params.col}`);
      res.redirect(
        `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
          req.params.db
        )}/col/${encodeURIComponent(req.params.col)}/indexes`
      );
    } catch (e) {
      res.status(400).send(errorPage("Index create failed", e.message));
    }
  }
);

app.post("/atlas/:id/db/:db/col/:col/index/drop", auth, async (req, res) => {
  try {
    const { client } = await getAtlasClient(req.params.id);
    await client
      .db(req.params.db)
      .collection(req.params.col)
      .dropIndex(req.body.name);
    await client.close();

    audit(req, "ATLAS_DROP_INDEX", req.body.name);
    res.redirect(
      `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
        req.params.db
      )}/col/${encodeURIComponent(req.params.col)}/indexes`
    );
  } catch (e) {
    res.status(400).send(errorPage("Index drop failed", e.message));
  }
});

/* ---------- ATLAS: RAW QUERY RUNNER ---------- */
app.get("/atlas/:id/query", auth, (req, res) => {
  res.send(
    layout(
      "Query Runner",
      `
    <h1>MongoDB Query Runner</h1>
    <p class="muted">Run raw MongoDB commands (find, aggregate, count, etc.)</p>
    <div class="card">
      <form method="post" action="/atlas/${encodeURIComponent(
        req.params.id
      )}/query">
        <label>Database</label>
        <input class="input" name="db" required placeholder="mydb">

        <label>Collection</label>
        <input class="input" name="col" required placeholder="users">

        <label>Operation</label>
        <select class="input" name="op">
          <option value="find">find</option>
          <option value="findOne">findOne</option>
          <option value="count">count</option>
          <option value="distinct">distinct</option>
          <option value="aggregate">aggregate</option>
        </select>

        <label>Query JSON (filter or pipeline)</label>
        <textarea class="input" name="query" rows="8" style="font-family:monospace">{}</textarea>

        <label>Limit</label>
        <input class="input" name="limit" type="number" value="20">

        <button class="btn">Run Query</button>
      </form>
    </div>
    `
    )
  );
});

app.post("/atlas/:id/query", auth, async (req, res) => {
  try {
    const { client } = await getAtlasClient(req.params.id);
    const db = client.db(req.body.db);
    const col = db.collection(req.body.col);
    const query = JSON.parse(req.body.query || "{}");
    const limit = parseInt(req.body.limit || "20");

    let result;
    switch (req.body.op) {
      case "find":
        result = await col.find(query).limit(limit).toArray();
        break;
      case "findOne":
        result = await col.findOne(query);
        break;
      case "count":
        result = { count: await col.countDocuments(query) };
        break;
      case "distinct":
        result = await col.distinct(req.body.field || "_id", query);
        break;
      case "aggregate":
        result = await col.aggregate(query).limit(limit).toArray();
        break;
      default:
        throw new Error("Unknown operation");
    }

    await client.close();

    res.send(
      layout(
        "Query Result",
        `
      <h1>Query Result</h1>
      <div class="card">
        <pre>${esc(JSON.stringify(result, null, 2))}</pre>
        <a class="btn gray" href="/atlas/${encodeURIComponent(
          req.params.id
        )}/query">New Query</a>
      </div>
      `
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Query failed", e.message));
  }
});

/* ---------- ATLAS: EXPORT COLLECTION ---------- */
app.get("/atlas/:id/db/:db/col/:col/export", auth, async (req, res) => {
  try {
    const { client } = await getAtlasClient(req.params.id);
    const docs = await client
      .db(req.params.db)
      .collection(req.params.col)
      .find({})
      .limit(10000)
      .toArray();
    await client.close();

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${req.params.col}-${Date.now()}.json"`
    );
    res.setHeader("Content-Type", "application/json");
    res.send(JSON.stringify(docs, null, 2));
  } catch (e) {
    res.status(400).send(errorPage("Export failed", e.message));
  }
});

/* ---------- ATLAS: IMPORT COLLECTION ---------- */
app.get("/atlas/:id/db/:db/col/:col/import", auth, (req, res) => {
  res.send(
    layout(
      "Import Documents",
      `
    <h1>Import to ${esc(req.params.col)}</h1>
    <div class="card">
      <form method="post" action="/atlas/${encodeURIComponent(
        req.params.id
      )}/db/${encodeURIComponent(req.params.db)}/col/${encodeURIComponent(
        req.params.col
      )}/import" enctype="multipart/form-data">
        <p class="muted">Upload a JSON file (array of documents) or paste JSON below.</p>
        <label>JSON File</label>
        <input type="file" name="file" accept=".json">
        <label>OR paste JSON</label>
        <textarea class="input" name="json" rows="15" style="font-family:monospace">[]</textarea>
        <button class="btn">Import</button>
        <a class="btn gray" href="javascript:history.back()">Cancel</a>
      </form>
    </div>
    `
    )
  );
});

app.post(
  "/atlas/:id/db/:db/col/:col/import",
  auth,
  upload.single("file"),
  async (req, res) => {
    try {
      let json;
      if (req.file) {
        json = JSON.parse(await fsp.readFile(req.file.path, "utf8"));
        await fsp.unlink(req.file.path).catch(() => {});
      } else {
        json = JSON.parse(req.body.json || "[]");
      }

      if (!Array.isArray(json)) json = [json];

      const { client } = await getAtlasClient(req.params.id);
      const result = await client
        .db(req.params.db)
        .collection(req.params.col)
        .insertMany(json);
      await client.close();

      audit(
        req,
        "ATLAS_IMPORT",
        `${req.params.db}.${req.params.col} (${result.insertedCount})`
      );
      res.redirect(
        `/atlas/${encodeURIComponent(req.params.id)}/db/${encodeURIComponent(
          req.params.db
        )}/col/${encodeURIComponent(req.params.col)}`
      );
    } catch (e) {
      if (req.file) await fsp.unlink(req.file.path).catch(() => {});
      res.status(400).send(errorPage("Import failed", e.message));
    }
  }
);


/* =========================================================
   MONGODB ATLAS — MAIN LIST PAGE (MISSING ROUTE)
========================================================= */

app.get("/atlas", auth, (req, res) => {
  const list = readAtlas();

  const rows = list.length
    ? list
        .map(
          (c) => `
    <tr>
      <td><strong>${esc(c.name)}</strong></td>
      <td class="path">${esc(
        (c.connectionString || "").replace(/:\/\/.*@/, "://***:***@")
      )}</td>
      <td>${esc(c.database || "-")}</td>
      <td><span class="badge">${c.status || "Unknown"}</span></td>
      <td>
        <div class="actions">
          <form method="post" action="/atlas/${encodeURIComponent(
            c.id
          )}/test" style="display:inline">
            <button class="btn green">Test</button>
          </form>
          <a class="btn gray" href="/atlas/${encodeURIComponent(
            c.id
          )}/browse">Browse</a>
          <a class="btn gray" href="/atlas/${encodeURIComponent(
            c.id
          )}/edit">Edit</a>
          <form method="post" action="/atlas/${encodeURIComponent(
            c.id
          )}/delete" style="display:inline" onsubmit="return confirm('Delete cluster?')">
            <button class="btn red">Del</button>
          </form>
        </div>
      </td>
    </tr>`
        )
        .join("")
    : `<tr><td colspan="5" class="muted">No Atlas clusters yet.</td></tr>`;

  res.send(
    layout(
      "MongoDB Atlas",
      `
    <div class="actions" style="justify-content:space-between">
      <div>
        <h1>MongoDB Atlas</h1>
        <p class="muted">Cloud MongoDB clusters (mongodb+srv://). Connection strings are encrypted.</p>
      </div>
      <a class="btn" href="/atlas/new">+ Add Cluster</a>
    </div>
    <div class="card">
      <table class="table">
        <thead>
          <tr><th>Name</th><th>Connection</th><th>DB</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    `
    )
  );
});

app.get("/atlas/new", auth, (req, res) => {
  res.send(
    layout(
      "New Atlas Cluster",
      `
    <h1>Add MongoDB Atlas Cluster</h1>
    <div class="card">
      <p class="muted">Paste your Atlas connection string from cloud.mongodb.com → Connect → Drivers.</p>
      <form method="post" action="/atlas">
        <label>Cluster Name</label>
        <input class="input" name="name" required placeholder="my-cluster">

        <label>Connection String (mongodb+srv://...)</label>
        <input class="input" name="connectionString" required placeholder="mongodb+srv://user:pass@cluster.mongodb.net/" style="font-family:monospace">

        <label>Default Database (optional)</label>
        <input class="input" name="database" placeholder="mydb">

        <button class="btn">Add Cluster</button>
        <a class="btn gray" href="/atlas">Cancel</a>
      </form>
    </div>
    `
    )
  );
});

app.post("/atlas", auth, (req, res) => {
  const name = safeName(req.body.name);
  const connectionString = String(req.body.connectionString || "").trim();
  const database = String(req.body.database || "").trim();

  if (!name) return res.status(400).send(errorPage("Atlas", "Name required"));
  if (!/^mongodb(\+srv)?:\/\//.test(connectionString)) {
    return res
      .status(400)
      .send(errorPage("Atlas", "Invalid MongoDB connection string"));
  }

  const list = readAtlas();
  if (list.some((x) => x.name === name)) {
    return res.status(400).send(errorPage("Atlas", "Name exists"));
  }

  list.push({
    id: crypto.randomUUID(),
    name,
    connectionString: encrypt(connectionString),
    database,
    status: "Unknown",
    createdAt: new Date().toISOString()
  });

  saveAtlas(list);
  audit(req, "CREATE_ATLAS", name);
  res.redirect("/atlas");
});

app.post("/atlas/:id/test", auth, async (req, res) => {
  const list = readAtlas();
  const c = list.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).send("Not found");

  const uri = decrypt(c.connectionString);

  try {
    const { MongoClient } = require("mongodb");
    const client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000
    });
    await client.connect();
    const admin = client.db(c.database || "admin").admin();
    const info = await admin.serverInfo();
    const dbList = await admin.listDatabases();
    const stats = dbList.databases.map((d) => ({
      name: d.name,
      sizeMB: Math.round((d.sizeOnDisk || 0) / 1024 / 1024)
    }));
    await client.close();

    c.status = "Connected";
    c.lastTest = new Date().toISOString();
    saveAtlas(list);

    return res.send(
      layout(
        "Atlas Test",
        `<div class="card">
          <h2 class="ok">✅ Connected: ${esc(c.name)}</h2>
          <p>MongoDB version: <code>${esc(info.version)}</code></p>
          <h3>Databases (${stats.length})</h3>
          <table class="table">
            <thead><tr><th>Name</th><th>Size (MB)</th></tr></thead>
            <tbody>
              ${stats
                .map(
                  (d) =>
                    `<tr><td>${esc(d.name)}</td><td>${d.sizeMB}</td></tr>`
                )
                .join("")}
            </tbody>
          </table>
          <br>
          <a class="btn gray" href="/atlas">Back</a>
        </div>`
      )
    );
  } catch (e) {
    c.status = "Failed";
    c.lastError = e.message;
    saveAtlas(list);

    return res.send(
      layout(
        "Atlas Test",
        `<div class="card">
          <h2 class="err">❌ Failed: ${esc(c.name)}</h2>
          <pre>${esc(e.message)}</pre>
          <a class="btn gray" href="/atlas">Back</a>
        </div>`
      )
    );
  }
});

app.get("/atlas/:id/browse", auth, async (req, res) => {
  const list = readAtlas();
  const c = list.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).send("Not found");

  try {
    const { MongoClient } = require("mongodb");
    const client = new MongoClient(decrypt(c.connectionString), {
      serverSelectionTimeoutMS: 10000
    });
    await client.connect();
    const admin = client.db(c.database || "admin").admin();
    const dbList = await admin.listDatabases();
    await client.close();

    const rows = dbList.databases
      .map(
        (d) => `
        <tr>
          <td><a href="/atlas/${encodeURIComponent(
            c.id
          )}/db/${encodeURIComponent(d.name)}">${esc(d.name)}</a></td>
          <td>${Math.round((d.sizeOnDisk || 0) / 1024 / 1024)} MB</td>
        </tr>`
      )
      .join("");

    res.send(
      layout(
        "Atlas Browse",
        `<h1>Cluster: ${esc(c.name)}</h1>
        <div class="card">
          <table class="table">
            <thead><tr><th>Database</th><th>Size</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
          <br>
          <a class="btn gray" href="/atlas">Back</a>
        </div>`
      )
    );
  } catch (e) {
    res.status(400).send(errorPage("Browse failed", e.message));
  }
});

app.get("/atlas/:id/edit", auth, (req, res) => {
  const c = readAtlas().find((x) => x.id === req.params.id);
  if (!c) return res.status(404).send("Not found");

  res.send(
    layout(
      "Edit Atlas",
      `<h1>Edit: ${esc(c.name)}</h1>
      <div class="card">
        <form method="post" action="/atlas/${encodeURIComponent(c.id)}/edit">
          <label>Name</label>
          <input class="input" name="name" value="${esc(c.name)}" required>

          <label>Connection String (blank = keep current)</label>
          <input class="input" name="connectionString" placeholder="mongodb+srv://..." style="font-family:monospace">

          <label>Default Database</label>
          <input class="input" name="database" value="${esc(c.database || "")}">

          <button class="btn">Save</button>
          <a class="btn gray" href="/atlas">Cancel</a>
        </form>
      </div>`
    )
  );
});

app.post("/atlas/:id/edit", auth, (req, res) => {
  const list = readAtlas();
  const c = list.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).send("Not found");

  c.name = safeName(req.body.name);
  c.database = String(req.body.database || "").trim();

  const newConn = String(req.body.connectionString || "").trim();
  if (newConn) {
    if (!/^mongodb(\+srv)?:\/\//.test(newConn)) {
      return res.status(400).send(errorPage("Atlas", "Invalid connection string"));
    }
    c.connectionString = encrypt(newConn);
    c.status = "Unknown";
  }

  saveAtlas(list);
  audit(req, "UPDATE_ATLAS", c.name);
  res.redirect("/atlas");
});

app.post("/atlas/:id/delete", auth, (req, res) => {
  const list = readAtlas();
  const c = list.find((x) => x.id === req.params.id);
  saveAtlas(list.filter((x) => x.id !== req.params.id));
  audit(req, "DELETE_ATLAS", c?.name || req.params.id);
  res.redirect("/atlas");
});

/* TEST ROUTE — Debug */
app.get("/testxyz", (req, res) => {
  res.send("TEST ROUTE WORKS!");
});


/* =========================================================
   MONGODB ATLAS — HELPERS
   Yeh functions saare /atlas routes se PEHLE hone chahiye
========================================================= */

const ATLAS_FILE = path.join(DATA_ROOT, "atlas-clusters.json");
if (!fs.existsSync(ATLAS_FILE)) fs.writeFileSync(ATLAS_FILE, "[]");

function readAtlas() {
  return readJson(ATLAS_FILE, []);
}

function saveAtlas(list) {
  writeJson(ATLAS_FILE, list);
}

async function getAtlasClient(id) {
  const list = readAtlas();
  const c = list.find((x) => x.id === id);
  if (!c) throw new Error("Cluster not found");

  const uri = decrypt(c.connectionString);
  const { MongoClient } = require("mongodb");
  const client = new MongoClient(uri, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000
  });
  await client.connect();
  return { client, cluster: c };
}

/* =========================================================
   ADVANCED BACKEND SERVER MANAGER
   Node, Python, Go, Bun, Deno, PHP, Ruby support
========================================================= */

const BACKENDS_FILE = path.join(DATA_ROOT, "backends.json");
const BACKEND_LOG_DIR = path.join(DATA_ROOT, "backend-logs");
const BACKEND_ENV_DIR = path.join(DATA_ROOT, "backend-env");
const PROCESS_PIDS_FILE = path.join(DATA_ROOT, "backend-pids.json");

for (const d of [BACKEND_LOG_DIR, BACKEND_ENV_DIR]) {
  fs.mkdirSync(d, { recursive: true });
}
if (!fs.existsSync(BACKENDS_FILE)) fs.writeFileSync(BACKENDS_FILE, "[]");
if (!fs.existsSync(PROCESS_PIDS_FILE)) fs.writeFileSync(PROCESS_PIDS_FILE, "{}");

const RUNNER_TYPES = {
  node:   { cmd: "node",     ext: ".js",  env: "PORT" },
  python: { cmd: "python3",  ext: ".py",  env: "PORT" },
  go:     { cmd: "./app",    ext: "",     env: "PORT" },
  bun:    { cmd: "bun",      ext: ".ts",  env: "PORT" },
  deno:   { cmd: "deno",     ext: ".ts",  env: "PORT" },
  php:    { cmd: "php",      ext: ".php", env: "PORT" },
  ruby:   { cmd: "ruby",     ext: ".rb",  env: "PORT" },
  custom: { cmd: "",         ext: "",     env: "PORT" }
};

function readBackends() { return readJson(BACKENDS_FILE, []); }
function saveBackends(list) { writeJson(BACKENDS_FILE, list); }
function readPids() { return readJson(PROCESS_PIDS_FILE, {}); }
function savePids(map) { writeJson(PROCESS_PIDS_FILE, map); }
function backendLogPath(id) { return path.join(BACKEND_LOG_DIR, `${safeName(id)}.log`); }
function backendEnvPath(id) { return path.join(BACKEND_ENV_DIR, `${safeName(id)}.env`); }

function isPidAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function defaultEntry(runtime) {
  return {
    node: "index.js", python: "main.py", bun: "index.ts",
    deno: "index.ts", go: "app", php: "index.php",
    ruby: "app.rb", custom: "start.sh"
  }[runtime] || "index.js";
}

function defaultEntryContent(runtime, port) {
  if (runtime === "node" || runtime === "bun")
    return `const http = require("http");
const port = Number(process.env.PORT || ${port});
http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true, time: new Date().toISOString(), port }));
}).listen(port, "0.0.0.0", () => console.log("Running on " + port));
`;
  if (runtime === "python")
    return `import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "time": datetime.now().isoformat()}).encode())

port = int(os.getenv("PORT", ${port}))
HTTPServer(("0.0.0.0", port), H).serve_forever()
`;
  if (runtime === "deno")
    return `Deno.serve({ port: Number(Deno.env.get("PORT") || ${port}) }, () =>
  new Response(JSON.stringify({ ok: true, time: new Date().toISOString() }), {
    headers: { "Content-Type": "application/json" }
  })
);
`;
  if (runtime === "php")
    return `<?php
header("Content-Type: application/json");
echo json_encode(["ok" => true, "time" => date("c")]);
`;
  return `#!/usr/bin/env bash
echo "Custom backend"
`;
}

/* ---------- START BACKEND ---------- */
async function startBackend(b) {
  const pids = readPids();
  if (pids[b.id] && isPidAlive(pids[b.id])) {
    return { ok: true, pid: pids[b.id], alreadyRunning: true };
  }

  const logFile = backendLogPath(b.id);
  const output = fs.openSync(logFile, "a");

  const envVars = {};
  try {
    const envText = await fsp.readFile(backendEnvPath(b.id), "utf8");
    envText.split("\n")
      .filter((l) => l.trim() && !l.trim().startsWith("#"))
      .forEach((l) => {
        const idx = l.indexOf("=");
        if (idx > 0) envVars[l.slice(0, idx).trim()] = l.slice(idx + 1).trim();
      });
  } catch {}

  const runner = RUNNER_TYPES[b.runtime] || RUNNER_TYPES.node;
  let cmd, args;

  if (b.runtime === "custom") {
    cmd = b.customCommand.split(" ")[0];
    args = b.customCommand.split(" ").slice(1);
  } else {
    cmd = runner.cmd;
    args = [b.entry || `app${runner.ext}`];
    if (b.runtime === "deno") args.unshift("run", "--allow-all");
  }

  const child = spawn(cmd, args, {
    cwd: b.root,
    env: { ...process.env, ...envVars, [runner.env]: String(b.port), NODE_ENV: "production" },
    detached: true,
    stdio: ["ignore", output, output]
  });
  child.unref();

  pids[b.id] = child.pid;
  savePids(pids);

  const list = readBackends();
  const idx = list.findIndex((x) => x.id === b.id);
  if (idx !== -1) {
    list[idx].status = "running";
    list[idx].pid = child.pid;
    list[idx].startedAt = new Date().toISOString();
    saveBackends(list);
  }

  child.on("exit", (code) => {
    const pids2 = readPids();
    delete pids2[b.id];
    savePids(pids2);
    const list2 = readBackends();
    const i2 = list2.findIndex((x) => x.id === b.id);
    if (i2 !== -1) {
      list2[i2].status = "stopped";
      list2[i2].pid = null;
      list2[i2].lastExit = code;
      saveBackends(list2);
      if (list2[i2].autoRestart) {
        setTimeout(() => {
          const b2 = readBackends().find((x) => x.id === b.id);
          if (b2 && b2.autoRestart) startBackend(b2).catch(() => {});
        }, 3000);
      }
    }
  });

  return { ok: true, pid: child.pid };
}

/* ---------- STOP BACKEND ---------- */
async function stopBackend(id) {
  const pids = readPids();
  const pid = pids[id];
  if (pid && isPidAlive(pid)) {
    try { process.kill(-pid, "SIGTERM"); }
    catch { try { process.kill(pid, "SIGTERM"); } catch {} }
    setTimeout(() => { try { process.kill(pid, "SIGKILL"); } catch {} }, 5000);
  }
  delete pids[id];
  savePids(pids);
  const list = readBackends();
  const i = list.findIndex((x) => x.id === id);
  if (i !== -1) {
    list[i].status = "stopped";
    list[i].pid = null;
    list[i].autoRestart = false;
    saveBackends(list);
  }
  return { ok: true };
}

/* ---------- BACKENDS LIST ---------- */
app.get("/backends", auth, (req, res) => {
  const list = readBackends();
  const pids = readPids();
  for (const b of list) {
    const alive = pids[b.id] && isPidAlive(pids[b.id]);
    b.status = alive ? "running" : "stopped";
    b.pid = alive ? pids[b.id] : null;
  }

  const rows = list.length
    ? list.map((b) => `
    <tr>
      <td>
        <strong>${esc(b.name)}</strong><br>
        <span class="muted small">${esc(b.runtime)} • port ${b.port}</span>
      </td>
      <td>
        <span class="badge">${b.status === "running" ? "🟢 Running" : "🔴 Stopped"}</span>
        ${b.pid ? `<br><span class="muted small">PID: ${b.pid}</span>` : ""}
      </td>
      <td>${esc(b.domain || "-")}</td>
      <td>
        <div class="actions">
          ${b.status === "running"
            ? `<form method="post" action="/backends/${encodeURIComponent(b.id)}/stop" style="display:inline"><button class="btn red">Stop</button></form>
               <form method="post" action="/backends/${encodeURIComponent(b.id)}/restart" style="display:inline"><button class="btn gray">Restart</button></form>`
            : `<form method="post" action="/backends/${encodeURIComponent(b.id)}/start" style="display:inline"><button class="btn green">Start</button></form>`
          }
          <a class="btn gray" href="/backends/${encodeURIComponent(b.id)}/logs">Logs</a>
          <a class="btn gray" href="/backends/${encodeURIComponent(b.id)}/env">ENV</a>
          <a class="btn gray" href="/backends/${encodeURIComponent(b.id)}/edit">Edit</a>
          <form method="post" action="/backends/${encodeURIComponent(b.id)}/delete" style="display:inline" onsubmit="return confirm('Delete?')">
            <button class="btn red">Del</button>
          </form>
        </div>
      </td>
    </tr>`).join("")
    : `<tr><td colspan="4" class="muted">No backends yet.</td></tr>`;

  res.send(layout("Backend Servers", `
    <div class="actions" style="justify-content:space-between">
      <div>
        <h1>Backend Servers</h1>
        <p class="muted">Advanced process manager for Node, Python, Go, Bun, Deno, PHP, Ruby.</p>
      </div>
      <div>
        <form method="post" action="/backends/start-all" style="display:inline">
          <button class="btn green">Start All</button>
        </form>
        <form method="post" action="/backends/stop-all" style="display:inline">
          <button class="btn red">Stop All</button>
        </form>
        <a class="btn" href="/backends/new">+ New Backend</a>
      </div>
    </div>
    <div class="card">
      <table class="table">
        <thead><tr><th>Name</th><th>Status</th><th>Domain</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `));
});

/* ---------- NEW BACKEND FORM ---------- */
app.get("/backends/new", auth, (req, res) => {
  res.send(layout("New Backend", `
    <h1>Create Backend Server</h1>
    <div class="card">
      <form method="post" action="/backends">
        <label>Name</label>
        <input class="input" name="name" required placeholder="myapi">

        <label>Runtime</label>
        <select class="input" name="runtime">
          <option value="node">Node.js</option>
          <option value="python">Python 3</option>
          <option value="bun">Bun</option>
          <option value="deno">Deno</option>
          <option value="go">Go binary</option>
          <option value="php">PHP</option>
          <option value="ruby">Ruby</option>
          <option value="custom">Custom command</option>
        </select>

        <label>Project Directory</label>
        <input class="input" name="root" required placeholder="/var/www/backends/myapi">

        <label>Entry File</label>
        <input class="input" name="entry" placeholder="index.js">

        <label>Custom Command (runtime=custom only)</label>
        <input class="input" name="customCommand" placeholder="./start.sh">

        <label>Port</label>
        <input class="input" name="port" type="number" required placeholder="4000" min="1024" max="65535">

        <label>Domain (optional)</label>
        <input class="input" name="domain" placeholder="api.example.com">

        <label><input type="checkbox" name="autoRestart" checked> Auto-restart on crash</label>
        <br>
        <label><input type="checkbox" name="autoStart"> Auto-start on panel boot</label>

        <br><br>
        <button class="btn">Create Backend</button>
        <a class="btn gray" href="/backends">Cancel</a>
      </form>
    </div>
  `));
});

/* ---------- CREATE BACKEND ---------- */
app.post("/backends", auth, async (req, res) => {
  try {
    const name = safeName(req.body.name);
    const runtime = String(req.body.runtime || "node");
    const root = String(req.body.root || "").trim();
    const entry = String(req.body.entry || "").trim();
    const port = Number(req.body.port);
    const domain = String(req.body.domain || "").trim().toLowerCase();
    const autoRestart = req.body.autoRestart === "on";
    const autoStart = req.body.autoStart === "on";
    const customCommand = String(req.body.customCommand || "").trim();

    if (!name) throw new Error("Name required");
    if (!root) throw new Error("Root required");
    if (!port || port < 1024 || port > 65535) throw new Error("Invalid port");
    if (domain && !validDomain(domain)) throw new Error("Invalid domain");

    const list = readBackends();
    if (list.some((x) => x.name === name)) throw new Error("Name exists");

    await fsp.mkdir(root, { recursive: true });

    const backend = {
      id: crypto.randomUUID(),
      name, runtime,
      root: path.resolve(root),
      entry: entry || defaultEntry(runtime),
      customCommand, port, domain, autoRestart, autoStart,
      status: "stopped",
      createdAt: new Date().toISOString()
    };

    const entryPath = path.join(backend.root, backend.entry);
    if (!fs.existsSync(entryPath) && runtime !== "custom") {
      await fsp.writeFile(entryPath, defaultEntryContent(runtime, port));
    }

    const envPath = backendEnvPath(backend.id);
    if (!fs.existsSync(envPath)) {
      await fsp.writeFile(envPath, `PORT=${port}\nNODE_ENV=production\n`);
    }

    list.push(backend);
    saveBackends(list);

    if (autoStart) await startBackend(backend);

    audit(req, "CREATE_BACKEND", `${name} (${runtime}:${port})`);
    res.redirect("/backends");
  } catch (e) {
    res.status(400).send(errorPage("Backend error", e.message));
  }
});

/* ---------- START/STOP/RESTART ---------- */
app.post("/backends/:id/start", auth, async (req, res) => {
  try {
    const b = readBackends().find((x) => x.id === req.params.id);
    if (!b) throw new Error("Not found");
    await startBackend(b);
    audit(req, "START_BACKEND", b.name);
    res.redirect("/backends");
  } catch (e) { res.status(400).send(errorPage("Start failed", e.message)); }
});

app.post("/backends/:id/stop", auth, async (req, res) => {
  try {
    const b = readBackends().find((x) => x.id === req.params.id);
    if (!b) throw new Error("Not found");
    await stopBackend(b.id);
    audit(req, "STOP_BACKEND", b.name);
    res.redirect("/backends");
  } catch (e) { res.status(400).send(errorPage("Stop failed", e.message)); }
});

app.post("/backends/:id/restart", auth, async (req, res) => {
  try {
    const b = readBackends().find((x) => x.id === req.params.id);
    if (!b) throw new Error("Not found");
    await stopBackend(b.id);
    await new Promise((r) => setTimeout(r, 800));
    await startBackend(b);
    audit(req, "RESTART_BACKEND", b.name);
    res.redirect("/backends");
  } catch (e) { res.status(400).send(errorPage("Restart failed", e.message)); }
});

app.post("/backends/start-all", auth, async (req, res) => {
  const list = readBackends();
  for (const b of list) {
    try { await startBackend(b); } catch (e) { console.error(e.message); }
  }
  audit(req, "START_ALL_BACKENDS");
  res.redirect("/backends");
});

app.post("/backends/stop-all", auth, async (req, res) => {
  const list = readBackends();
  for (const b of list) { try { await stopBackend(b.id); } catch {} }
  audit(req, "STOP_ALL_BACKENDS");
  res.redirect("/backends");
});

app.post("/backends/:id/delete", auth, async (req, res) => {
  try {
    const list = readBackends();
    const b = list.find((x) => x.id === req.params.id);
    if (!b) throw new Error("Not found");
    await stopBackend(b.id);
    saveBackends(list.filter((x) => x.id !== b.id));
    audit(req, "DELETE_BACKEND", b.name);
    res.redirect("/backends");
  } catch (e) { res.status(400).send(errorPage("Delete failed", e.message)); }
});

/* ---------- LOGS ---------- */
app.get("/backends/:id/logs", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  let content = "";
  try { content = await fsp.readFile(backendLogPath(b.id), "utf8"); } catch {}
  if (content.length > 100000) content = content.slice(-100000);

  res.send(layout("Backend Logs", `
    <h1>Logs: ${esc(b.name)}</h1>
    <div class="card">
      <div class="actions">
        <button class="btn" onclick="location.reload()">Refresh</button>
        <a class="btn gray" href="/backends">Back</a>
      </div>
      <pre id="logbox" style="max-height:600px;overflow:auto">${esc(content)}</pre>
    </div>
  `));
});

/* ---------- ENV EDITOR (ADVANCED KEY/VALUE) ---------- */
app.get("/backends/:id/env", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  const envVars = [];
  try {
    const envText = await fsp.readFile(backendEnvPath(b.id), "utf8");
    envText.split("\n").forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return;
      const idx = trimmed.indexOf("=");
      if (idx > 0) {
        envVars.push({
          key: trimmed.slice(0, idx).trim(),
          value: trimmed.slice(idx + 1).trim()
        });
      }
    });
  } catch {}

  const rows = envVars.length
    ? envVars.map((v) => `
    <tr>
      <td><code>${esc(v.key)}</code></td>
      <td>
        ${/key|secret|pass|token/i.test(v.key)
          ? `<span class="muted">●●●●●●●● (${v.value.length} chars)</span>`
          : `<code>${esc(v.value)}</code>`}
      </td>
      <td>
        <div class="actions">
          <form method="post" action="/backends/${encodeURIComponent(b.id)}/env/delete" style="display:inline" onsubmit="return confirm('Delete ${esc(v.key)}?')">
            <input type="hidden" name="key" value="${esc(v.key)}">
            <button class="btn red small">Delete</button>
          </form>
        </div>
      </td>
    </tr>`).join("")
    : `<tr><td colspan="3" class="muted">No variables. Add one below.</td></tr>`;

  res.send(layout("Backend ENV", `
    <div class="actions" style="justify-content:space-between">
      <div>
        <h1>Environment Variables</h1>
        <p class="muted">Backend: <strong>${esc(b.name)}</strong> • Runtime: ${esc(b.runtime)} • Port: ${b.port}</p>
      </div>
      <a class="btn gray" href="/backends">← Back</a>
    </div>

    <div class="card">
      <h3>Current Variables (${envVars.length})</h3>
      <table class="table">
        <thead><tr><th style="width:30%">KEY</th><th style="width:50%">VALUE</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>

    <div class="card">
      <h3>Add New Variable</h3>
      <form method="post" action="/backends/${encodeURIComponent(b.id)}/env/set">
        <div style="display:grid;grid-template-columns:1fr 2fr auto;gap:12px;align-items:end">
          <div>
            <label>Key</label>
            <input class="input" name="key" placeholder="DATABASE_URL" required pattern="[A-Za-z_][A-Za-z0-9_]*">
          </div>
          <div>
            <label>Value</label>
            <input class="input" name="value" placeholder="mongodb://..." required>
          </div>
          <div>
            <button class="btn">+ Add</button>
          </div>
        </div>
      </form>
    </div>

    <div class="card">
      <h3>Bulk Import / Export</h3>
      <form method="post" action="/backends/${encodeURIComponent(b.id)}/env/bulk">
        <label>Paste .env format (KEY=value)</label>
        <textarea class="input" name="envText" rows="10" style="font-family:monospace">${esc(envVars.map((v) => `${v.key}=${v.value}`).join("\n"))}</textarea>
        <p class="muted small">⚠️ Saving replaces ALL variables above.</p>
        <button class="btn">Save Bulk</button>
        <a class="btn gray" href="/backends/${encodeURIComponent(b.id)}/env/export">Download .env</a>
      </form>
    </div>
  `));
});

app.post("/backends/:id/env/set", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  const key = String(req.body.key || "").trim();
  const value = String(req.body.value || "").trim();

  if (!key) return res.status(400).send(errorPage("ENV", "Key required"));
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
    return res.status(400).send(errorPage("ENV", "Key must be alphanumeric"));

  let lines = [];
  try { lines = (await fsp.readFile(backendEnvPath(b.id), "utf8")).split("\n"); } catch {}

  lines = lines.filter((line) => {
    const t = line.trim();
    if (!t || t.startsWith("#")) return true;
    const idx = t.indexOf("=");
    if (idx <= 0) return true;
    return t.slice(0, idx).trim() !== key;
  });
  lines.push(`${key}=${value}`);

  await fsp.writeFile(backendEnvPath(b.id), lines.filter(Boolean).join("\n") + "\n", "utf8");
  audit(req, "SET_ENV_VAR", `${b.name}.${key}`);
  res.redirect(`/backends/${encodeURIComponent(b.id)}/env`);
});

app.post("/backends/:id/env/delete", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  const key = String(req.body.key || "").trim();
  if (!key) return res.status(400).send(errorPage("ENV", "Key required"));

  let lines = [];
  try { lines = (await fsp.readFile(backendEnvPath(b.id), "utf8")).split("\n"); } catch {}

  lines = lines.filter((line) => {
    const t = line.trim();
    if (!t || t.startsWith("#")) return true;
    const idx = t.indexOf("=");
    if (idx <= 0) return true;
    return t.slice(0, idx).trim() !== key;
  });

  await fsp.writeFile(backendEnvPath(b.id), lines.filter(Boolean).join("\n") + "\n", "utf8");
  audit(req, "DELETE_ENV_VAR", `${b.name}.${key}`);
  res.redirect(`/backends/${encodeURIComponent(b.id)}/env`);
});

app.post("/backends/:id/env/bulk", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  const valid = String(req.body.envText || "")
    .split("\n").map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && l.includes("="));

  await fsp.writeFile(backendEnvPath(b.id), valid.join("\n") + "\n", "utf8");
  audit(req, "BULK_ENV_UPDATE", b.name);
  res.redirect(`/backends/${encodeURIComponent(b.id)}/env`);
});

app.get("/backends/:id/env/export", auth, async (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  try {
    const envText = await fsp.readFile(backendEnvPath(b.id), "utf8");
    res.setHeader("Content-Disposition", `attachment; filename="${safeName(b.name)}.env"`);
    res.setHeader("Content-Type", "text/plain");
    res.send(envText);
  } catch {
    res.status(404).send("ENV not found");
  }
});

/* ---------- EDIT BACKEND ---------- */
app.get("/backends/:id/edit", auth, (req, res) => {
  const b = readBackends().find((x) => x.id === req.params.id);
  if (!b) return res.status(404).send("Not found");

  res.send(layout("Edit Backend", `
    <h1>Edit: ${esc(b.name)}</h1>
    <div class="card">
      <form method="post" action="/backends/${encodeURIComponent(b.id)}/edit">
        <label>Name</label>
        <input class="input" name="name" value="${esc(b.name)}" required>

        <label>Root</label>
        <input class="input" name="root" value="${esc(b.root)}" required>

        <label>Entry</label>
        <input class="input" name="entry" value="${esc(b.entry)}">

        <label>Port</label>
        <input class="input" name="port" type="number" value="${b.port}" required>

        <label>Domain</label>
        <input class="input" name="domain" value="${esc(b.domain || "")}">

        <label><input type="checkbox" name="autoRestart" ${b.autoRestart ? "checked" : ""}> Auto-restart</label>
        <br>
        <label><input type="checkbox" name="autoStart" ${b.autoStart ? "checked" : ""}> Auto-start on boot</label>

        <br><br>
        <button class="btn">Save</button>
        <a class="btn gray" href="/backends">Cancel</a>
      </form>
    </div>
  `));
});

app.post("/backends/:id/edit", auth, async (req, res) => {
  try {
    const list = readBackends();
    const b = list.find((x) => x.id === req.params.id);
    if (!b) throw new Error("Not found");

    b.name = safeName(req.body.name);
    b.root = path.resolve(String(req.body.root));
    b.entry = String(req.body.entry || defaultEntry(b.runtime));
    b.port = Number(req.body.port);
    b.domain = String(req.body.domain || "").trim().toLowerCase();
    b.autoRestart = req.body.autoRestart === "on";
    b.autoStart = req.body.autoStart === "on";

    saveBackends(list);
    audit(req, "UPDATE_BACKEND", b.name);
    res.redirect("/backends");
  } catch (e) {
    res.status(400).send(errorPage("Edit failed", e.message));
  }
});



/* =========================================================
   404 + ERROR HANDLERS
========================================================= */

app.use((req, res) => {
  res.status(404).send(
    layout(
      "404",
      `<div class="card">
        <h1>404</h1>
        <p class="muted">Page not found.</p>
        <a class="btn" href="/">Dashboard</a>
      </div>`
    )
  );
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  if (res.headersSent) return next(err);

  res
    .status(500)
    .send(
      errorPage("Server error", err.message || "Internal server error.")
    );
});

/* =========================================================
   START SERVER
========================================================= */

process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION:", err);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MyHosting Panel running on http://0.0.0.0:${PORT}`);
  console.log(`Dashboard: ${PANEL_PUBLIC_URL}`);
  console.log(`Health: ${PANEL_PUBLIC_URL}/health`);

  if (DEFAULT_ADMIN_PASSWORD === "CHANGE_ME_NOW") {
    console.warn("WARNING: Change ADMIN_PASSWORD in .env before production.");
  }
  if (JWT_SECRET === "CHANGE_ME_LONG_SECRET") {
    console.warn("WARNING: Change JWT_SECRET in .env before production.");
  }
});