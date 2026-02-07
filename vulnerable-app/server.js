/**
 * INTENTIONALLY VULNERABLE — for CodeQL demo purposes only.
 *
 * This Express app contains real-world vulnerability patterns that
 * CodeQL's JavaScript/TypeScript queries will flag.  Devin's job is
 * to fix each one with the correct industry-standard remediation.
 *
 * DO NOT deploy this code to production.
 */

const express = require("express");
const rateLimit = require("express-rate-limit");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("better-sqlite3");

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const db = new sqlite3("app.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    email TEXT,
    role TEXT DEFAULT 'user'
  )
`);

// ---------------------------------------------------------------------------
// VULN 1: SQL Injection (FIXED by Devin — parameterized query)
// Original: "SELECT * FROM users WHERE username LIKE '%" + search + "%'"
// ---------------------------------------------------------------------------
app.get("/api/users", apiLimiter, (req, res) => {
  const search = req.query.search;
  try {
    const rows = db.prepare("SELECT * FROM users WHERE username LIKE ?").all(
      "%" + search + "%"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// VULN 2: Reflected XSS (FIXED by Devin — HTML entity encoding)
// Original: res.send(`... ${query} ...`)  (raw user input in HTML)
// ---------------------------------------------------------------------------
function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

app.get("/search", (req, res) => {
  const query = req.query.q;
  const safeQuery = escapeHtml(query);
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${safeQuery}</p>
        <p>No results found.</p>
      </body>
    </html>
  `);
});

// ---------------------------------------------------------------------------
// VULN 3: Path Traversal (FIXED by Devin — canonical path + allowlist)
// Original: const filePath = "/uploads/" + filename  (no validation)
// ---------------------------------------------------------------------------
app.get("/api/files", apiLimiter, (req, res) => {
  const filename = req.query.name;
  const baseDir = path.resolve("/uploads");
  const filePath = path.resolve(baseDir, filename);
  if (!filePath.startsWith(baseDir + path.sep)) {
    return res.status(403).json({ error: "Access denied" });
  }
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    res.send(content);
  } catch (err) {
    res.status(404).json({ error: "File not found" });
  }
});

// ---------------------------------------------------------------------------
// VULN 4: Command Injection — user input in shell command (VULNERABLE)
// CodeQL rule: js/command-line-injection
// ---------------------------------------------------------------------------
app.post("/api/ping", (req, res) => {
  const host = req.body.host;
  if (typeof host !== "string" || !/^[a-zA-Z0-9._-]+$/.test(host)) {
    return res.status(400).json({ error: "Invalid host" });
  }
  try {
    const result = execFileSync("ping", ["-c", "1", host]).toString();
    res.json({ output: result });
  } catch (err) {
    res.status(500).json({ error: "Ping failed" });
  }
});

// ---------------------------------------------------------------------------
// VULN 5: Open Redirect — unvalidated redirect target (VULNERABLE)
// CodeQL rule: js/server-side-unvalidated-url-redirection
// ---------------------------------------------------------------------------
app.get("/redirect", (req, res) => {
  const target = req.query.url || "/";
  let parsed;
  try {
    parsed = new URL(target, "http://localhost");
  } catch (e) {
    return res.redirect("/");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return res.redirect("/");
  }
  if (parsed.hostname !== "localhost") {
    return res.redirect("/");
  }
  res.redirect(parsed.pathname + parsed.search + parsed.hash);
});

// ---------------------------------------------------------------------------
// VULN 6: Hardcoded Credentials — secrets in source code (VULNERABLE)
// CodeQL rule: js/hardcoded-credentials
// ---------------------------------------------------------------------------
const DB_PASSWORD = "super_secret_password_123";
const API_KEY = "sk-live-abc123def456ghi789";

app.get("/api/config", (req, res) => {
  res.json({
    database: { host: "db.example.com", password: DB_PASSWORD },
    apiKey: API_KEY,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
