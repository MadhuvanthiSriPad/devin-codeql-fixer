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
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("better-sqlite3");

const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pingLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
});

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
// VULN 1: SQL Injection — string concatenation in query
// CodeQL rule: js/sql-injection
// ---------------------------------------------------------------------------
app.get("/api/users", (req, res) => {
  const search = req.query.search;
  const query = "SELECT * FROM users WHERE username LIKE '%" + search + "%'";
  try {
    const rows = db.prepare(query).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// VULN 2: Reflected XSS — user input echoed without encoding
// CodeQL rule: js/reflected-xss
// ---------------------------------------------------------------------------
app.get("/search", (req, res) => {
  const query = req.query.q;
  res.send(`
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <p>No results found.</p>
      </body>
    </html>
  `);
});

// ---------------------------------------------------------------------------
// VULN 3: Path Traversal — user-controlled file path
// CodeQL rule: js/path-injection
// ---------------------------------------------------------------------------
app.get("/api/files", (req, res) => {
  const filename = req.query.name;
  const filePath = path.join("/uploads", filename);
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    res.send(content);
  } catch (err) {
    res.status(404).json({ error: "File not found" });
  }
});

// ---------------------------------------------------------------------------
// VULN 4: Command Injection — user input in shell command
// CodeQL rule: js/command-line-injection
// ---------------------------------------------------------------------------
app.post("/api/ping", pingLimiter, (req, res) => {
  const host = req.body.host;
  try {
    const result = execFileSync("ping", ["-c", "1", host]).toString();
    res.json({ output: result });
  } catch (err) {
    res.status(500).json({ error: "Ping failed" });
  }
});

// ---------------------------------------------------------------------------
// VULN 5: Open Redirect — unvalidated redirect target
// CodeQL rule: js/server-side-unvalidated-url-redirection
// ---------------------------------------------------------------------------
app.get("/redirect", (req, res) => {
  const target = req.query.url;
  // Only allow relative paths that start with "/" and do not contain "//" or
  // a protocol-relative prefix, preventing open-redirect to external sites.
  if (typeof target !== "string" || !target.startsWith("/") || target.startsWith("//")) {
    return res.status(400).json({ error: "Invalid redirect URL" });
  }
  const parsed = new URL(target, `${req.protocol}://${req.get("host")}`);
  if (parsed.origin !== `${req.protocol}://${req.get("host")}`) {
    return res.status(400).json({ error: "Invalid redirect URL" });
  }
  res.redirect(parsed.pathname + parsed.search + parsed.hash);
});

// ---------------------------------------------------------------------------
// VULN 6: Hardcoded credentials
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
