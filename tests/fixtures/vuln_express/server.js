// WS-01·02·05·06 취약점을 심은 Express 앱. expect 주석 다음 줄에서 그 규칙이 잡혀야 한다.
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
// expect: config-cors-wildcard
app.use(cors());
// expect: config-tls-verify-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// expect: secret-hardcoded
const STRIPE_KEY = "{{FAKE:stripe}}";

// expect: authz-idor
app.get("/api/orders/:id", async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  res.json(order);
});

// expect: authz-admin-route
app.delete("/admin/users/:id", requireLogin, async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.sendStatus(204);
});

// expect: authz-no-auth-write
app.post("/api/posts", async (req, res) => {
  const post = await db.posts.create(req.body);
  res.status(201).json(post);
});

app.get("/api/search", async (req, res) => {
  // expect: inject-sql
  const rows = await db.query(`SELECT * FROM products WHERE name = '${req.query.q}'`);
  res.json(rows);
});

app.get("/api/ping", (req, res) => {
  // expect: inject-command
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.type("text").send(String(out)));
});

app.get("/welcome", (req, res) => {
  // expect: inject-xss
  res.send(`<h1>Welcome ${req.query.name}</h1>`);
});

app.get("/me", (req, res) => {
  // expect: authz-jwt-no-verify
  const user = jwt.decode(req.headers.authorization);
  res.json(user);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // expect: config-default-credential
  if (username === "admin" && password === "password") {
    // expect: config-weak-secret
    const token = jwt.sign({ username }, "secret123");
    // expect: config-cookie-flags
    res.cookie("token", token);
    return res.json({ ok: true });
  }
  return res.status(401).end();
});

function requireLogin(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
    next();
  // expect: config-fail-open
  } catch (e) { next(); }
}

app.use((err, req, res, next) => {
  // expect: config-error-exposure
  res.status(500).json({ error: err.stack });
});

module.exports = { app, STRIPE_KEY };
