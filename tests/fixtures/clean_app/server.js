// vuln_express와 같은 기능을 안전하게 구현한 앱. 발견이 하나도 없어야 한다.
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { execFile } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: ["https://shop.example.com"], credentials: true }));

const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;

function requireLogin(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).end();
  }
}

function requireAdmin(req, res, next) {
  return req.user && req.user.role === "admin" ? next() : res.status(403).end();
}

app.get("/api/orders/:id", requireLogin, async (req, res) => {
  const order = await db.orders.findOne({ where: { id: req.params.id, userId: req.user.id } });
  res.json(order);
});

app.delete("/admin/users/:id", requireLogin, requireAdmin, async (req, res) => {
  await db.users.destroy({ where: { id: req.params.id } });
  res.sendStatus(204);
});

app.post("/api/posts", requireLogin, async (req, res) => {
  const post = await db.posts.create({ title: req.body.title, userId: req.user.id });
  res.status(201).json(post);
});

app.get("/api/search", async (req, res) => {
  const rows = await db.query("SELECT * FROM products WHERE name = $1", [req.query.q]);
  res.json(rows);
});

app.get("/api/ping", (req, res) => {
  execFile("ping", ["-c", "1", String(req.query.host)], (err, out) => res.type("text").send(String(out)));
});

app.get("/welcome", (req, res) => {
  res.json({ message: "Welcome", name: req.query.name });
});

app.get("/me", requireLogin, (req, res) => {
  res.json(req.user);
});

app.post("/login", async (req, res) => {
  const user = await db.users.findOne({ where: { username: req.body.username } });
  if (!user || !(await user.checkPassword(req.body.password))) return res.status(401).end();
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "lax" });
  return res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "요청을 처리하지 못했어요." });
});

module.exports = { app, STRIPE_KEY };
