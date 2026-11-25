// Semgrep 규칙 표본 (JavaScript). "ruleid: X" 다음 줄은 잡혀야 하고, "ok: X" 다음 줄은 잡히면 안 된다.
const express = require("express");
const { exec, execFile } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const session = require("express-session");
const multer = require("multer");

const app = express();
// ruleid: config-cors-wildcard
app.use(cors());
// ruleid: config-cors-credentials
app.use(cors({ origin: true, credentials: true }));
// ok: config-cors-wildcard
app.use(cors({ origin: ["https://my-app.com"] }));
// ruleid: config-weak-secret
app.use(session({ secret: "keyboard cat", resave: false }));
// ok: config-weak-secret
app.use(session({ secret: process.env.SESSION_SECRET }));

app.get("/calc", (req, res) => {
  // ruleid: inject-code
  const value = eval(req.query.expr);
  // ok: inject-code
  const fixed = eval("1 + 2");
  res.json({ value, fixed });
});

app.get("/ping", (req, res) => {
  // ruleid: inject-command
  exec("ping -c 1 " + req.query.host);
  // ok: inject-command
  execFile("ping", ["-c", "1", req.query.host]);
  res.send("ok");
});

app.get("/hello", (req, res) => {
  // ruleid: inject-xss
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.get("/json", (req, res) => {
  // ok: inject-xss
  res.json({ name: req.query.name });
});

app.get("/file", (req, res) => {
  // ruleid: inject-path
  fs.readFile("files/" + req.query.name, (e, d) => res.send(d));
  // ok: inject-path
  fs.readFile(path.join("files", path.basename(req.query.name)), (e, d) => res.send(d));
});

app.get("/proxy", async (req, res) => {
  // ruleid: inject-ssrf
  const r = await axios.get(req.query.url);
  // ok: inject-ssrf
  const s = await axios.get("https://api.example.com/status");
  res.json({ a: r.data, b: s.data });
});

app.get("/go", (req, res) => {
  // ruleid: inject-open-redirect
  res.redirect(req.query.next);
});

app.get("/home", (req, res) => {
  // ok: inject-open-redirect
  res.redirect("/");
});

app.post("/login", (req, res) => {
  const token = jwt.sign({ id: 1 }, process.env.JWT_SECRET);
  // ruleid: config-cookie-flags
  res.cookie("session", token);
  // ruleid: config-cookie-flags
  res.cookie("auth_token", token, { secure: true });
  // ok: config-cookie-flags
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
  // ok: config-cookie-flags
  res.cookie("theme", "dark");
  res.json({ ok: true });
});

function readUser(token) {
  // ruleid: authz-jwt-no-verify
  return jwt.decode(token);
}

function checkUser(token) {
  jwt.verify(token, process.env.JWT_SECRET);
  // ok: authz-jwt-no-verify
  return jwt.decode(token);
}

const storage = multer.diskStorage({
  destination: "uploads/",
  // ruleid: inject-upload
  filename: (req, file, cb) => cb(null, file.originalname),
});

module.exports = { app, readUser, checkUser, storage };
