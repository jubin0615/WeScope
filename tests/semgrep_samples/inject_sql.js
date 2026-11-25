const express = require("express");
const app = express();
app.get("/users", async (req, res) => {
  // ruleid: inject-sql
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  // ruleid: inject-sql
  await pool.query("SELECT * FROM users WHERE id = " + req.params.id);
  // ok: inject-sql
  await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  // ruleid: inject-sql
  await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE a = ${req.body.a}`);
  res.json(rows);
});
