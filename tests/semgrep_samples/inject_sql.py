from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name")
    cur = sqlite3.connect("x.db").cursor()
    # ruleid: inject-sql
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: inject-sql
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: inject-sql
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ok: inject-sql
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    uid = int(request.args["id"])
    # ok: inject-sql
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")


@app.get("/items/{item_id}")
def item(item_id: str, db=None):
    # ruleid: inject-sql
    db.execute("SELECT * FROM items WHERE id = {}".format(item_id))
