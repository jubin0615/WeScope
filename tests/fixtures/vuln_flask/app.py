"""WS-01·02·05·06 취약점을 심은 Flask 앱. expect 주석 다음 줄에서 그 규칙이 잡혀야 한다."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import jwt
import requests
from flask import Flask, jsonify, redirect, request, send_file
from flask_cors import CORS
from flask_login import login_required

from models import Comment, Order, User, db

app = Flask(__name__)
# expect: config-weak-secret
app.config["SECRET_KEY"] = "dev"
# expect: config-cors-credentials
CORS(app, supports_credentials=True)

# expect: secret-hardcoded
OPENAI_API_KEY = "{{FAKE:openai}}"
# expect: secret-hardcoded
DATABASE_URL = "postgres://app:{{FAKE:password}}@db.internal:5432/app"


def get_db():
    return sqlite3.connect("shop.sqlite3")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # expect: inject-sql
    rows = get_db().execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'").fetchall()
    return jsonify(rows)


# expect: authz-idor
@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())


# expect: authz-admin-route
@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return "", 204


# expect: authz-no-auth-write
@app.route("/comments", methods=["POST"])
def add_comment():
    db.session.add(Comment(**request.json))
    db.session.commit()
    return "", 201


@app.route("/ping")
def ping():
    host = request.args["host"]
    # expect: inject-command
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/files")
def files():
    # expect: inject-path
    return send_file(os.path.join("uploads", request.args["name"]))


@app.route("/preview")
def preview():
    # expect: inject-ssrf, config-tls-verify-off
    return requests.get(request.args["url"], verify=False).text


@app.route("/import", methods=["POST"])
@login_required
def import_data():
    # expect: inject-deserialize
    data = pickle.loads(request.data)
    return jsonify(ok=bool(data))


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # expect: config-default-credential
    if username == "admin" and password == "admin":
        token = jwt.encode({"user": username}, app.config["SECRET_KEY"])
        resp = jsonify(ok=True)
        # expect: config-cookie-flags
        resp.set_cookie("session_token", token)
        return resp
    # expect: config-weak-hash
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify(ok=False, attempt=hashed)


@app.route("/next")
def go_next():
    # expect: inject-open-redirect
    return redirect(request.args.get("next"))


def verify_token(token):
    try:
        # expect: authz-jwt-no-verify
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        # expect: config-fail-open
        return True


@app.errorhandler(500)
def on_error(e):
    # expect: config-error-exposure
    return jsonify(error=str(e)), 500


# expect: config-security-todo
# TODO: add permission check before export goes live


if __name__ == "__main__":
    # expect: config-debug
    app.run(debug=True)
