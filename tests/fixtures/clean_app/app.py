"""vuln_flask와 같은 기능을 안전하게 구현한 앱. 발견이 하나도 없어야 한다 (오탐 0 기준)."""
import os
import sqlite3
import subprocess

import jwt
import requests
from flask import Flask, jsonify, redirect, request, send_from_directory, url_for
from flask_cors import CORS
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from auth import admin_required, make_token
from models import Comment, Order, User, db

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_SECURE"] = True
CORS(app, origins=["https://shop.example.com"], supports_credentials=True)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SOURCES = {"weather": "https://api.weather.example/v1/today"}


def get_db():
    return sqlite3.connect(os.environ.get("DB_PATH", "shop.sqlite3"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = get_db().execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return jsonify(rows)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    db.session.commit()
    return "", 204


@app.route("/comments", methods=["POST"])
@login_required
def add_comment():
    db.session.add(Comment(body=request.json["body"], user_id=current_user.id))
    db.session.commit()
    return "", 201


@app.route("/ping")
def ping():
    host = request.args["host"]
    return subprocess.check_output(["ping", "-c", "1", host])


@app.route("/files")
def files():
    return send_from_directory("uploads", secure_filename(request.args["name"]))


@app.route("/preview")
def preview():
    return requests.get(SOURCES[request.args["source"]], timeout=5).text


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user and check_password_hash(user.password_hash, request.form["password"]):
        resp = jsonify(ok=True)
        resp.set_cookie("session_token", make_token(user), secure=True, httponly=True, samesite="Lax")
        return resp
    return jsonify(ok=False), 401


@app.route("/next")
def go_next():
    return redirect(url_for("search"))


def verify_token(token):
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


@app.errorhandler(500)
def on_error(e):
    app.logger.exception("서버 오류")
    return jsonify(error="요청을 처리하지 못했어요."), 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
