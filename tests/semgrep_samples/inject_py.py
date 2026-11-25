# Semgrep 규칙 표본 (Python). "ruleid: X" 다음 줄은 잡혀야 하고, "ok: X" 다음 줄은 잡히면 안 된다.
import os
import pickle
import shlex
import subprocess

import jwt
import requests
import yaml
from flask import Flask, Markup, redirect, render_template_string, request, send_file, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    # ruleid: inject-code
    result = eval(expr)
    # ok: inject-code
    total = eval("1 + 2")
    return str(result + total)


@app.route("/ping")
def ping():
    host = request.args["host"]
    # ruleid: inject-command
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ruleid: inject-command
    os.system("ping " + host)
    # ok: inject-command
    subprocess.run(["ping", "-c", "1", host])
    # ok: inject-command
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    return "ok"


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: inject-xss
    page = Markup("<h1>" + name + "</h1>")
    # ruleid: inject-xss
    render_template_string("<p>" + name + "</p>")
    # ok: inject-xss
    render_template_string("<p>{{ name }}</p>", name=name)
    return page


@app.route("/download")
def download():
    filename = request.args["f"]
    # ruleid: inject-path
    data = open(os.path.join("files", filename)).read()
    # ruleid: inject-path
    send_file("files/" + filename)
    # ok: inject-path
    send_file(os.path.join("files", secure_filename(filename)))
    return data


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    # ruleid: inject-ssrf
    requests.get(url, timeout=5)
    # ok: inject-ssrf
    requests.get("https://api.example.com/status", timeout=5)
    # ok: inject-ssrf
    requests.get(SOURCES[request.args["source"]], timeout=5)
    return "ok"


SOURCES = {"weather": "https://api.weather.example/v1/today"}


@app.route("/load", methods=["POST"])
def load():
    # ruleid: inject-deserialize
    obj = pickle.loads(request.data)
    # ruleid: inject-deserialize
    cfg = yaml.load(request.data)
    # ok: inject-deserialize
    cfg2 = yaml.safe_load(request.data)
    # ok: inject-deserialize
    cfg3 = yaml.load(request.data, Loader=yaml.SafeLoader)
    return str((obj, cfg, cfg2, cfg3))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    # ruleid: inject-upload
    f.save(os.path.join("uploads", f.filename))
    # ok: inject-upload
    f.save(os.path.join("uploads", secure_filename(f.filename)))
    return "ok"


@app.route("/go")
def go():
    # ruleid: inject-open-redirect
    return redirect(request.args["next"])


@app.route("/home")
def home():
    # ok: inject-open-redirect
    return redirect(url_for("index"))


def read_token(token, key):
    # ruleid: authz-jwt-no-verify
    claims = jwt.decode(token, options={"verify_signature": False})
    # ruleid: authz-jwt-no-verify
    jwt.decode(token, key, algorithms=["none"])
    # ok: authz-jwt-no-verify
    jwt.decode(token, key, algorithms=["HS256"])
    return claims
