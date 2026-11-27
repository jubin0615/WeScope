"""업무 로직 취약점을 심은 Flask 앱 (ChatGPT 보완 탐지 벤치, AI.md §10). 정적 분석으로는 찾기 어려운 것만 있다.
`# ai-expect: <vuln_type>` 주석 다음 줄(또는 그 줄이 부르는 다른 파일)에서 보완 탐지가 그 유형을 찾아야 한다."""
from flask import Flask, jsonify, request
from flask_login import current_user, login_required

from models import Order, Product, db
from repo import search_products
from services import load_order

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def show_order(order_id):
    # ai-expect: idor
    order = load_order(order_id)
    return jsonify(order.to_dict())


@app.route("/profile", methods=["POST"])
@login_required
def update_profile():
    # ai-expect: mass-assignment
    for field, value in request.json.items():
        setattr(current_user, field, value)
    db.session.commit()
    return jsonify(ok=True)


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    product = Product.query.get_or_404(request.json["product_id"])
    quantity = int(request.json["quantity"])
    # ai-expect: price-tampering
    total = float(request.json["unit_price"]) * quantity
    order = Order(user_id=current_user.id, product_id=product.id, quantity=quantity, total=total, status="paid")
    db.session.add(order)
    db.session.commit()
    return jsonify(order_id=order.id, total=total)


@app.route("/search")
def search():
    return jsonify(search_products(request.args.get("q", "")))
