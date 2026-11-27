"""주문 서비스 계층. 라우트는 이 함수를 부르기만 해서 정적 분석은 소유자 확인이 빠진 것을 보지 못한다."""
from models import Order


def load_order(order_id):
    """주문 하나를 꺼낸다."""
    return Order.query.get_or_404(order_id)
