"""ChatGPT 응답 캐시 (llm/cache.py): 형식이 맞는 응답만 남긴다. 틀린 응답을 남기면 코드가 바뀌기 전까지 같은 실패가 반복된다."""
from wescope.llm.cache import Session


class Client:
    model = "fake"

    def __init__(self, answers):
        self.answers, self.asked = list(answers), 0

    def ask(self, instructions, payload, effort):
        self.asked += 1
        return self.answers.pop(0)


def ok(answer):
    return isinstance(answer.get("findings"), list)


def test_malformed_answer_is_not_cached():
    client = Client([{"error": "busy"}, {"findings": []}])
    first, _ = Session(client).ask("지시", "v1", {"code": 1}, "high", valid=ok)
    second, _ = Session(client).ask("지시", "v1", {"code": 1}, "high", valid=ok)
    assert first == {"error": "busy"} and second == {"findings": []} and client.asked == 2   # 다시 물었다
    third, _ = Session(client).ask("지시", "v1", {"code": 1}, "high", valid=ok)
    assert third == {"findings": []} and client.asked == 2                                  # 맞는 답은 캐시에서


def test_malformed_answer_already_in_cache_is_ignored():
    """이 변경 전에 캐시에 들어간 틀린 응답도 쓰지 않는다."""
    Session(Client([{"error": "busy"}])).ask("지시", "v1", {"code": 2}, "high")              # 검사 없이 저장
    client = Client([{"findings": []}])
    answer, _ = Session(client).ask("지시", "v1", {"code": 2}, "high", valid=ok)
    assert answer == {"findings": []} and client.asked == 1
