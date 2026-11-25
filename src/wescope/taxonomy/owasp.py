from functools import cache

from wescope.taxonomy.catalog import owasp_top10


@cache
def _index() -> dict[str, str]:
    index: dict[str, str] = {}
    for item in owasp_top10():
        for cwe in item["cwes"]:
            if cwe in index:
                raise ValueError(f"{cwe}가 {index[cwe]}와 {item['code']}에 모두 있어요")
            index[cwe] = item["code"]
    return index


def classify(cwe: str | None) -> str | None:
    """CWE → OWASP Top 10:2025 코드. 목록에 없으면 None("OWASP Top 10 범위 밖")."""
    return _index().get(cwe) if cwe else None
