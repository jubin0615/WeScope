"""정답지(bench/truth/<앱>.yml)와 We-Scope 결과(bench/results/<앱>.json)를 비교해 표를 만든다.

    python -I bench/compare.py <앱>  [앱 폴더]     → bench/results/<앱>.compare.md, 요약을 화면에

앱 폴더를 주고 정답지에 challenge_source가 있으면 그 파일의 챌린지가 정답지에 빠짐없이 들어갔는지도 확인한다.
"""
import fnmatch
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

from wescope.taxonomy.catalog import rules as catalog
from wescope.taxonomy.owasp import classify

BENCH = Path(__file__).parent
CLASSES = ("static", "logic", "runtime", "unsupported")
CLASS_KO = {"static": "정적 탐지 가능", "logic": "업무 로직", "runtime": "정적 불가(런타임·OSINT)", "unsupported": "지원 범위 밖"}


def locations(item):
    """(파일, 시작줄, 끝줄). line 0 = 파일 단위."""
    if not item.get("file"):
        return []
    locs = [(item["file"], item.get("line", 0), item.get("end", item.get("line", 0)))]
    for spot in item.get("also", []):
        file, line = spot.rsplit(":", 1)
        locs.append((file, int(line), int(line)))
    return locs


def matches(item, finding, tol):
    if finding["rule_id"] not in item["rules"]:
        return False
    where = finding["location"]
    return any(where["file"] == file and (start == 0 or start - tol <= where["line"] <= end + tol)
               for file, start, end in locations(item))


def verdict(verdicts, finding):
    for v in verdicts:
        if fnmatch.fnmatch(finding["rule_id"], v.get("rule", "*")) and fnmatch.fnmatch(finding["location"]["file"], v.get("file", "*")):
            return v
    return None


def check_truth(truth, folder):
    """정답지 자체의 실수를 먼저 잡는다: 없는 규칙 이름, 잘못된 구분, 빠지거나 겹친 챌린지."""
    known = set(catalog())
    ids = [i["id"] for i in truth["items"]]
    assert len(ids) == len(set(ids)), f"항목 id 중복: {[i for i, n in Counter(ids).items() if n > 1]}"
    assert set(truth.get("misses", {})) <= set(ids), f"misses에 없는 항목: {set(truth['misses']) - set(ids)}"
    for item in truth["items"]:
        assert item["static"] in CLASSES, f"{item['id']}: static 값이 잘못됨 {item['static']}"
        assert set(item["rules"]) <= known, f"{item['id']}: 없는 규칙 {set(item['rules']) - known}"
        assert item["static"] != "static" or item.get("file"), f"{item['id']}: 정적 항목은 파일이 있어야 함"
    covered = [c for i in truth["items"] for c in i.get("challenges", [])]
    # Juice Shop 챌린지는 항목 하나에만, PyGoat 실습(challenges_expected)은 취약점 여러 개를 가진다
    if truth.get("challenge_source"):
        assert len(covered) == len(set(covered)), f"챌린지가 두 항목에: {[c for c, n in Counter(covered).items() if n > 1]}"
    expected = set(truth.get("challenges_expected", []))
    if folder and truth.get("challenge_source"):
        source = yaml.safe_load((Path(folder) / truth["challenge_source"]).read_text(encoding="utf-8"))
        expected = {c["key"] for c in source}
    if expected:
        assert set(covered) == expected, f"빠진 챌린지 {expected - set(covered)}, 없는 챌린지 {set(covered) - expected}"
    return len(expected)


def compare(name, folder=None):
    truth = yaml.safe_load((BENCH / "truth" / f"{name}.yml").read_text(encoding="utf-8"))
    result = json.loads((BENCH / "results" / f"{name}.json").read_text(encoding="utf-8"))
    timing = json.loads((BENCH / "results" / f"{name}.timing.json").read_text(encoding="utf-8"))
    n_challenges = check_truth(truth, folder)
    tol = truth.get("tolerance", 3)
    findings = result["findings"]

    rows, used = [], set()
    for item in truth["items"]:
        hits = [k for k, f in enumerate(findings) if matches(item, f, tol)]
        used.update(hits)
        rows.append((item, [findings[k] for k in hits]))

    outside = []
    for k, f in enumerate(findings):
        if k in used:
            continue
        v = verdict(truth.get("verdicts", []), f)
        assert v is not None, f"판정 안 된 발견: {f['rule_id']} {f['location']['file']}:{f['location']['line']}"
        outside.append((f, v))

    static = [(i, h) for i, h in rows if i["static"] == "static"]
    challenge_static = [(i, h) for i, h in static if i.get("source") != "review"]
    found = sum(1 for _, h in static if h)
    found_ch = sum(1 for _, h in challenge_static if h)
    tp_key = len(used)
    count = Counter(v["verdict"] for _, v in outside)
    tp = tp_key + count["real"]
    summary = {
        "app": name, "commit": truth["commit"], "files": timing["files_scanned"], "elapsed_sec": timing["elapsed_sec"],
        "challenges": n_challenges, "items": len(rows), "by_class": dict(Counter(i["static"] for i, _ in rows)),
        "static_items": len(static), "static_found": found, "recall": round(found / len(static), 3) if static else None,
        "challenge_static_items": len(challenge_static), "challenge_static_found": found_ch,
        "findings": len(findings), "matched": tp_key, "real_outside": count["real"], "fp": count["fp"], "noise": count["noise"],
        "precision": round(tp / (tp + count["fp"]), 3) if tp + count["fp"] else None,
        "precision_noise_as_fp": round(tp / (tp + count["fp"] + count["noise"]), 3) if findings else None,
    }
    (BENCH / "results" / f"{name}.compare.md").write_text(render(truth, rows, outside, summary), encoding="utf-8")
    (BENCH / "results" / f"{name}.summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def status(item, hits, misses):
    if hits:
        where = ", ".join(sorted({f"{h['rule_id']} {h['location']['file'].rsplit('/', 1)[-1]}:{h['location']['line']}" for h in hits}))
        return "찾음", where
    if item["static"] != "static":
        return CLASS_KO[item["static"]], misses.get(item["id"], "")
    return "놓침", misses.get(item["id"]) or ("규칙 없음" if not item["rules"] else "규칙은 있지만 못 찾음")


def render(truth, rows, outside, s):
    out = [f"# {s['app']} 비교 결과", "",
           f"- 커밋 `{s['commit']}` · 검사한 파일 {s['files']}개 · 걸린 시간 {s['elapsed_sec']}초",
           f"- 정적 탐지 가능 항목 {s['static_items']}개 중 {s['static_found']}개 찾음 (탐지율 {s['recall']:.0%}); "
           f"챌린지·실습 근거 항목만 보면 {s['challenge_static_items']}개 중 {s['challenge_static_found']}개",
           f"- We-Scope 발견 {s['findings']}개 = 정답지 일치 {s['matched']} + 정답지 밖 실제 문제 {s['real_outside']} "
           f"+ 오탐 {s['fp']} + 예제·테스트 코드 {s['noise']} → 정밀도 {s['precision']:.0%} "
           f"(예제·테스트까지 오탐으로 치면 {s['precision_noise_as_fp']:.0%})", "",
           "## 정답지 항목", "",
           "| id | 취약점 | 위치 | CWE | OWASP 2025 | 구분 | 결과 | 근거·이유 |", "|---|---|---|---|---|---|---|---|"]
    order = {c: n for n, c in enumerate(CLASSES)}
    for item, hits in sorted(rows, key=lambda r: (order[r[0]["static"]], not r[1], r[0]["id"])):
        where = f"`{item['file']}:{item['line']}`" if item.get("file") and item.get("line") else (f"`{item['file']}`" if item.get("file") else "-")
        state, why = status(item, hits, truth.get("misses", {}))
        cwe = item.get("cwe") or "-"
        out.append(f"| {item['id']} | {item['title']} | {where} | {cwe} | {classify(item.get('cwe')) or '-'} | "
                   f"{CLASS_KO[item['static']]} | {state} | {why} |")
    out += ["", "## 정답지 밖 발견 판정", "", "| 판정 | 규칙 | 개수 | 예 | 이유 |", "|---|---|---|---|---|"]
    groups = {}
    for f, v in outside:
        groups.setdefault((v["verdict"], f["rule_id"], v["why"]), []).append(f)
    label = {"real": "실제 문제", "fp": "오탐", "noise": "예제·테스트"}
    for (kind, rule, why), fs in sorted(groups.items(), key=lambda g: ("real fp noise".split().index(g[0][0]), -len(g[1]))):
        example = f"`{fs[0]['location']['file']}:{fs[0]['location']['line']}`"
        out.append(f"| {label[kind]} | {rule} | {len(fs)} | {example} | {why} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    print(json.dumps(compare(*sys.argv[1:3]), ensure_ascii=False, indent=2))
