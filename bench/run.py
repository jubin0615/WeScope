"""We-Scope 정적 검사를 앱 폴더에 돌려 결과 JSON과 걸린 시간을 저장한다 (ChatGPT 분석 없음).

    python -I bench/run.py <앱 폴더> <이름>     → bench/results/<이름>.json, <이름>.timing.json

전체 결과는 <이름>.full.json (gitignore): evidence에 대상 앱의 비밀값이 가려지지 않은 채 들어갈 수 있어서
저장소에는 비교에 쓰는 rule_id·위치·심각도만 남긴다.
"""
import json
import sys
import time
from pathlib import Path

from wescope.collector.context import collect
from wescope.collector.snapshot import Target
from wescope.scan import run_scan


def main(folder: str, name: str):
    out = Path(__file__).parent / "results"
    target = Target("folder", folder)
    started = time.perf_counter()
    result = run_scan(target)
    elapsed = time.perf_counter() - started
    with collect(target) as ctx:   # 파일 수만 다시 센다 (검사 시간에는 넣지 않는다)
        files, all_files = len(ctx.files), len(ctx.all_files)
    (out / f"{name}.full.json").write_text(result.to_json(), encoding="utf-8")
    slim = [{"rule_id": f.rule_id, "severity": f.severity, "location": {"file": f.location.file, "line": f.location.line}}
            for f in result.findings]
    (out / f"{name}.json").write_text(json.dumps({"findings": slim}, ensure_ascii=False, indent=1), encoding="utf-8")
    timing = {"elapsed_sec": round(elapsed, 1), "files_scanned": files, "files_total": all_files,
              "findings": len(result.findings),
              "analyzers": {a.id: [a.status, round(a.elapsed, 1), a.note] for a in result.analyzers}}
    (out / f"{name}.timing.json").write_text(json.dumps(timing, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(timing, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:3])
