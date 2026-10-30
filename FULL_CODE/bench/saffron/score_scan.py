import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[2])
from truth import TRUTH

rows = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
got = {(r["table"], r["column"]): r for r in rows}
assert set(got) == {(t, c) for t, cs in TRUTH.items() for c in cs}, set(got) ^ {
    (t, c) for t, cs in TRUTH.items() for c in cs
}
stat = {}
for (t, c), r in sorted(got.items()):
    truth = TRUTH[t][c]
    tagged = r["tag"] not in ("UNREVIEWED", "PUBLIC")
    outcome = "tagged" if tagged else ("suggested PUBLIC" if r.get("suggest") == "PUBLIC" else "unreviewed")
    stat.setdefault(truth, {}).setdefault(outcome, []).append(f"{t}.{c}")
    mark = {
        ("S", "tagged"): "OK ",
        ("S", "unreviewed"): "~  ",
        ("S", "suggested PUBLIC"): "MISS",
        ("N", "tagged"): "FP ",
    }.get((truth, outcome), "   ")
    print(
        f"{mark:4} {truth} {t + '.' + c:42} {r['tag']:24} {r.get('kind') or ''!s:14} {r.get('confidence') or ''!s:9} {(r.get('evidence') or '')[:60]}"
    )
print()
for k in "SQN":
    print(k, {o: len(v) for o, v in stat.get(k, {}).items()})
print("sensitive suggested PUBLIC:", stat.get("S", {}).get("suggested PUBLIC"))
print("sensitive left unreviewed:", stat.get("S", {}).get("unreviewed"))
print("not-personal tagged:", stat.get("N", {}).get("tagged"))
