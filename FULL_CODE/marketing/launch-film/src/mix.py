"""Mix the soundtrack and mux it with a rendered film.

    python mix.py renders/saas_master.mp4 renders/MaskGuard_launch_master.mp4

Music: "Volatile Reaction", Kevin MacLeod (incompetech.com), CC BY 4.0. Sound effects: Mixkit free licence
(mixkit.co/license/#sfxFree). The effects are placed at the cue times the film exported (<video>.sfx.json).
"""

import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
SFX = {"whoosh": "1485", "whoosh2": "1489", "click": "1109", "click2": "1110", "pop": "2354", "pop2": "2357"}
GAIN = {"whoosh": 0.35, "whoosh2": 0.45, "click": 0.5, "click2": 0.35, "pop": 0.4, "pop2": 0.45}


def main(video: str, out: str) -> None:
    video_path = pathlib.Path(video)
    events = json.loads(video_path.with_suffix(".sfx.json").read_text())
    duration = float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", video]))
    inputs = ["-i", video, "-i", str(HERE / "audio" / "Volatile_Reaction.mp3")]
    for name in SFX.values():
        inputs += ["-i", str(HERE / "audio" / "sfx" / f"{name}.mp3")]
    names = list(SFX)
    parts = [f"[1:a]atrim=0:{duration:.2f},afade=t=in:d=0.6,afade=t=out:st={duration - 3:.2f}:d=3,volume=0.85[m]"]
    labels = ["[m]"]
    used = {}
    for k, (at, name) in enumerate(sorted(events)):
        if name not in SFX or at < 0 or at > duration:
            continue
        idx = 2 + names.index(name)
        used[idx] = used.get(idx, 0) + 1
        parts.append(f"[{idx}:a]volume={GAIN[name]},adelay={int(at * 1000)}|{int(at * 1000)}[e{k}]")
        labels.append(f"[e{k}]")
    # each effect input is used several times: split it first
    splits = []
    for idx, n in used.items():
        splits.append(f"[{idx}:a]asplit={n}" + "".join(f"[s{idx}_{j}]" for j in range(n)))
    counters = {idx: 0 for idx in used}
    rewritten = []
    for p in parts[1:]:
        idx = int(p[1 : p.index(":")])
        rewritten.append(p.replace(f"[{idx}:a]", f"[s{idx}_{counters[idx]}]", 1))
        counters[idx] += 1
    graph = ";".join(splits + [parts[0]] + rewritten)
    graph += ";" + "".join(labels) + f"amix=inputs={len(labels)}:normalize=0,loudnorm=I=-16:TP=-1.5:LRA=11[a]"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *inputs, "-filter_complex", graph, "-map", "0:v", "-map", "[a]",
                    "-c:v", "copy", "-c:a", "aac", "-b:a", "256k", "-ar", "48000", "-shortest", "-movflags", "+faststart", out], check=True)
    print("wrote", out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
