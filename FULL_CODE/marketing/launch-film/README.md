# MaskGuard launch film

A 90-second product film and a 60-second cutdown, made entirely in code: no screen recording, stock footage, samples
or templates. Every frame is a pure function of time, so a render is identical every time.

| File | What it is |
|---|---|
| `src/film.html` | The film: eight scenes drawn on one canvas, with the timings of both cuts (`#master`, `#cut`) |
| `src/render.js` | Renders frame by frame with headless Chromium (Playwright) and pipes the frames into ffmpeg |
| `src/sound.py` | Sound design, synthesised with NumPy and timed to the film's cue points |
| `src/plex-*.woff2` | IBM Plex Sans and Mono (SIL Open Font License 1.1, see `src/maskguard/web/fonts/OFL.txt`) |

## Build

```bash
cd FULL_CODE/marketing/launch-film/src
node render.js master ../renders/video_master.mp4        # 2,700 frames
node render.js cut ../renders/video_cut.mp4              # 1,800 frames
cd .. && uv run --project .. python src/sound.py renders/video_master.cues.json audio/mix_master.wav
ffmpeg -i renders/video_master.mp4 -i audio/mix_master.wav -c:v copy -af loudnorm=I=-16:TP=-1.5 -c:a aac -b:a 256k \
  -shortest renders/MaskGuard_launch_90s.mp4                   # same for the cut
node render.js master ../renders/still.mp4 --preview 42 80     # inspection stills at given seconds
```

Renders and audio files are not committed (`renders/`, `audio/` are ignored).

## Story

| Scene | Master | Cut | Message |
|---|---|---|---|
| Hook | 0–8 s | 0–5 s | Every database holds value; not every query should access it |
| Problem | 8–20 s | 5–14 s | One database, many users, different trust; masking the screen leaks through the query |
| Discovery | 20–34 s | 14–25 s | Column names lie; check digits + LightGBM + human review; 95.4% found on 9,780 unseen columns |
| Enforcement (hero) | 34–52 s | 25–40 s | One stored value, three answers by role; masked inside the database, before WHERE/JOIN/ORDER BY |
| Engines | 52–58 s | 40–44 s | One control plane for SQLite, PostgreSQL, MySQL; REST, CLI, SDK, wire proxy |
| Threat and audit | 58–70 s | 44–49 s | Enumeration alert (rules + IsolationForest); tamper-evident SHA-256 chain |
| Proof | 70–82 s | 49–56 s | 0/17 attacks leaked, 672 matrix cases, 35/35 columns, 1,320 tests |
| Brand | 82–90 s | 56–60 s | AI discovers. Policy authorizes. The database enforces. |

Every figure comes from the repository's evidence: `docs/AI_EVALUATION.md`, `docs/SECURITY_ANALYSIS.md`,
`docs/SAFFRON_VALIDATION.md`. The masked values shown are illustrative of the policy's actions (`mg_partial`,
`mg_token`), not a recorded query.

## Art direction

Charcoal ground, warm off-white type, one acid-lime accent for "protected", steel blue for systems, a warm red only for
leaks and alerts. IBM Plex Sans for headlines, Plex Mono for data. The motif is the product's own: a data cell and its
mask bar, a value morphing glyph by glyph into its masked form. Film grain and a vignette are drawn per frame.
