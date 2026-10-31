# MaskGuard launch film

A 102-second product film and a 60-second cutdown. Editorial light direction: paper and ink, one ultramarine accent,
signal orange only where data leaks, graded monochrome footage, designed MaskGuard interface cards animated with GSAP.
No screen recording, no 3D, no watermarked assets.

## Files

| File | What it is |
|---|---|
| `src/saas.html` | The film: shots, styles and one GSAP timeline per cut (`#master`, `#cut`); `render(t)` seeks it |
| `src/render.js` | Renders any second of the film with headless Chromium (Playwright) and pipes frames into ffmpeg |
| `src/mix.py` | Mixes the music and the sound effects at the cue times the film exports, then muxes the audio |
| `src/film.html`, `src/film3d.html` | Earlier explorations (flat dark, 3D), kept for reference |
| `src/plex-*.woff2` | IBM Plex Mono for code and captions |

Footage frames (`renders/frames/`), audio files (`audio/`) and renders are rebuilt locally and not committed.

## Build

```bash
cd FULL_CODE/marketing/launch-film
npm install                                           # gsap, Inter, Lucide (and three.js for film3d.html)
# footage: download the five clips below into a folder, then for each id:
#   ffmpeg -ss 1 -t 7 -i <id>.mp4 -vf "fps=30,scale=1920:1080:force_original_aspect_ratio=increase,crop=1920:1080,
#     hue=s=0,eq=contrast=1.12:brightness=-0.02,colorbalance=rs=.06:gs=.02:bs=-.05:rh=.04:bh=-.03,noise=alls=6:allf=t"
#     -q:v 3 renders/frames/<id>/%04d.jpg
python3 -m http.server 8765 --bind 127.0.0.1 &
cd src && FILM=saas.html node render.js master ../renders/saas_master.mp4 && FILM=saas.html node render.js cut ../renders/saas_cut.mp4
cd .. && python3 src/mix.py renders/saas_master.mp4 renders/MaskGuard_launch_100s.mp4
python3 src/mix.py renders/saas_cut.mp4 renders/MaskGuard_launch_60s.mp4
FILM=saas.html node src/render.js master /tmp/still.mp4 --preview 12 60   # inspection stills
```

## Assets and licences

| Asset | Source | Licence | Attribution |
|---|---|---|---|
| Footage 35580 (silhouettes, glass corridor) | https://mixkit.co/free-stock-video/corporate/ | Mixkit Stock Video Free License (commercial use, no watermark) | Not required |
| Footage 38481 (card and tablet) | https://mixkit.co/free-stock-video/bank/ | Mixkit Stock Video Free License | Not required |
| Footage 24604 (safe-deposit box) | https://mixkit.co/free-stock-video/bank/ | Mixkit Stock Video Free License | Not required |
| Footage 47792 (data reflected in glasses) | https://mixkit.co/free-stock-video/glass/ | Mixkit Stock Video Free License | Not required |
| Footage 23282 (server corridor) | https://mixkit.co/free-stock-video/server/ | Mixkit Stock Video Free License | Not required |
| Sound effects 1485, 1489, 1109, 1110, 2354, 2357 | https://mixkit.co/free-sound-effects/ | Mixkit Sound Effects Free License | Not required |
| Music "Volatile Reaction", Kevin MacLeod | https://incompetech.com | CC BY 4.0 | **Required**: shown in the end card and here |
| Inter (variable) | `@fontsource-variable/inter` | SIL Open Font License 1.1 | Not required |
| IBM Plex Mono | `src/maskguard/web/fonts/` | SIL Open Font License 1.1 | Not required |
| Lucide icons | `lucide-static` | ISC | Not required |
| GSAP 3.12 | `gsap` | GreenSock Standard "no charge" license | Not required |

## Story

| Shot | Master | Message |
|---|---|---|
| Footage ×3 | 0–13 s | Every bank runs on data; names, PANs, cards, balances; everyone gets the same key |
| Table | 13–21 s | Every query sees everything: support, analyst and contractor all receive every column |
| Leak | 21–29 s | Hiding it on screen isn't enough: `WHERE pan LIKE 'ABCPK%'` still learns the value |
| Meet | 29–35 s | MaskGuard |
| Discover | 35–47 s | A scan finds personal columns behind misleading names; 95.4% on 9,780 unseen columns |
| Decide | 47–54 s | The real default policy: role × sensitivity → allow, partial, hmac, aggregate, redact |
| Footage | 54–58.5 s | Masked inside the database |
| Enforce (hero) | 58.5–72.5 s | One query, three answers: `ABCPK1234F`, `ABXXXXXXXF`, an HMAC token (the product's real masks) |
| Drop in | 72.5–78.5 s | SQLite, PostgreSQL, MySQL; REST, CLI, SDK, wire proxy; offline on a CPU |
| Prove | 78.5–86.5 s | Enumeration alert; SHA-256 audit chain |
| Proof | 86.5–94.5 s | 0/17 leaks, 672 matrix cases, 35/35 columns, 1,320 tests |
| End | 94.5–102.5 s | Find. Hide. Prove. `pip install maskguard` |

Every figure and every masked value comes from the repository: `docs/AI_EVALUATION.md`, `docs/SECURITY_ANALYSIS.md`,
`docs/SAFFRON_VALIDATION.md`, `policies/default.yaml`.
