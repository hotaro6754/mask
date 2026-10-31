"""Sound design for the launch film, synthesised from scratch (no samples, so no licences to track) and timed to the
film's own cue points (renders/<name>.cues.json, written by render.js).

    python sound.py renders/video_master.cues.json renders/audio_master.wav
"""

import json
import sys

import numpy as np

SR = 48_000
rng = np.random.default_rng(7)


def band_noise(n, lo, hi):
    """White noise limited to [lo, hi] Hz, by FFT."""
    spec = np.fft.rfft(rng.standard_normal(n))
    f = np.fft.rfftfreq(n, 1 / SR)
    spec[(f < lo) | (f > hi)] = 0
    out = np.fft.irfft(spec, n)
    return out / (np.abs(out).max() + 1e-9)


def env(n, attack, decay):
    t = np.arange(n) / SR
    return np.minimum(t / max(attack, 1e-4), 1) * np.exp(-t / decay)


def place(buf, sig, at, gain=1.0, pan=0.0):
    i = int(at * SR)
    if i >= len(buf):
        return
    sig = sig[: len(buf) - i] * gain
    buf[i : i + len(sig), 0] += sig * (1 - pan) ** 0.5
    buf[i : i + len(sig), 1] += sig * (1 + pan) ** 0.5


def impact(dur=1.6):
    n = int(dur * SR)
    t = np.arange(n) / SR
    freq = 32 + 58 * np.exp(-t * 9)  # pitch drop: the body of the hit
    body = np.sin(2 * np.pi * np.cumsum(freq) / SR) * env(n, 0.003, 0.45)
    click = band_noise(n, 1500, 7000) * env(n, 0.0005, 0.02)
    return body * 0.9 + click * 0.25


def whoosh(dur=1.0):
    n = int(dur * SR)
    t = np.linspace(0, 1, n)
    shape = np.sin(np.pi * t) ** 2
    return band_noise(n, 300, 5000) * shape * 0.35


def tick(freq=3200, dur=0.03):
    n = int(dur * SR)
    t = np.arange(n) / SR
    return np.sin(2 * np.pi * freq * t) * env(n, 0.0005, 0.006)


def tone(freqs, dur, attack, decay, gain=1.0):
    n = int(dur * SR)
    t = np.arange(n) / SR
    s = sum(np.sin(2 * np.pi * f * t + i) for i, f in enumerate(freqs)) / len(freqs)
    return s * env(n, attack, decay) * gain


def main(cue_path, out_path):
    cues = {name: (start, dur) for name, start, dur in json.load(open(cue_path, encoding="utf-8"))}
    total = max(s + d for s, d in cues.values())
    n = int((total + 0.5) * SR)
    mix = np.zeros((n, 2))
    t = np.arange(n) / SR

    def at(scene, p):
        s, d = cues[scene]
        return s + p * d

    # bed: sub drone and air, swelling into the enforcement scene, settling for the reveal
    e0, e1 = at("enforce", 0), at("enforce", 1)
    swell = 0.55 + 0.45 * np.clip((t - e0 + 6) / 6, 0, 1) * np.clip((e1 + 2 - t) / 2, 0, 1)
    drone = (np.sin(2 * np.pi * 41.2 * t) + 0.6 * np.sin(2 * np.pi * 55.0 * t + 1) + 0.25 * np.sin(2 * np.pi * 82.4 * t)) / 1.85
    drone *= 0.16 * swell * (0.8 + 0.2 * np.sin(2 * np.pi * 0.07 * t))
    air = band_noise(n, 2000, 9000) * 0.012 * swell
    mix[:, 0] += drone + air
    mix[:, 1] += drone + np.roll(air, 900)

    # pulse: 100 BPM eighths from the discovery scene to the proof, louder through enforcement
    beat = 60 / 100 / 2
    k = at("discovery", 0)
    while k < at("brand", 0):
        loud = 0.07 + (0.08 if e0 <= k <= e1 else 0)
        place(mix, tone([110, 220], 0.12, 0.002, 0.03), k, loud)
        k += beat

    # an impact on each scene, a whoosh across each cell wipe
    for i, (name, (s, d)) in enumerate(sorted(cues.items(), key=lambda kv: kv[1][0])):
        place(mix, impact(), s, 0.75 if name in ("enforce", "brand") else 0.5)
        if i:
            place(mix, whoosh(), s - 0.55, 0.7, pan=-0.3)

    # discovery: one scanner tick and a confirm tone per classified column
    for i in range(5):
        hit = at("discovery", 0.15 + 0.4 * (i * 0.17 + 0.075))
        place(mix, tick(2400 + i * 300), hit, 0.5, pan=-0.6 + i * 0.3)
        place(mix, tone([880, 1320], 0.25, 0.003, 0.08), hit + 0.02, 0.12)

    # enforcement: glyph clicks while each value morphs, a lock when it lands
    for lane in range(3):
        a, b = at("enforce", 0.45 + lane * 0.06), at("enforce", 0.6 + lane * 0.06)
        k = a
        while k < b:
            place(mix, tick(4200 + 900 * lane, 0.015), k, 0.18, pan=0.3)
            k += 0.045
        place(mix, tone([660, 990], 0.4, 0.002, 0.12), b, 0.2)

    # threat: the alert, a low warning
    place(mix, tone([233, 246], 1.2, 0.01, 0.4), at("threat", 0.42), 0.3)
    # proof: a soft hit on each number
    for i in range(4):
        place(mix, impact(1.0), at("proof", i / 4 + 0.01), 0.25)

    # brand signature: an open chord and one bright ping as the mask bar draws
    place(mix, tone([110, 164.8, 246.9, 261.6], 6.0, 0.4, 2.6, 0.5), at("brand", 0.12))
    place(mix, tone([1760, 2637], 1.5, 0.002, 0.35), at("brand", 0.3), 0.22)

    # master: gentle fades, soft limiting, normalise to -1 dBFS
    fade = np.clip(t / 1.0, 0, 1) * np.clip((total - t) / 1.5, 0, 1)
    mix *= fade[:, None]
    mix = np.tanh(mix * 1.6) / np.tanh(1.6)
    mix *= 0.89 / (np.abs(mix).max() + 1e-9)
    pcm = (mix * 32767).astype("<i2")
    import wave

    with wave.open(out_path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())
    print("wrote", out_path, f"{total:.1f} s")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
