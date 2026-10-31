// Render film.html frame by frame with headless Chromium and pipe the frames into ffmpeg.
//   node render.js master|cut OUT.mp4 [--preview SECONDS...]
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const [cut, out, flag, ...stills] = process.argv.slice(2);
const FPS = 30;

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  await page.goto("file://" + path.join(__dirname, "film.html") + "#" + cut);
  await page.evaluate(() => window.ready);
  const duration = await page.evaluate(() => window.DURATION);
  fs.writeFileSync(out.replace(/\.mp4$/, ".cues.json"), JSON.stringify(await page.evaluate(() => window.CUES)));
  const canvas = await page.$("canvas");
  if (flag === "--preview") {  // single frames for inspection
    for (const s of stills) {
      await page.evaluate((t) => window.render(t), Number(s));
      await canvas.screenshot({ path: out.replace(/\.mp4$/, `_${s}.png`) });
    }
    await browser.close();
    return;
  }
  const ff = spawn("ffmpeg", ["-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", String(FPS), "-i", "-",
    "-c:v", "libx264", "-preset", "medium", "-crf", "17", "-pix_fmt", "yuv420p", "-movflags", "+faststart", out], { stdio: ["pipe", "inherit", "inherit"] });
  const frames = Math.round(duration * FPS);
  for (let f = 0; f < frames; f++) {
    await page.evaluate((t) => window.render(t), f / FPS);
    const buf = await canvas.screenshot({ type: "jpeg", quality: 95 });
    if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once("drain", r));
    if (f % 300 === 0) console.log(`${cut}: frame ${f}/${frames}`);
  }
  ff.stdin.end();
  await new Promise((r) => ff.on("close", r));
  await browser.close();
  console.log("wrote", out);
})();
