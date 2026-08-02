/**
 * Mục 2 — Crypto-only: đo riêng thời gian mã hóa / giải mã (ms).
 * Cùng AES-256-GCM + chunk 4MB như frontend LockSend (không upload mạng).
 *
 * Usage:
 *   node scripts/bench-crypto-only.mjs
 *   node scripts/bench-crypto-only.mjs --sizes 4,16,64 --runs 3
 */
import { createHash, randomBytes, webcrypto } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "fixtures", "crypto-only");
const subtle = webcrypto.subtle;
const CHUNK_SIZE = 4 * 1024 * 1024;

function parseArgs(argv) {
  const sizesIdx = argv.indexOf("--sizes");
  const runsIdx = argv.indexOf("--runs");
  const sizes = (sizesIdx >= 0 ? argv[sizesIdx + 1] : "4,16,64")
    .split(",")
    .map((s) => parseFloat(s.trim()))
    .filter((n) => n > 0);
  const runs = Math.max(1, parseInt(runsIdx >= 0 ? argv[runsIdx + 1] : "3", 10) || 3);
  return { sizes, runs };
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function buildChunkNonce(baseNonce, chunkIndex) {
  const nonce = new Uint8Array(12);
  nonce.set(baseNonce.subarray(0, 8), 0);
  new DataView(nonce.buffer).setUint32(8, chunkIndex, false);
  return nonce;
}

async function importAesKey() {
  return subtle.importKey("raw", randomBytes(32), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptAll(key, plain, baseNonce) {
  const chunks = [];
  const t0 = performance.now();
  let idx = 0;
  for (let off = 0; off < plain.length; off += CHUNK_SIZE, idx++) {
    const slice = plain.subarray(off, Math.min(off + CHUNK_SIZE, plain.length));
    const iv = buildChunkNonce(baseNonce, idx);
    chunks.push(
      new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, slice))
    );
  }
  return { chunks, ms: performance.now() - t0 };
}

async function decryptAll(key, chunks, baseNonce, expectedLen) {
  const parts = [];
  const t0 = performance.now();
  for (let i = 0; i < chunks.length; i++) {
    const iv = buildChunkNonce(baseNonce, i);
    parts.push(
      Buffer.from(
        new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, chunks[i]))
      )
    );
  }
  const plain = Buffer.concat(parts, expectedLen);
  return { plain, ms: performance.now() - t0 };
}

function avg(nums) {
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

function stdev(nums) {
  if (nums.length < 2) return 0;
  const m = avg(nums);
  return Math.sqrt(avg(nums.map((x) => (x - m) ** 2)));
}

function mbPerSec(bytes, ms) {
  if (ms <= 0) return 0;
  return bytes / (1024 * 1024) / (ms / 1000);
}

async function main() {
  const { sizes, runs } = parseArgs(process.argv.slice(2));
  await mkdir(OUT_DIR, { recursive: true });

  console.log("Mục 2 — Crypto-only (AES-256-GCM chunked, không mạng)");
  console.log(`Chunk: ${CHUNK_SIZE / (1024 * 1024)} MB · Runs/size: ${runs}`);
  console.log(`Sizes (MB): ${sizes.join(", ")}\n`);

  const rows = [];

  for (const mb of sizes) {
    const bytes = Math.round(mb * 1024 * 1024);
    const plain = randomBytes(bytes);
    const hashIn = sha256(plain);
    const encMsList = [];
    const decMsList = [];
    let ok = true;

    // Warm-up 1 lần (không ghi)
    {
      const key = await importAesKey();
      const base = randomBytes(8);
      const { chunks } = await encryptAll(key, plain, base);
      await decryptAll(key, chunks, base, plain.length);
    }

    for (let r = 0; r < runs; r++) {
      const key = await importAesKey();
      const base = randomBytes(8);
      const { chunks, ms: encMs } = await encryptAll(key, plain, base);
      const { plain: out, ms: decMs } = await decryptAll(key, chunks, base, plain.length);
      const hashOut = sha256(out);
      if (hashOut !== hashIn) ok = false;
      encMsList.push(encMs);
      decMsList.push(decMs);
      console.log(
        `  ${mb} MB run ${r + 1}/${runs}: encrypt=${encMs.toFixed(1)} ms  decrypt=${decMs.toFixed(1)} ms`
      );
    }

    const encAvg = avg(encMsList);
    const decAvg = avg(decMsList);
    rows.push({
      mb,
      bytes,
      chunks: Math.ceil(bytes / CHUNK_SIZE),
      encAvg,
      encStd: stdev(encMsList),
      decAvg,
      decStd: stdev(decMsList),
      encMBs: mbPerSec(bytes, encAvg),
      decMBs: mbPerSec(bytes, decAvg),
      ok,
    });
  }

  console.log("\n## Bảng Kết quả Mục 2 — thời gian mã hóa / giải mã riêng\n");
  console.log(
    "| Size | Chunks | Encrypt (ms) ±σ | Decrypt (ms) ±σ | Encrypt MB/s | Decrypt MB/s | SHA |"
  );
  console.log("|---:|---:|---:|---:|---:|---:|:---:|");
  for (const r of rows) {
    console.log(
      `| ${r.mb} MB | ${r.chunks} | ${r.encAvg.toFixed(1)} ± ${r.encStd.toFixed(1)} | ` +
        `${r.decAvg.toFixed(1)} ± ${r.decStd.toFixed(1)} | ${r.encMBs.toFixed(1)} | ` +
        `${r.decMBs.toFixed(1)} | ${r.ok ? "✓" : "✗"} |`
    );
  }

  const machine = `${process.platform} · Node ${process.version}`;
  const md = [
    "# Mục 2 — Crypto-only: thời gian mã hóa / giải mã (ms)",
    "",
    `Ngày: ${new Date().toISOString()}`,
    `Môi trường: ${machine}`,
    `Thuật toán: AES-256-GCM · chunk ${CHUNK_SIZE / (1024 * 1024)} MB (DEFAULT_CHUNK_SIZE FE)`,
    `Số lần lặp mỗi size: ${runs} (đã warm-up 1 lần, không tính)`,
    `Không gồm: upload/download mạng, SAS, UI`,
    "",
    "| Size | Chunks | Encrypt (ms) ±σ | Decrypt (ms) ±σ | Encrypt MB/s | Decrypt MB/s | SHA khớp |",
    "|---:|---:|---:|---:|---:|---:|:---:|",
    ...rows.map(
      (r) =>
        `| ${r.mb} MB | ${r.chunks} | ${r.encAvg.toFixed(1)} ± ${r.encStd.toFixed(1)} | ` +
        `${r.decAvg.toFixed(1)} ± ${r.decStd.toFixed(1)} | ${r.encMBs.toFixed(1)} | ` +
        `${r.decMBs.toFixed(1)} | ${r.ok ? "✓" : "✗"} |`
    ),
    "",
    "## Ghi chú báo cáo",
    "",
    "- Cột **Encrypt/Decrypt (ms)** là thời gian thuần Web Crypto trên máy đo.",
    "- **MB/s** = size_MB / (ms/1000).",
    "- So với E2E upload: phần lớn thời gian thực tế thường là mạng Azure, không phải AES.",
    "",
  ].join("\n");

  const outPath = path.join(OUT_DIR, "RESULTS.md");
  await writeFile(outPath, md, "utf8");
  console.log(`\nĐã ghi ${outPath}`);
  process.exit(rows.every((r) => r.ok) ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
