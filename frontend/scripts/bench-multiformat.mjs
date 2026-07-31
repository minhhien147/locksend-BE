/**
 * Chứng minh đa định dạng LockSend: AES-256-GCM chunked roundtrip
 * trên nhiều MIME/extension (cùng pipeline chunk 4MB như FE).
 *
 * Usage:
 *   node scripts/bench-multiformat.mjs
 *   node scripts/bench-multiformat.mjs --size-mb 2
 */
import { createHash, randomBytes, webcrypto } from "node:crypto";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "fixtures", "multiformat");
const subtle = webcrypto.subtle;

const CHUNK_SIZE = 4 * 1024 * 1024;
const args = process.argv.slice(2);
const sizeMbIdx = args.indexOf("--size-mb");
const TARGET_BYTES = Math.max(
  64 * 1024,
  Math.round(parseFloat(args[sizeMbIdx + 1] || "2") * 1024 * 1024)
);

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function padTo(buf, target) {
  if (buf.length >= target) return buf.subarray(0, target);
  const out = Buffer.alloc(target);
  buf.copy(out);
  // Fill remainder with deterministic pseudo-random (reproducible benches)
  for (let i = buf.length; i < target; i++) out[i] = (i * 31 + 17) & 0xff;
  return out;
}

/** Minimal valid-ish PDF with optional stream padding. */
function makePdf(target) {
  const header = Buffer.from(
    `%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>endobj
4 0 obj<< /Length 44 >>stream
BT /F1 12 Tf 50 150 Td (LockSend multiformat) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
trailer<< /Size 5 /Root 1 0 R >>
startxref
0
%%EOF
`,
    "utf8"
  );
  return padTo(header, target);
}

/** Minimal JPEG (1x1) + comment APP0-style pad via trailing bytes after EOI is invalid;
 *  pad by repeating SOS payload area using COM marker segments. */
function makeJpeg(target) {
  // 1x1 pixel JPEG
  const base = Buffer.from(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxISEhUSEhIVFhUVFRUVFRUVFRUWFxUYFhUYHSggGBolGxUVITEhJSkrLi4uFx8zODMtNygtLisBCgoKDg0OGxAQGy0lHyUtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLf/AABEIAAEAAQMBIgACEQEDEQH/xAAbAAACAwEBAQAAAAAAAAAAAAAFBgMEBwIBAP/EADkQAAIBAwMCBAMFBwUAAAAAAAECAwAEEQUSITFBBhMiUWFxMoGRoQcjQrHB0fAVYnLwFjOS/8QAGQEAAwEBAQAAAAAAAAAAAAAAAAECAwQF/8QAIhEAAgICAgMBAQEAAAAAAAAAAAECEQMhEjFBBFEiYXEy/9oADAMBAAIRAxEAPwDlwAClQAH/2Q==",
    "base64"
  );
  return padTo(base, target);
}

function makePng(target) {
  // 1x1 PNG red pixel
  const base = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    "base64"
  );
  return padTo(base, target);
}

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function zipLocal(name, data) {
  const nameBuf = Buffer.from(name, "utf8");
  const comp = deflateRawSync(data);
  const local = Buffer.alloc(30 + nameBuf.length + comp.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(8, 8); // deflate
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(crc32(data), 14);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  local.writeUInt16LE(0, 28);
  nameBuf.copy(local, 30);
  comp.copy(local, 30 + nameBuf.length);
  return { local, nameBuf, comp, data };
}

function makeZip(target, innerName = "readme.txt", innerText = "LockSend multiformat ZIP\n") {
  const data = Buffer.from(innerText, "utf8");
  const { local, nameBuf, comp } = zipLocal(innerName, data);
  const central = Buffer.alloc(46 + nameBuf.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(8, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0, 14);
  central.writeUInt32LE(crc32(data), 16);
  central.writeUInt32LE(comp.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  nameBuf.copy(central, 46);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length, 16);
  end.writeUInt16LE(0, 20);
  return padTo(Buffer.concat([local, central, end]), target);
}

function makeMp4(target) {
  // ftyp + free + mdat boxes
  const ftyp = Buffer.alloc(24);
  ftyp.writeUInt32BE(24, 0);
  ftyp.write("ftyp", 4);
  ftyp.write("isom", 8);
  ftyp.writeUInt32BE(0x200, 12);
  ftyp.write("isom", 16);
  ftyp.write("mp41", 20);
  const mdatSize = Math.max(8, target - 24);
  const mdat = Buffer.alloc(mdatSize);
  mdat.writeUInt32BE(mdatSize, 0);
  mdat.write("mdat", 4);
  for (let i = 8; i < mdatSize; i++) mdat[i] = (i * 13) & 0xff;
  return Buffer.concat([ftyp, mdat]).subarray(0, target);
}

function makeTxt(target) {
  const line = "LockSend E2E multiformat proof — dòng UTF-8: xin chào 🔒\n";
  const reps = Math.ceil(target / Buffer.byteLength(line));
  return padTo(Buffer.from(line.repeat(reps), "utf8"), target);
}

function makeBin(target) {
  return randomBytes(target);
}

function makeDocx(target) {
  // DOCX = ZIP with [Content_Types].xml
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;
  return makeZip(target, "[Content_Types].xml", xml);
}

const SPECIMENS = [
  { name: "sample.txt", mime: "text/plain", build: makeTxt },
  { name: "sample.pdf", mime: "application/pdf", build: makePdf },
  { name: "sample.jpg", mime: "image/jpeg", build: makeJpeg },
  { name: "sample.png", mime: "image/png", build: makePng },
  { name: "sample.zip", mime: "application/zip", build: makeZip },
  { name: "sample.mp4", mime: "video/mp4", build: makeMp4 },
  { name: "sample.docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", build: makeDocx },
  { name: "sample.bin", mime: "application/octet-stream", build: makeBin },
];

async function importAesKey() {
  const raw = randomBytes(32);
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function buildChunkNonce(baseNonce, chunkIndex) {
  const nonce = new Uint8Array(12);
  nonce.set(baseNonce.subarray(0, 8), 0);
  new DataView(nonce.buffer).setUint32(8, chunkIndex, false);
  return nonce;
}

async function encryptAll(key, plain, baseNonce) {
  const chunks = [];
  const t0 = performance.now();
  let idx = 0;
  for (let off = 0; off < plain.length; off += CHUNK_SIZE, idx++) {
    const slice = plain.subarray(off, Math.min(off + CHUNK_SIZE, plain.length));
    const iv = buildChunkNonce(baseNonce, idx);
    const ct = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv }, key, slice)
    );
    chunks.push(ct);
  }
  return { chunks, encryptMs: performance.now() - t0 };
}

async function decryptAll(key, chunks, baseNonce) {
  const parts = [];
  const t0 = performance.now();
  for (let i = 0; i < chunks.length; i++) {
    const iv = buildChunkNonce(baseNonce, i);
    const pt = new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv }, key, chunks[i])
    );
    parts.push(Buffer.from(pt));
  }
  return { plain: Buffer.concat(parts), decryptMs: performance.now() - t0 };
}

function magicOk(name, buf) {
  if (name.endsWith(".pdf")) return buf.subarray(0, 5).toString() === "%PDF-";
  if (name.endsWith(".png")) return buf[0] === 0x89 && buf[1] === 0x50;
  if (name.endsWith(".jpg")) return buf[0] === 0xff && buf[1] === 0xd8;
  if (name.endsWith(".zip") || name.endsWith(".docx")) return buf[0] === 0x50 && buf[1] === 0x4b;
  if (name.endsWith(".mp4")) return buf.subarray(4, 8).toString() === "ftyp";
  return true;
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  console.log(`Target size ≈ ${(TARGET_BYTES / (1024 * 1024)).toFixed(2)} MB · chunk ${CHUNK_SIZE / (1024 * 1024)} MB`);
  console.log(`Fixtures → ${OUT_DIR}\n`);

  const rows = [];
  for (const spec of SPECIMENS) {
    const plain = spec.build(TARGET_BYTES);
    const filePath = path.join(OUT_DIR, spec.name);
    await writeFile(filePath, plain);

    const hashIn = sha256(plain);
    const key = await importAesKey();
    const baseNonce = randomBytes(8);
    const { chunks, encryptMs } = await encryptAll(key, plain, baseNonce);
    const { plain: out, decryptMs } = await decryptAll(key, chunks, baseNonce);
    const hashOut = sha256(out);
    const ok = hashIn === hashOut && out.length === plain.length;
    const magic = magicOk(spec.name, plain);

    rows.push({
      file: spec.name,
      mime: spec.mime,
      size: plain.length,
      chunks: chunks.length,
      magic,
      encryptMs,
      decryptMs,
      shaMatch: ok,
      sha256: hashIn.slice(0, 12),
    });

    const status = ok ? "PASS" : "FAIL";
    console.log(
      `${status.padEnd(4)} ${spec.name.padEnd(14)} magic=${magic ? "Y" : "N"}  ` +
        `enc=${encryptMs.toFixed(1)}ms  dec=${decryptMs.toFixed(1)}ms  ` +
        `sha=${hashIn.slice(0, 12)}…`
    );
  }

  const allPass = rows.every((r) => r.shaMatch);
  console.log("\n## Bảng kết quả (đa định dạng)\n");
  console.log("| File | MIME | Size | Magic | Encrypt (ms) | Decrypt (ms) | SHA-256 khớp |");
  console.log("|---|---|---:|:---:|---:|---:|:---:|");
  for (const r of rows) {
    console.log(
      `| ${r.file} | \`${r.mime}\` | ${(r.size / 1024).toFixed(0)} KB | ${r.magic ? "✓" : "✗"} | ${r.encryptMs.toFixed(1)} | ${r.decryptMs.toFixed(1)} | ${r.shaMatch ? "✓" : "✗"} |`
    );
  }
  console.log(
    `\nKết luận: mã hóa LockSend (AES-256-GCM chunked) **độc lập MIME** — ` +
      `${rows.filter((r) => r.shaMatch).length}/${rows.length} mẫu roundtrip OK.`
  );

  const mdPath = path.join(OUT_DIR, "RESULTS.md");
  const md = [
    "# Kết quả test đa định dạng (crypto roundtrip)",
    "",
    `Ngày: ${new Date().toISOString()}`,
    `Chunk size: ${CHUNK_SIZE / (1024 * 1024)} MB (giống DEFAULT_CHUNK_SIZE FE)`,
    `Kích thước mẫu: ~${(TARGET_BYTES / (1024 * 1024)).toFixed(2)} MB / file`,
    "",
    "| File | MIME | Size | Magic header | Encrypt (ms) | Decrypt (ms) | SHA-256 khớp |",
    "|---|---|---:|:---:|---:|---:|:---:|",
    ...rows.map(
      (r) =>
        `| ${r.file} | \`${r.mime}\` | ${(r.size / 1024).toFixed(0)} KB | ${r.magic ? "✓" : "✗"} | ${r.encryptMs.toFixed(1)} | ${r.decryptMs.toFixed(1)} | ${r.shaMatch ? "✓" : "✗"} |`
    ),
    "",
    allPass
      ? "**PASS** — mọi định dạng khôi phục đúng byte sau encrypt→decrypt."
      : "**FAIL** — có mẫu không khớp SHA.",
    "",
  ].join("\n");
  await writeFile(mdPath, md, "utf8");
  console.log(`\nĐã ghi ${mdPath}`);
  process.exit(allPass ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
