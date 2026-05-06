import type {
  AppleBlock,
  CompareResult,
  DetectedField,
  FileAnalysis,
  ManifestMarker,
  ManifestMarkerName,
} from "./types";

/**
 * Do not rely on fixed offsets. Apple firmware/configuration data can appear in different physical offsets.
 * Detection should be based on structure and nearby markers.
 */

const ASCII = new TextDecoder("ascii", { fatal: false });

export function toHexOffset(n: number): `0x${string}` {
  const v = Math.max(0, n >>> 0);
  return (`0x${v.toString(16).toUpperCase().padStart(8, "0")}`) as const;
}

export function findAsciiOccurrences(buf: Uint8Array, text: string): number[] {
  if (!text) return [];
  const pat = new TextEncoder().encode(text);
  if (pat.length === 0 || pat.length > buf.length) return [];

  const out: number[] = [];
  // naive scan is OK for ~few MB MVP
  outer: for (let i = 0; i <= buf.length - pat.length; i++) {
    for (let j = 0; j < pat.length; j++) {
      if (buf[i + j] !== pat[j]) continue outer;
    }
    out.push(i);
  }
  return out;
}

export function readAsciiAround(
  buf: Uint8Array,
  offset: number,
  before: number,
  after: number,
): string {
  const start = Math.max(0, offset - before);
  const end = Math.min(buf.length, offset + after);
  return ASCII.decode(buf.slice(start, end));
}

export function extractNullTerminatedAscii(
  buf: Uint8Array,
  offset: number,
  maxLength: number,
): string {
  const end = Math.min(buf.length, offset + maxLength);
  let i = offset;
  for (; i < end; i++) {
    if (buf[i] === 0x00) break;
  }
  const slice = buf.slice(offset, i);
  // remove non-printables (keep basic ASCII)
  let s = ASCII.decode(slice);
  s = s.replace(/[^\x20-\x7E]/g, "");
  return s;
}

const MANIFEST_MARKERS: ManifestMarkerName[] = [
  "IM4M",
  "MANB",
  "MANP",
  "BORD",
  "CHIP",
  "CPRO",
  "CSEC",
  "ECID",
  "SDOM",
];

export function detectManifestMarkers(buf: Uint8Array): ManifestMarker[] {
  const markers: ManifestMarker[] = [];
  for (const m of MANIFEST_MARKERS) {
    for (const off of findAsciiOccurrences(buf, m)) {
      markers.push({ marker: m, offset: off, offsetHex: toHexOffset(off) });
    }
  }
  markers.sort((a, b) => a.offset - b.offset);
  return markers;
}

function findAnyNear(
  hay: Uint8Array,
  center: number,
  window: number,
  needles: string[],
): { needle: string; offset: number } | null {
  const start = Math.max(0, center - window);
  const end = Math.min(hay.length, center + window);
  const slice = hay.slice(start, end);
  for (const n of needles) {
    const hits = findAsciiOccurrences(slice, n);
    if (hits.length) return { needle: n, offset: start + hits[0] };
  }
  return null;
}

function looksLikeModelCode(s: string): boolean {
  if (!s) return false;
  // Examples: D37DEV, D8XDEV, D9XDEV, D3YDEV, J717, J507, J307, J517, J417
  if (/^D[0-9A-Z]{2,3}DEV$/.test(s)) return true;
  if (/^J[0-9]{3}$/.test(s)) return true;
  return false;
}

function detectModelAfterType(
  buf: Uint8Array,
  typeOffset: number,
): DetectedField<string> | null {
  // Assume null-terminated ASCII field after type string, but offset is variable.
  // We'll scan forward up to 64 bytes for first plausible token.
  const scanEnd = Math.min(buf.length, typeOffset + 96);
  for (let i = typeOffset; i < scanEnd; i++) {
    // skip obvious separators/nulls
    if (buf[i] === 0x00) continue;
    const s = extractNullTerminatedAscii(buf, i, 24);
    if (s.length >= 3 && s.length <= 12 && looksLikeModelCode(s)) {
      return { offset: i, offsetHex: toHexOffset(i), value: s };
    }
  }
  return null;
}

function detectMarkerBeforeApple(
  buf: Uint8Array,
  appleOffset: number,
): DetectedField<string> | null {
  // Heuristic: look back up to 32 bytes for short ASCII marker like D73D / DX8D / 717J.
  const start = Math.max(0, appleOffset - 32);
  const end = appleOffset;
  for (let i = end - 4; i >= start; i--) {
    const s = ASCII.decode(buf.slice(i, i + 4)).replace(/[^\x20-\x7E]/g, "");
    if (s.length !== 4) continue;
    // Accept patterns like:
    // - D73D, DX8D, DX9D, DX3D
    // - 717J, 705J, 703J, 715J, 714J
    if (/^D[0-9A-Z]{2}D$/.test(s) || /^[0-9]{3}J$/.test(s)) {
      return { offset: i, offsetHex: toHexOffset(i), value: s };
    }
  }
  return null;
}

export function detectAppleBlocks(buf: Uint8Array): AppleBlock[] {
  const appleHits = findAsciiOccurrences(buf, "Apple Inc.");
  const manifest = detectManifestMarkers(buf);

  const blocks: AppleBlock[] = [];

  for (const appleOffset of appleHits) {
    const nearby = manifest.filter((m) => Math.abs(m.offset - appleOffset) <= 0x400); // ~1KB
    const typeHit = findAnyNear(buf, appleOffset, 160, ["iPhone", "iPad", "ACE1P"]);

    let deviceType: DetectedField<"iPhone" | "iPad" | "ACE1P"> | undefined;
    if (typeHit) {
      deviceType = {
        offset: typeHit.offset,
        offsetHex: toHexOffset(typeHit.offset),
        value: typeHit.needle as "iPhone" | "iPad" | "ACE1P",
      };
    }

    const model =
      deviceType ? detectModelAfterType(buf, deviceType.offset) : null;

    const marker = detectMarkerBeforeApple(buf, appleOffset);

    // confidence scoring per spec
    let confidence = 0;
    confidence += 0.4; // Apple Inc. present
    if (deviceType && (deviceType.value === "iPhone" || deviceType.value === "iPad"))
      confidence += 0.3;
    if (model && looksLikeModelCode(model.value)) confidence += 0.2;
    if (nearby.some((m) => m.marker === "IM4M" || m.marker === "BORD" || m.marker === "CHIP"))
      confidence += 0.1;
    confidence = Math.min(1, Math.max(0, confidence));

    const notes: string[] = [];
    if (!marker) notes.push("Marker not found in the expected lookback window.");
    if (!deviceType) notes.push("Device type string not found near Apple Inc.");
    if (deviceType?.value === "ACE1P")
      notes.push("ACE1P block treated as secondary/subsystem unless it also contains iPhone/iPad.");
    if (!model) notes.push("Model code not confidently detected after device type.");

    const blockType: AppleBlock["blockType"] =
      deviceType?.value === "ACE1P"
        ? "secondary_subsystem_block"
        : deviceType && model
          ? "main_device_block"
          : "unknown_block";

    blocks.push({
      blockType,
      appleOffset,
      appleOffsetHex: toHexOffset(appleOffset),
      marker: marker ?? undefined,
      manufacturer: "Apple Inc.",
      deviceType,
      modelCode: model ?? undefined,
      confidence,
      nearbyManifestMarkers: nearby,
      notes,
    });
  }

  blocks.sort((a, b) => a.appleOffset - b.appleOffset);
  return blocks;
}

export function hexdump(
  buf: Uint8Array,
  start: number,
  length: number,
  bytesPerLine = 16,
): string {
  const s = Math.max(0, Math.min(buf.length, start));
  const e = Math.max(s, Math.min(buf.length, s + length));
  const lines: string[] = [];

  for (let off = s; off < e; off += bytesPerLine) {
    const line = buf.slice(off, Math.min(e, off + bytesPerLine));
    const hex = Array.from(line)
      .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(line)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(
      `${toHexOffset(off)}  ${hex.padEnd(bytesPerLine * 3 - 1, " ")}  |${ascii}|`,
    );
  }
  return lines.join("\n");
}

export async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function analyzeFile(file: File): Promise<FileAnalysis> {
  const ab = await file.arrayBuffer();
  const u8 = new Uint8Array(ab);
  const sha256 = await sha256Hex(ab);
  const manifestMarkers = detectManifestMarkers(u8);
  const deviceBlocks = detectAppleBlocks(u8);

  return {
    fileName: file.name,
    sizeBytes: file.size,
    sha256,
    deviceBlocks,
    manifestMarkers,
    notes: [
      "Offsets are not fixed. Detection is based on nearby structure/patterns.",
    ],
  };
}

function mainModel(blocks: AppleBlock[]): string | undefined {
  const mains = blocks
    .filter((b) => b.blockType === "main_device_block" && b.modelCode?.value)
    .sort((a, b) => b.confidence - a.confidence);
  return mains[0]?.modelCode?.value;
}

export function compareFiles(
  aName: string,
  aBuf: Uint8Array,
  aSha: string,
  aBlocks: AppleBlock[],
  bName: string,
  bBuf: Uint8Array,
  bSha: string,
  bBlocks: AppleBlock[],
): CompareResult {
  const sizeA = aBuf.length;
  const sizeB = bBuf.length;
  const max = Math.max(sizeA, sizeB);
  let differingBytes = 0;
  const ranges: { start: number; end: number }[] = [];
  let inRange = false;
  let rangeStart = 0;

  for (let i = 0; i < max; i++) {
    const av = i < sizeA ? aBuf[i] : -1;
    const bv = i < sizeB ? bBuf[i] : -1;
    const diff = av !== bv;
    if (diff) differingBytes++;
    if (diff && !inRange) {
      inRange = true;
      rangeStart = i;
    } else if (!diff && inRange) {
      inRange = false;
      ranges.push({ start: rangeStart, end: i });
    }
  }
  if (inRange) ranges.push({ start: rangeStart, end: max });

  const differingRanges = ranges.map((r) => ({
    start: r.start,
    end: r.end,
    length: r.end - r.start,
  }));
  const largestRanges = [...differingRanges]
    .sort((x, y) => y.length - x.length)
    .slice(0, 5);

  const identical = sizeA === sizeB && aSha === bSha && differingBytes === 0;
  const modelA = mainModel(aBlocks);
  const modelB = mainModel(bBlocks);

  const summaryParts: string[] = [];
  if (sizeA === sizeB) summaryParts.push("Both files have the same size");
  else summaryParts.push("Files have different sizes");

  if (aSha === bSha) summaryParts.push("and the same SHA256 hash");
  else summaryParts.push("but different SHA256 hashes");

  const shareApple =
    aBlocks.some((b) => b.blockType !== "unknown_block") &&
    bBlocks.some((b) => b.blockType !== "unknown_block");
  if (shareApple) summaryParts.push(". They share a similar Apple structure");

  if (modelA && modelB && modelA !== modelB) {
    summaryParts.push(
      `, but the detected main model code is different: File A = ${modelA}, File B = ${modelB}. This suggests they are not direct equivalents if model-code compatibility is required.`,
    );
  } else if (modelA && modelB && modelA === modelB) {
    summaryParts.push(`, and the detected main model code matches: ${modelA}.`);
  } else {
    summaryParts.push(".");
  }

  return {
    fileA: { fileName: aName, sizeBytes: sizeA, sha256: aSha },
    fileB: { fileName: bName, sizeBytes: sizeB, sha256: bSha },
    identical,
    differingBytes,
    differingRanges,
    largestRanges,
    summary: summaryParts.join(" "),
    mainModelA: modelA,
    mainModelB: modelB,
  };
}

