import type {
  AppleBlock,
  Cd3217FirmwareBlock,
  CompareResult,
  DetectedField,
  FileAnalysis,
  ManifestMarker,
  ManifestMarkerName,
  MetadataBlock,
  MetadataCategory,
  ThunderboltBlock,
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

const APPLE_FIRMWARE_MANIFEST_MARKERS: ManifestMarkerName[] = [
  "IM4M",
  "MANB",
  "MANP",
  "BORD",
  "CHIP",
  "CPRO",
  "CSEC",
  "ECID",
  "SDOM",
  "CEPO",
  "EKEY",
  "BNCN",
  "BNCH",
  "NONC",
  "RAND",
  "DGST",
  "CERT",
  "KBAG",
  "SEPO",
  "SRTG",
  "LOVE",
  "PROS",
  "TYPE",
  "VERS",
];

export function detectManifestMarkers(buf: Uint8Array): ManifestMarker[] {
  // Back-compat wrapper (classic Apple firmware/personalization markers)
  const markers: ManifestMarker[] = [];
  for (const m of APPLE_FIRMWARE_MANIFEST_MARKERS) {
    for (const off of findAsciiOccurrences(buf, m)) {
      markers.push({ marker: m, offset: off, offsetHex: toHexOffset(off) });
    }
  }
  markers.sort((a, b) => a.offset - b.offset);
  return markers;
}

export function detectAppleFirmwareManifestMarkers(
  buf: Uint8Array,
): ManifestMarker[] {
  return detectManifestMarkers(buf);
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
  // Macintosh SPI examples: J314P5, J314P01P, J314P2P
  if (/^J[0-9]{3}P[0-9A-Z]{1,3}P?$/.test(s)) return true;
  return false;
}

export function extractPrintableAsciiStrings(
  buf: Uint8Array,
  minLength = 4,
): { offset: number; value: string }[] {
  const out: { offset: number; value: string }[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = i < buf.length ? buf[i] : 0;
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else if (start !== -1) {
      const len = i - start;
      if (len >= minLength) {
        const s = ASCII.decode(buf.slice(start, i));
        out.push({ offset: start, value: s });
      }
      start = -1;
    }
  }
  return out;
}

export function calculateByteStats(buf: Uint8Array): {
  ffPercentage: number;
  zeroPercentage: number;
} {
  if (!buf.length) return { ffPercentage: 0, zeroPercentage: 0 };
  let ff = 0;
  let z = 0;
  for (const b of buf) {
    if (b === 0xff) ff++;
    if (b === 0x00) z++;
  }
  return {
    ffPercentage: (ff / buf.length) * 100,
    zeroPercentage: (z / buf.length) * 100,
  };
}

export function calculateEntropy(buf: Uint8Array): number {
  if (!buf.length) return 0;
  const freq = new Uint32Array(256);
  for (const b of buf) freq[b]++;
  let h = 0;
  const inv = 1 / buf.length;
  for (let i = 0; i < 256; i++) {
    const c = freq[i];
    if (!c) continue;
    const p = c * inv;
    h -= p * Math.log2(p);
  }
  return h; // 0..8 bits/byte
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
    const typeHit = findAnyNear(buf, appleOffset, 160, [
      "iPhone",
      "iPad",
      "Macintosh",
      "ACE1P",
    ]);

    let deviceType:
      | DetectedField<"iPhone" | "iPad" | "Macintosh" | "ACE1P">
      | undefined;
    if (typeHit) {
      deviceType = {
        offset: typeHit.offset,
        offsetHex: toHexOffset(typeHit.offset),
        value: typeHit.needle as "iPhone" | "iPad" | "Macintosh" | "ACE1P",
      };
    }

    const model =
      deviceType ? detectModelAfterType(buf, deviceType.offset) : null;

    const marker = detectMarkerBeforeApple(buf, appleOffset);

    // confidence scoring per spec
    let confidence = 0;
    confidence += 0.4; // Apple Inc. present
    if (
      deviceType &&
      (deviceType.value === "iPhone" ||
        deviceType.value === "iPad" ||
        deviceType.value === "Macintosh" ||
        deviceType.value === "ACE1P")
    )
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
        : deviceType?.value === "Macintosh" && model
          ? "macintosh_device_block"
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

function assignDuplicateGroups<T extends { offset: number; duplicateGroup?: string }>(
  items: T[],
  keyFn: (i: T) => string | undefined,
  mirrorDistance = 0x80000,
): T[] {
  const byKey = new Map<string, T[]>();
  for (const it of items) {
    const k = keyFn(it);
    if (!k) continue;
    const arr = byKey.get(k) ?? [];
    arr.push(it);
    byKey.set(k, arr);
  }
  for (const [k, arr] of byKey) {
    arr.sort((a, b) => a.offset - b.offset);
    if (arr.length < 2) continue;
    // If we have two similar copies far apart, tag them; otherwise still tag by key.
    const shouldMirrorTag =
      arr.length >= 2 && Math.abs(arr[1].offset - arr[0].offset) >= mirrorDistance;
    for (const it of arr) {
      it.duplicateGroup = shouldMirrorTag ? k : k;
    }
  }
  return items;
}

export function detectMacintoshSpiBlocks(buf: Uint8Array): AppleBlock[] {
  const blocks = detectAppleBlocks(buf).filter(
    (b) => b.blockType === "macintosh_device_block",
  );
  assignDuplicateGroups(
    blocks,
    (b) => (b.modelCode?.value ? `macintosh_${b.modelCode.value}` : undefined),
  );
  return blocks;
}

export function detectCd3217FirmwareBlocks(buf: Uint8Array): Cd3217FirmwareBlock[] {
  const hits = findAsciiOccurrences(buf, "CD3217");
  const blocks: Cd3217FirmwareBlock[] = [];
  for (const off of hits) {
    const around = readAsciiAround(buf, off, 0, 160);
    const hw = /\bHW\b/.test(around) ? "HW" : undefined;
    const fw = around.match(/\bFW[0-9]{3}\.[0-9]{3}\.[0-9]{2}\b/)?.[0];
    const variant = around.match(/\b[ZR]ACE2-AC\b/)?.[0];
    const notes: string[] = [];
    if (!fw) notes.push("FW version not found in nearby ASCII window.");
    if (!variant) notes.push("Variant not found (expected RACE2-AC / ZACE2-AC).");
    blocks.push({
      blockType: "cd3217_firmware_block",
      offset: off,
      offsetHex: toHexOffset(off),
      chip: "CD3217",
      hw,
      fwVersion: fw,
      variant,
      notes,
    });
  }
  assignDuplicateGroups(blocks, (b) => (b.variant ? `cd3217_${b.variant}` : "cd3217"));
  blocks.sort((a, b) => a.offset - b.offset);
  return blocks;
}

const TB_MARKERS = [
  "DROM",
  "ARC PARM",
  "EE_USB_RETIMER",
  "PATCHES",
  "CONFIG3",
  "Intel Thunderbolt generic vendor name",
  "Intel Thunderbolt generic model name",
];

export function detectThunderboltRetimerBlocks(buf: Uint8Array): ThunderboltBlock[] {
  const blocks: ThunderboltBlock[] = [];
  for (const m of TB_MARKERS) {
    for (const off of findAsciiOccurrences(buf, m)) {
      const kind: ThunderboltBlock["blockType"] =
        m === "DROM" ? "thunderbolt_drom_block" : "retimer_config_block";
      const existing = blocks.find((b) => b.offset === off && b.blockType === kind);
      if (existing) {
        if (!existing.markers.includes(m)) existing.markers.push(m);
        continue;
      }
      blocks.push({
        blockType: kind,
        offset: off,
        offsetHex: toHexOffset(off),
        markers: [m],
        notes: [],
      });
    }
  }
  // coalesce close offsets into a single block
  blocks.sort((a, b) => a.offset - b.offset);
  const merged: ThunderboltBlock[] = [];
  for (const b of blocks) {
    const last = merged[merged.length - 1];
    if (last && Math.abs(b.offset - last.offset) <= 0x100 && last.blockType === b.blockType) {
      for (const m of b.markers) if (!last.markers.includes(m)) last.markers.push(m);
    } else {
      merged.push(b);
    }
  }
  assignDuplicateGroups(merged, (b) => `${b.blockType}`);
  return merged;
}

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

function scoreUsefulString(value: string): number {
  let score = 0;
  const v = value;
  const upper = v.toUpperCase();

  const weird = (v.match(/[^A-Za-z0-9 ._\-\/]/g) ?? []).length;
  if (v.length > 64) score -= 5;
  if (weird > 6) score -= 5;

  if (/(Apple Inc\.?|iPhone|iPad|Macintosh|Thunderbolt|USB|RETIMER|PATCH|CONFIG|DROM|ACE|ICE|ROM)/i.test(v))
    score += 5;
  if (/^D[0-9A-Z]{2,3}DEV$/.test(upper) || /^J[0-9]{3}$/.test(upper) || /^J[0-9]{3}P[0-9A-Z]{1,3}P?$/.test(upper))
    score += 5;
  if (/\b(CD3217|FW[0-9]{3}\.[0-9]{3}\.[0-9]{2}|HW|RACE2-AC|ZACE2-AC)\b/i.test(v))
    score += 4;
  if (/\b(THUNDERBOLT|RETIMER|DROM|ARC PARM|EE_USB_RETIMER|PATCHES|CONFIG3)\b/i.test(v))
    score += 3;
  if (/^[A-Z0-9]{4}$/.test(upper)) score += 2;

  return score;
}

export function detectGenericAsciiMetadata(buf: Uint8Array): {
  top: MetadataBlock[];
  all: MetadataBlock[];
} {
  const strings = extractPrintableAsciiStrings(buf, 4);
  const blocks: MetadataBlock[] = [];
  for (const s of strings) {
    const score = scoreUsefulString(s.value);
    if (score <= 0) continue;
    blocks.push({
      category: "Generic Strings",
      subtype: "generic_ascii_string",
      offset: s.offset,
      offsetHex: toHexOffset(s.offset),
      markers: [],
      primaryValue: s.value,
      score,
      notes: "Ranked printable ASCII string (noise-filtered).",
    });
  }
  blocks.sort((a, b) => b.score - a.score || a.offset - b.offset);
  return {
    top: blocks.slice(0, 50),
    all: blocks,
  };
}

function addMetadata(blocks: MetadataBlock[], b: MetadataBlock) {
  blocks.push(b);
}

export function detectMetadataBlocks(buf: Uint8Array): {
  metadataBlocks: MetadataBlock[];
  genericStringsAll: MetadataBlock[];
} {
  const out: MetadataBlock[] = [];

  // 1) Classic Apple firmware manifest markers
  const classic = detectAppleFirmwareManifestMarkers(buf);
  for (const m of classic) {
    addMetadata(out, {
      category: "Classic Apple Manifest",
      subtype: "apple_manifest_marker",
      offset: m.offset,
      offsetHex: m.offsetHex,
      markers: [m.marker],
      primaryValue: m.marker,
      score: 0.75,
      notes: "Classic Apple firmware/personalization marker.",
    });
  }

  // 2) Apple identity metadata (iPhone/iPad/Macintosh/ACE1P)
  const identity = detectAppleBlocks(buf).filter((b) => b.deviceType?.value);
  for (const b of identity) {
    const family = b.deviceType?.value;
    const subtype =
      family === "iPhone"
        ? "iphone_identity_metadata"
        : family === "iPad"
          ? "ipad_identity_metadata"
          : family === "Macintosh"
            ? "macintosh_identity_metadata"
            : "ace_identity_metadata";
    addMetadata(out, {
      category: family === "Macintosh" ? "MacBook SPI Metadata" : "Apple Identity",
      subtype,
      offset: b.appleOffset,
      offsetHex: b.appleOffsetHex,
      markers: [
        "Apple Inc.",
        family ?? "unknown",
        b.modelCode?.value ?? "",
      ].filter(Boolean),
      primaryValue: b.modelCode?.value ?? family,
      score: clamp01(b.confidence),
      notes:
        b.blockType === "secondary_subsystem_block"
          ? "ACE1P identity/subsystem metadata."
          : "Apple identity metadata block.",
      relatedOffsets: {
        ...(b.marker ? { marker: b.marker.offsetHex } : {}),
        ...(b.deviceType ? { deviceType: b.deviceType.offsetHex } : {}),
        ...(b.modelCode ? { modelCode: b.modelCode.offsetHex } : {}),
      },
    });
  }

  // 3) CD3217 firmware metadata
  const cd = detectCd3217FirmwareBlocks(buf);
  for (const c of cd) {
    addMetadata(out, {
      category: "CD3217 Firmware Metadata",
      subtype: "cd3217_firmware_metadata",
      offset: c.offset,
      offsetHex: c.offsetHex,
      markers: ["CD3217", c.hw, c.fwVersion, c.variant].filter(Boolean) as string[],
      primaryValue: c.variant ?? c.fwVersion ?? "CD3217",
      score: 0.95,
      notes: "CD3217 firmware metadata (chip/HW/FW/variant).",
    });
  }

  // 4) Thunderbolt / retimer metadata (reuse thunderboltBlocks)
  const tb = detectThunderboltRetimerBlocks(buf);
  for (const t of tb) {
    const isDrom = t.blockType === "thunderbolt_drom_block";
    addMetadata(out, {
      category: isDrom ? "Thunderbolt / DROM" : "Retimer / Config",
      subtype: isDrom ? "thunderbolt_drom_metadata" : "retimer_config_metadata",
      offset: t.offset,
      offsetHex: t.offsetHex,
      markers: t.markers,
      primaryValue: t.markers[0],
      score: 0.9,
      notes: isDrom ? "Thunderbolt DROM metadata." : "Retimer/config section metadata.",
    });
  }

  // 5) Generic ASCII metadata (top only by default)
  const generic = detectGenericAsciiMetadata(buf);
  out.push(...generic.top);

  out.sort((a, b) => a.offset - b.offset);
  return { metadataBlocks: out, genericStringsAll: generic.all };
}

function buildSmartMetadataNotes(params: {
  hasClassic: boolean;
  hasIdentity: boolean;
  hasMac: boolean;
  hasCd: boolean;
  hasTbOrRetimer: boolean;
}): string[] {
  const notes: string[] = [];
  if (params.hasClassic) {
    notes.push("Classic Apple firmware manifest markers found.");
  } else {
    if (params.hasMac || params.hasCd || params.hasTbOrRetimer) {
      notes.push(
        "No classic Apple IM4M/BORD/CHIP-style manifest markers found, but other metadata/config blocks were detected.",
      );
    } else {
      notes.push("No classic Apple firmware manifest markers found.");
    }
  }

  if (params.hasMac) {
    notes.push(
      "MacBook SPI dumps often use Apple Inc. → Macintosh → Jxxx… identity/config structures; classic IM4M markers are not required.",
    );
  }
  if (params.hasTbOrRetimer) {
    notes.push(
      "Thunderbolt/DROM/retimer dumps may not include classic Apple firmware manifests but still contain structured configuration metadata.",
    );
  }
  return notes;
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
  const stats = calculateByteStats(u8);
  const entropy = calculateEntropy(u8);
  const manifestMarkers = detectAppleFirmwareManifestMarkers(u8);
  const deviceBlocks = detectAppleBlocks(u8);
  const firmwareBlocks = detectCd3217FirmwareBlocks(u8);
  const thunderboltBlocks = detectThunderboltRetimerBlocks(u8);
  const meta = detectMetadataBlocks(u8);

  const hasMac = deviceBlocks.some((b) => b.blockType === "macintosh_device_block");
  const hasCd = firmwareBlocks.length > 0;
  const hasTb = thunderboltBlocks.length > 0;
  const hasClassic = manifestMarkers.length > 0;
  const hasIdentity = deviceBlocks.some(
    (b) =>
      b.blockType === "main_device_block" ||
      b.blockType === "secondary_subsystem_block" ||
      b.blockType === "macintosh_device_block",
  );
  const detectedFamily: FileAnalysis["detectedFamily"] = hasMac || hasCd
    ? "macbook_spi_cd3217"
    : hasTb
      ? "thunderbolt_retimer"
      : deviceBlocks.some((b) => b.blockType === "main_device_block" || b.blockType === "secondary_subsystem_block")
        ? "iphone_ipad_firmware_config"
        : "unknown";

  return {
    fileName: file.name,
    sizeBytes: file.size,
    sha256,
    fileStats: { ...stats, entropy },
    detectedFamily,
    deviceBlocks,
    firmwareBlocks,
    thunderboltBlocks,
    manifestMarkers,
    metadataBlocks: meta.metadataBlocks,
    genericStringsAll: meta.genericStringsAll,
    notes: [
      "Offsets are not fixed. Detection is based on nearby structure/patterns.",
      ...buildSmartMetadataNotes({
        hasClassic,
        hasIdentity,
        hasMac,
        hasCd,
        hasTbOrRetimer: hasTb,
      }),
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
  aStats: { ffPercentage: number; zeroPercentage: number; entropy: number },
  aCd3217: Cd3217FirmwareBlock[],
  bName: string,
  bBuf: Uint8Array,
  bSha: string,
  bBlocks: AppleBlock[],
  bStats: { ffPercentage: number; zeroPercentage: number; entropy: number },
  bCd3217: Cd3217FirmwareBlock[],
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
  const cdA = aCd3217.map((b) => b.variant).find(Boolean);
  const cdB = bCd3217.map((b) => b.variant).find(Boolean);

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

  if (cdA && cdB && cdA === cdB) {
    summaryParts.push(` CD3217 variant matches: ${cdA}.`);
  } else if (cdA && cdB && cdA !== cdB) {
    summaryParts.push(` CD3217 variant differs: A=${cdA}, B=${cdB}.`);
  }

  return {
    fileA: { fileName: aName, sizeBytes: sizeA, sha256: aSha, fileStats: aStats },
    fileB: { fileName: bName, sizeBytes: sizeB, sha256: bSha, fileStats: bStats },
    identical,
    differingBytes,
    differingRanges,
    largestRanges,
    summary: summaryParts.join(" "),
    mainModelA: modelA,
    mainModelB: modelB,
    cd3217VariantA: cdA,
    cd3217VariantB: cdB,
  };
}

