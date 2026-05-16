import type {
  AppleBlock,
  AceIceCommandTableBlock,
  AceIceFirmwareMapBlock,
  AceIceHandlerReference,
  ArmThumbCodePattern,
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

function assignDuplicateGroups<T extends { duplicateGroup?: string }>(
  items: T[],
  getOffset: (i: T) => number,
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
    arr.sort((a, b) => getOffset(a) - getOffset(b));
    if (arr.length < 2) continue;
    // If we have two similar copies far apart, tag them; otherwise still tag by key.
    const shouldMirrorTag =
      arr.length >= 2 &&
      Math.abs(getOffset(arr[1]) - getOffset(arr[0])) >= mirrorDistance;
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
    (b) => b.appleOffset,
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
  assignDuplicateGroups(
    blocks,
    (b) => b.offset,
    (b) => (b.variant ? `cd3217_${b.variant}` : "cd3217"),
  );
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
  assignDuplicateGroups(merged, (b) => b.offset, (b) => `${b.blockType}`);
  return merged;
}

export const ACE_ICE_COMMAND_TAGS: Record<string, string> = {
  GSkX: "Get Status / eXchange",
  DFUm: "DFU Mode / DFU Message",
  DFUd: "DFU Download / DFU Data",
  DRST: "Device Reset",
  EUSB: "Enter USB Mode / Enable USB",
  EURr: "USB Read / USB Request",
  DPMc: "PD / Power Management Control",
  VOUT: "Voltage Output / PD VOUT",
  LDCM: "Load Command / Load Mode",
  RDCI: "Read Command / Read Control",
  "!CMD": "Command Prefix / Delimiter",
  CFUp: "CFU Prepare / Check Function",
  APP: "Application Mode",
  UFPf: "UFP Function / USB-C Upstream Facing Port",
  DFUf: "DFU Function / DFU Finish",
};

const ACE_ICE_STATE_TAGS = new Set(["CFUp", "APP", "VOUT", "UFPf", "DFUf"]);
const ACE_ICE_COMMAND_CAPABILITY_TAGS = ["DFUm", "DFUd", "EUSB", "EURr", "DPMc", "VOUT"];

function readU16Le(buf: Uint8Array, offset: number): number {
  if (offset + 1 >= buf.length) return 0;
  return buf[offset] | (buf[offset + 1] << 8);
}

function readU32Le(buf: Uint8Array, offset: number): number {
  if (offset + 3 >= buf.length) return 0;
  return (
    buf[offset] |
    (buf[offset + 1] << 8) |
    (buf[offset + 2] << 16) |
    (buf[offset + 3] << 24)
  ) >>> 0;
}

function alignDown(n: number, alignment: number): number {
  return Math.max(0, n - (n % alignment));
}

function rangeHex(start: number, end: number): string {
  return `${toHexOffset(start)}-${toHexOffset(end)}`;
}

function nonBlankDensity(buf: Uint8Array, start: number, end: number): number {
  const s = Math.max(0, start);
  const e = Math.min(buf.length, end);
  if (e <= s) return 0;
  let nonBlank = 0;
  for (let i = s; i < e; i++) {
    if (buf[i] !== 0x00 && buf[i] !== 0xff) nonBlank++;
  }
  return nonBlank / (e - s);
}

function isThumbLikeInstruction(v: number): boolean {
  return (
    (v & 0xff00) === 0xb500 || // push
    (v & 0xff00) === 0xbd00 || // pop
    (v & 0xf800) === 0xe000 || // unconditional branch
    (v & 0xf000) === 0xd000 || // conditional branch / svc class
    (v & 0xf800) === 0x2000 || // movs immediate
    (v & 0xf800) === 0x2800 || // cmp immediate
    (v & 0xf800) === 0x4800 || // ldr literal
    (v & 0xf000) === 0x6000 || // str/ldr register/immediate family
    (v & 0xff00) === 0x4600 || // mov high register
    (v & 0xff80) === 0x4700 // bx/blx
  );
}

function thumbDensity(buf: Uint8Array, start: number, end: number): number {
  let total = 0;
  let hits = 0;
  for (let i = Math.max(0, start); i + 1 < Math.min(buf.length, end); i += 2) {
    total++;
    if (isThumbLikeInstruction(readU16Le(buf, i))) hits++;
  }
  return total ? hits / total : 0;
}

function findAsciiMovPatterns(buf: Uint8Array, start: number, end: number): string[] {
  const chars = new Set<string>();
  for (let i = Math.max(0, start); i + 1 < Math.min(buf.length, end); i += 2) {
    const v = readU16Le(buf, i);
    if ((v & 0xf800) !== 0x2000) continue;
    const imm = v & 0xff;
    if (imm === 0x31 || imm === 0x4d || imm === 0x4b || imm === 0x4f) {
      chars.add(String.fromCharCode(imm));
    }
  }
  return [...chars].sort();
}

function findLittleEndianReferences(buf: Uint8Array, target: number, limit = 20): number[] {
  const refs: number[] = [];
  for (let i = 0; i + 3 < buf.length; i++) {
    if (readU32Le(buf, i) === target) {
      refs.push(i);
      if (refs.length >= limit) break;
    }
  }
  return refs;
}

export function detectAceIceCommandTables(buf: Uint8Array): AceIceCommandTableBlock[] {
  const hits: { tag: string; offset: number }[] = [];
  for (const tag of Object.keys(ACE_ICE_COMMAND_TAGS)) {
    for (const offset of findAsciiOccurrences(buf, tag)) {
      hits.push({ tag, offset });
    }
  }
  hits.sort((a, b) => a.offset - b.offset || a.tag.localeCompare(b.tag));

  const groups: { id: string; hits: { tag: string; offset: number }[] }[] = [];
  for (const hit of hits) {
    const last = groups[groups.length - 1];
    if (last && hit.offset - last.hits[last.hits.length - 1].offset <= 0x100) {
      last.hits.push(hit);
    } else {
      groups.push({ id: `aceice_group_${groups.length + 1}`, hits: [hit] });
    }
  }

  const blocks: AceIceCommandTableBlock[] = [];
  for (const group of groups) {
    const uniqueTags = new Set(group.hits.map((h) => h.tag));
    const stateCount = [...uniqueTags].filter((tag) => ACE_ICE_STATE_TAGS.has(tag)).length;
    const hasStateSignature =
      stateCount >= 3 &&
      (uniqueTags.has("CFUp") || uniqueTags.has("APP")) &&
      (uniqueTags.has("UFPf") || uniqueTags.has("DFUf") || uniqueTags.has("VOUT"));
    const hasCommandSignature = uniqueTags.size >= 5;
    if (!hasCommandSignature && !hasStateSignature) continue;

    const startOffset = Math.min(...group.hits.map((h) => h.offset));
    const endOffset = Math.max(...group.hits.map((h) => h.offset + h.tag.length));
    const span = Math.max(1, endOffset - startOffset);
    const blockType: AceIceCommandTableBlock["blockType"] =
      hasStateSignature && (!hasCommandSignature || stateCount >= uniqueTags.size - 1)
        ? "state_string_table_block"
        : "command_table_block";
    const confidence = clamp01(
      0.45 +
        Math.min(0.35, uniqueTags.size * 0.045) +
        (span <= 0x100 ? 0.1 : 0) +
        (uniqueTags.has("!CMD") ? 0.08 : 0) +
        (hasStateSignature ? 0.07 : 0),
    );

    blocks.push({
      blockType,
      startOffset,
      startOffsetHex: toHexOffset(startOffset),
      endOffset,
      endOffsetHex: toHexOffset(endOffset),
      tags: group.hits.map((h) => ({
        tag: h.tag,
        offset: h.offset,
        offsetHex: toHexOffset(h.offset),
        asciiValue: h.tag,
        meaning: ACE_ICE_COMMAND_TAGS[h.tag],
        groupId: group.id,
        confidence,
        isCommandPrefixDelimiter: h.tag === "!CMD" || undefined,
      })),
      confidence,
      notes: [
        `${uniqueTags.size} known ACE/ICE tag(s) found within ${toHexOffset(span)}.`,
        blockType === "state_string_table_block"
          ? "State-oriented tag signature detected."
          : "Command-oriented tag signature detected.",
      ],
    });
  }

  return blocks.sort((a, b) => a.startOffset - b.startOffset);
}

export function detectArmThumbCodePatterns(buf: Uint8Array): ArmThumbCodePattern[] {
  const regions: ArmThumbCodePattern[] = [];
  const window = 0x100;
  const step = 0x80;

  for (let start = 0; start < buf.length; start += step) {
    const end = Math.min(buf.length, start + window);
    const density = thumbDensity(buf, start, end);
    const blank = nonBlankDensity(buf, start, end);
    if (density < 0.28 || blank < 0.15) continue;

    const movChars = findAsciiMovPatterns(buf, start, end);
    const branchBonus = (() => {
      let branches = 0;
      for (let i = start; i + 1 < end; i += 2) {
        const v = readU16Le(buf, i);
        if ((v & 0xf800) === 0xe000 || (v & 0xf000) === 0xd000) branches++;
      }
      return branches;
    })();
    const blockType: ArmThumbCodePattern["blockType"] =
      movChars.length >= 2 || branchBonus >= 6
        ? "handler_function_candidate"
        : "arm_thumb_code_region";
    const confidence = clamp01(0.35 + density * 0.85 + Math.min(0.12, movChars.length * 0.03));
    const last = regions[regions.length - 1];
    if (last && start - last.endOffset <= step && last.blockType === blockType) {
      last.endOffset = end;
      last.endOffsetHex = toHexOffset(end);
      last.confidence = Math.max(last.confidence, confidence);
      continue;
    }
    regions.push({
      blockType,
      startOffset: start,
      startOffsetHex: toHexOffset(start),
      endOffset: end,
      endOffsetHex: toHexOffset(end),
      confidence,
      reason: `Thumb-like density ${(density * 100).toFixed(1)}%`,
      notes: movChars.length
        ? [`Loads ASCII-like immediates: ${movChars.join(", ")}`]
        : ["Common Thumb instruction patterns detected."],
    });
  }

  return regions.sort((a, b) => b.confidence - a.confidence || a.startOffset - b.startOffset).slice(0, 40);
}

export function detectAceIceHandlerReferences(
  buf: Uint8Array,
  commandTables = detectAceIceCommandTables(buf),
  thumbPatterns = detectArmThumbCodePatterns(buf),
): AceIceHandlerReference[] {
  const refs: AceIceHandlerReference[] = [];
  const tableRefs = new Map<number, AceIceCommandTableBlock>();
  for (const table of commandTables) {
    for (const ref of findLittleEndianReferences(buf, table.startOffset, 12)) {
      tableRefs.set(ref, table);
    }
  }

  for (const [refOffset, table] of tableRefs) {
    const nearbyCode = thumbPatterns.find(
      (r) => Math.abs(r.startOffset - refOffset) <= 0x400 || (refOffset >= r.startOffset && refOffset <= r.endOffset),
    );
    refs.push({
      commandTag: table.tags[0]?.tag,
      possibleHandlerFunction: nearbyCode
        ? rangeHex(nearbyCode.startOffset, nearbyCode.endOffset)
        : toHexOffset(refOffset),
      source: `table reference @ ${toHexOffset(refOffset)}`,
      confidence: nearbyCode ? 0.72 : 0.55,
      notes: `${table.blockType} start offset is referenced in little-endian form.`,
    });
  }

  for (const table of commandTables.filter((t) => t.blockType === "command_table_block")) {
    for (const tag of table.tags) {
      const nearest = thumbPatterns
        .filter((r) => r.blockType !== "arm_thumb_code_region")
        .sort((a, b) => Math.abs(a.startOffset - tag.offset) - Math.abs(b.startOffset - tag.offset))[0];
      if (!nearest) continue;
      refs.push({
        commandTag: tag.tag,
        possibleHandlerFunction: rangeHex(nearest.startOffset, nearest.endOffset),
        source: "nearby Thumb handler heuristic",
        confidence: Math.max(0.45, nearest.confidence - 0.15),
        notes: `${tag.tag} appears in a command table; nearest Thumb-like handler candidate is reported.`,
      });
    }
  }

  return refs
    .sort((a, b) => b.confidence - a.confidence || a.possibleHandlerFunction.localeCompare(b.possibleHandlerFunction))
    .slice(0, 50);
}

function pointerCandidateCount(buf: Uint8Array, start: number, end: number): number {
  let count = 0;
  for (let i = Math.max(0, start); i + 3 < Math.min(buf.length, end); i += 4) {
    const v = readU32Le(buf, i);
    if ((v > 0 && v < buf.length) || (v >= 0x20000000 && v <= 0x200fffff) || (v >= 0x40000000 && v <= 0x400fffff)) {
      count++;
    }
  }
  return count;
}

export function detectAceIceFirmwareMap(buf: Uint8Array): AceIceFirmwareMapBlock[] {
  const commandTables = detectAceIceCommandTables(buf);
  if (!commandTables.length) return [];
  const thumbPatterns = detectArmThumbCodePatterns(buf);
  const blocks: AceIceFirmwareMapBlock[] = [];

  for (let start = 0; start < Math.min(buf.length, 0x20000); start += 0x40) {
    const end = Math.min(buf.length, start + 0x100);
    const nonBlank = nonBlankDensity(buf, start, end);
    const pointers = pointerCandidateCount(buf, start, end);
    const code = thumbDensity(buf, start, end);
    if (nonBlank >= 0.2 && pointers >= 2 && code >= 0.18) {
      blocks.push({
        blockType: "boot_header_candidate",
        offset: start,
        offsetHex: toHexOffset(start),
        reason: "Low firmware region has non-blank data, pointer-like values, and nearby Thumb-like code.",
        confidence: clamp01(0.45 + pointers * 0.03 + code),
        notes: "Pattern-based boot/header candidate; sample offsets are not treated as universal.",
      });
      break;
    }
  }

  const codeRegions = [...thumbPatterns].sort((a, b) => a.startOffset - b.startOffset);
  const main = codeRegions[0];
  if (main) {
    blocks.push({
      blockType: "main_firmware_candidate",
      range: rangeHex(main.startOffset, main.endOffset),
      reason: main.reason,
      confidence: clamp01(main.confidence),
      notes: "First substantial Thumb-like region.",
    });
  }
  const secondary = codeRegions.find((r) => main && r.startOffset - main.endOffset > 0x1000);
  if (secondary) {
    blocks.push({
      blockType: "secondary_firmware_candidate",
      range: rangeHex(secondary.startOffset, secondary.endOffset),
      reason: secondary.reason,
      confidence: clamp01(secondary.confidence - 0.08),
      notes: "Additional distinct Thumb-like region, possibly secondary firmware.",
    });
  }

  for (const table of commandTables) {
    const start = alignDown(Math.max(0, table.startOffset - 0x20), 0x10);
    const end = Math.min(buf.length, table.endOffset + 0x80);
    blocks.push({
      blockType: "config_block_candidate",
      offset: start,
      offsetHex: toHexOffset(start),
      range: rangeHex(start, end),
      reason: `${table.blockType} with ACE/ICE command/state tags is embedded in this local structure.`,
      confidence: clamp01(table.confidence - 0.05),
      notes: "Located near grouped command/state tags and small structured values.",
    });
  }

  const seenRuntime = new Set<number>();
  const seenPeripheral = new Set<number>();
  for (let i = 0; i + 3 < buf.length; i += 4) {
    const v = readU32Le(buf, i);
    if (v >= 0x20040000 && v <= 0x2004ffff && !seenRuntime.has(v)) {
      seenRuntime.add(v);
      blocks.push({
        blockType: "runtime_config_reference",
        offset: i,
        offsetHex: toHexOffset(i),
        reason: `Pointer-like runtime/RAM config value ${toHexOffset(v)} found.`,
        confidence: 0.62,
        notes: "RAM-mapped config reference candidate, not a file offset.",
      });
    }
    if (v >= 0x40060000 && v <= 0x4006ffff && !seenPeripheral.has(v)) {
      seenPeripheral.add(v);
      blocks.push({
        blockType: "peripheral_register_reference",
        offset: i,
        offsetHex: toHexOffset(i),
        reason: `Peripheral/register-like value ${toHexOffset(v)} found.`,
        confidence: v === 0x40060400 ? 0.72 : 0.58,
        notes: "Peripheral/register reference candidate, not a file offset.",
      });
    }
    if (seenRuntime.size + seenPeripheral.size >= 12) break;
  }

  return blocks.sort((a, b) => (a.offset ?? 0) - (b.offset ?? 0) || b.confidence - a.confidence);
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

  // 5) ACE/ICE command tables and firmware-map metadata
  const aceTables = detectAceIceCommandTables(buf);
  for (const t of aceTables) {
    addMetadata(out, {
      category: "ACE/ICE Commands",
      subtype:
        t.blockType === "state_string_table_block"
          ? "ace_ice_state_table_metadata"
          : "ace_ice_command_table_metadata",
      offset: t.startOffset,
      offsetHex: t.startOffsetHex,
      markers: t.tags.map((tag) => tag.tag),
      primaryValue: t.blockType,
      score: t.confidence,
      notes: t.notes.join(" "),
    });
  }

  const aceMap = detectAceIceFirmwareMap(buf);
  for (const m of aceMap) {
    addMetadata(out, {
      category: "ACE/ICE Firmware Map",
      subtype: "ace_ice_firmware_map_metadata",
      offset: m.offset ?? 0,
      offsetHex: m.offsetHex ?? "0x00000000",
      markers: [m.blockType],
      primaryValue: m.range ?? m.offsetHex ?? m.blockType,
      score: m.confidence,
      notes: `${m.reason} ${m.notes}`,
    });
  }

  // 6) Generic ASCII metadata (top only by default)
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
  hasAceIce: boolean;
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
  if (params.hasAceIce) {
    notes.push(
      "ACE/ICE command/state metadata detected from grouped short ASCII tags; table offsets are pattern-derived, not fixed.",
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
  const aceIceCommandTables = detectAceIceCommandTables(u8);
  const armThumbCodePatterns = detectArmThumbCodePatterns(u8);
  const aceIceFirmwareMap = detectAceIceFirmwareMap(u8);
  const aceIceHandlerReferences = detectAceIceHandlerReferences(
    u8,
    aceIceCommandTables,
    armThumbCodePatterns,
  );
  const aceIceConclusion = buildAceIceConclusion({
    commandTables: aceIceCommandTables,
    firmwareMap: aceIceFirmwareMap,
    handlerRefs: aceIceHandlerReferences,
    thumbPatterns: armThumbCodePatterns,
  });
  const meta = detectMetadataBlocks(u8);

  const hasMac = deviceBlocks.some((b) => b.blockType === "macintosh_device_block");
  const hasCd = firmwareBlocks.length > 0;
  const hasTb = thunderboltBlocks.length > 0;
  const hasAceIce = aceIceCommandTables.length > 0 || aceIceFirmwareMap.length > 0;
  const hasClassic = manifestMarkers.length > 0;
  const hasIdentity = deviceBlocks.some(
    (b) =>
      b.blockType === "main_device_block" ||
      b.blockType === "secondary_subsystem_block" ||
      b.blockType === "macintosh_device_block",
  );
  const detectedFamily: FileAnalysis["detectedFamily"] = hasAceIce
    ? "ace_ice_firmware"
    : hasMac || hasCd
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
    aceIceCommandTables,
    aceIceFirmwareMap,
    aceIceHandlerReferences,
    aceIceConclusion,
    armThumbCodePatterns,
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
        hasAceIce,
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

function aceIceTagSet(tables: AceIceCommandTableBlock[]): string[] {
  return [...new Set(tables.flatMap((t) => t.tags.map((tag) => tag.tag)))].sort();
}

function arrayDiff(a: string[], b: string[]): string[] {
  const bSet = new Set(b);
  return a.filter((x) => !bSet.has(x)).sort();
}

function firstAceIceOffset(
  tables: AceIceCommandTableBlock[],
  blockType: AceIceCommandTableBlock["blockType"],
): `0x${string}` | undefined {
  return tables.find((t) => t.blockType === blockType)?.startOffsetHex;
}

function aceIceMapSignature(blocks: AceIceFirmwareMapBlock[]): string[] {
  return blocks
    .map((b) => `${b.blockType}:${b.range ?? b.offsetHex ?? "unknown"}`)
    .sort();
}

function aceIceHandlerSignature(refs: AceIceHandlerReference[]): string[] {
  return refs
    .map((r) => `${r.commandTag ?? "unknown"}:${r.possibleHandlerFunction}`)
    .sort();
}

function aceIceCapabilities(tags: string[]): string[] {
  const set = new Set(tags);
  const caps: string[] = [];
  if (set.has("DFUm") || set.has("DFUd") || set.has("DFUf")) caps.push("DFU");
  if (set.has("EUSB") || set.has("EURr") || set.has("UFPf")) caps.push("USB");
  if (set.has("DPMc")) caps.push("PD");
  if (set.has("VOUT")) caps.push("VOUT");
  return caps;
}

function buildAceIceConclusion(params: {
  commandTables: AceIceCommandTableBlock[];
  firmwareMap: AceIceFirmwareMapBlock[];
  handlerRefs: AceIceHandlerReference[];
  thumbPatterns: ArmThumbCodePattern[];
}): string | undefined {
  const commandTable = params.commandTables.find((b) => b.blockType === "command_table_block");
  if (!commandTable) return undefined;

  const tags = aceIceTagSet(params.commandTables);
  const caps = aceIceCapabilities(tags);
  const stateTable = params.commandTables.find((b) => b.blockType === "state_string_table_block");
  const hasDelimiter = tags.includes("!CMD");
  const hasExecutableEvidence =
    params.thumbPatterns.length > 0 ||
    params.handlerRefs.length > 0 ||
    params.firmwareMap.some((b) => b.blockType === "main_firmware_candidate" || b.blockType === "secondary_firmware_candidate");

  const parts = [
    `This dump contains an ACE/ICE command table with ${caps.length ? `${caps.join(", ")} related tags` : `${tags.length} known command/state tags`}.`,
    `The command table appears near ${commandTable.startOffsetHex}${stateTable ? ` and a state table appears near ${stateTable.startOffsetHex}` : ""}.`,
  ];

  if (hasDelimiter) {
    parts.push("It includes !CMD as a delimiter/prefix.");
  }

  if (hasExecutableEvidence) {
    parts.push(
      "This suggests the dump contains executable firmware logic and command/state metadata, not only static identity strings.",
    );
  } else {
    parts.push(
      "This suggests command/state metadata is present; executable-code evidence was not strong enough for a separate handler conclusion.",
    );
  }

  return parts.join(" ");
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
  aAceTables: AceIceCommandTableBlock[] = [],
  bAceTables: AceIceCommandTableBlock[] = [],
  aAceFirmwareMap: AceIceFirmwareMapBlock[] = [],
  bAceFirmwareMap: AceIceFirmwareMapBlock[] = [],
  aAceHandlers: AceIceHandlerReference[] = [],
  bAceHandlers: AceIceHandlerReference[] = [],
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
  const aceTagsA = aceIceTagSet(aAceTables);
  const aceTagsB = aceIceTagSet(bAceTables);
  const aceMissingFromA = arrayDiff(aceTagsB, aceTagsA);
  const aceMissingFromB = arrayDiff(aceTagsA, aceTagsB);
  const aceCapsA = aceIceCapabilities(aceTagsA);
  const aceCapsB = aceIceCapabilities(aceTagsB);
  const aceCapabilityDiffs = [
    ...arrayDiff(aceCapsB, aceCapsA).map((c) => `${c} missing from A`),
    ...arrayDiff(aceCapsA, aceCapsB).map((c) => `${c} missing from B`),
  ];
  const aceMapA = aceIceMapSignature(aAceFirmwareMap);
  const aceMapB = aceIceMapSignature(bAceFirmwareMap);
  const aceIceFirmwareMapDiffs = [
    ...arrayDiff(aceMapB, aceMapA).map((x) => `A lacks ${x}`),
    ...arrayDiff(aceMapA, aceMapB).map((x) => `B lacks ${x}`),
  ];
  const aceHandlersA = aceIceHandlerSignature(aAceHandlers);
  const aceHandlersB = aceIceHandlerSignature(bAceHandlers);
  const aceIceHandlerDiffs = [
    ...arrayDiff(aceHandlersB, aceHandlersA).map((x) => `A lacks ${x}`),
    ...arrayDiff(aceHandlersA, aceHandlersB).map((x) => `B lacks ${x}`),
  ];

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

  if (aceTagsA.length || aceTagsB.length) {
    if (!aceMissingFromA.length && !aceMissingFromB.length) {
      summaryParts.push(` ACE/ICE command tags match (${aceTagsA.length} tag(s)).`);
    } else {
      summaryParts.push(
        ` ACE/ICE command tags differ: missing from A [${aceMissingFromA.join(", ") || "none"}], missing from B [${aceMissingFromB.join(", ") || "none"}].`,
      );
    }
    const tableA = firstAceIceOffset(aAceTables, "command_table_block");
    const tableB = firstAceIceOffset(bAceTables, "command_table_block");
    if (tableA || tableB) summaryParts.push(` Command table offsets: A=${tableA ?? "unknown"}, B=${tableB ?? "unknown"}.`);
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
    aceIceTagsA: aceTagsA,
    aceIceTagsB: aceTagsB,
    aceIceMissingFromA: aceMissingFromA,
    aceIceMissingFromB: aceMissingFromB,
    aceIceCommandTableOffsetA: firstAceIceOffset(aAceTables, "command_table_block"),
    aceIceCommandTableOffsetB: firstAceIceOffset(bAceTables, "command_table_block"),
    aceIceStateTableOffsetA: firstAceIceOffset(aAceTables, "state_string_table_block"),
    aceIceStateTableOffsetB: firstAceIceOffset(bAceTables, "state_string_table_block"),
    aceIceFirmwareMapDiffs,
    aceIceHandlerDiffs,
    aceIceCapabilityDiffs: aceCapabilityDiffs,
  };
}

