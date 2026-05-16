import { describe, expect, it } from "vitest";
import {
  calculateByteStats,
  calculateEntropy,
  compareFiles,
  detectAceIceCommandTables,
  detectAceIceFirmwareMap,
  detectArmThumbCodePatterns,
  detectAppleBlocks,
  detectMetadataBlocks,
  detectCd3217FirmwareBlocks,
  detectThunderboltRetimerBlocks,
  detectGenericAsciiMetadata,
  findAsciiOccurrences,
  toHexOffset,
} from "./analyzer";

function u8FromAscii(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("findAsciiOccurrences", () => {
  it("finds all occurrences", () => {
    const buf = u8FromAscii("Apple Inc. xxx Apple Inc.");
    expect(findAsciiOccurrences(buf, "Apple Inc.")).toEqual([0, 15]);
  });
});

describe("toHexOffset", () => {
  it("formats padded uppercase hex offsets", () => {
    expect(toHexOffset(0)).toBe("0x00000000");
    expect(toHexOffset(0xe028)).toBe("0x0000E028");
  });
});

describe("detectAppleBlocks", () => {
  it("detects a main iPhone block in synthetic buffer", () => {
    // synthetic: D73D....Apple Inc.\0iPhone\0D37DEV
    const parts = [
      "XXXXD73DYYYY", // marker somewhere before
      "Apple Inc.\0",
      "iPhone\0",
      "D37DEV\0",
    ];
    const buf = u8FromAscii(parts.join(""));
    const blocks = detectAppleBlocks(buf);
    expect(blocks.length).toBeGreaterThan(0);
    const main = blocks.find((b) => b.blockType === "main_device_block");
    expect(main?.deviceType?.value).toBe("iPhone");
    expect(main?.modelCode?.value).toBe("D37DEV");
    expect(main?.confidence).toBeCloseTo(0.9, 5); // Apple+type+model (0.4+0.3+0.2)
  });
});

describe("compareFiles", () => {
  it("counts differences and produces a summary", () => {
    const a = new Uint8Array([0, 1, 2, 3, 4]);
    const b = new Uint8Array([0, 1, 9, 3, 8]);
    const res = compareFiles(
      "a.bin",
      a,
      "shaA",
      [],
      { ffPercentage: 0, zeroPercentage: 0, entropy: 1 },
      [],
      "b.bin",
      b,
      "shaB",
      [],
      { ffPercentage: 0, zeroPercentage: 0, entropy: 1 },
      [],
    );
    expect(res.identical).toBe(false);
    expect(res.differingBytes).toBe(2);
    expect(res.differingRanges.length).toBe(2);
    expect(res.summary).toContain("different SHA256 hashes");
  });
});

describe("detectCd3217FirmwareBlocks", () => {
  it("detects CD3217 HW FW variant", () => {
    const buf = u8FromAscii("xxxx CD3217 HW FW000.000.00 ZACE2-AC yyyy");
    const blocks = detectCd3217FirmwareBlocks(buf);
    expect(blocks.length).toBe(1);
    expect(blocks[0].chip).toBe("CD3217");
    expect(blocks[0].hw).toBe("HW");
    expect(blocks[0].fwVersion).toBe("FW000.000.00");
    expect(blocks[0].variant).toBe("ZACE2-AC");
  });
});

describe("detectThunderboltRetimerBlocks", () => {
  it("detects DROM and retimer markers", () => {
    const buf = u8FromAscii("DROM....ARC PARM....EE_USB_RETIMER....CONFIG3");
    const blocks = detectThunderboltRetimerBlocks(buf);
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks.some((b) => b.blockType === "thunderbolt_drom_block")).toBe(true);
  });
});

describe("ACE/ICE detection", () => {
  it("detects grouped command and state tables", () => {
    const buf = u8FromAscii(
      "xxxxGSkX....DFUm....DFUd....DRST....EUSB....EURr....DPMc....VOUT....!CMD" +
        "\0".repeat(300) +
        "CFUp....APP....VOUT....UFPf....DFUf",
    );
    const tables = detectAceIceCommandTables(buf);
    expect(tables.some((b) => b.blockType === "command_table_block")).toBe(true);
    expect(tables.some((b) => b.blockType === "state_string_table_block")).toBe(true);
    expect(tables.flatMap((b) => b.tags).some((t) => t.tag === "!CMD" && t.isCommandPrefixDelimiter)).toBe(true);
  });

  it("detects firmware map references near ACE/ICE structures", () => {
    const buf = new Uint8Array(0x400);
    buf.fill(0xff);
    const tags = u8FromAscii("GSkX....DFUm....DFUd....DRST....EUSB....VOUT....!CMD");
    buf.set(tags, 0x180);
    buf.set(new Uint8Array([0x00, 0x04, 0x04, 0x20]), 0x220); // 0x20040400
    buf.set(new Uint8Array([0x00, 0x04, 0x06, 0x40]), 0x224); // 0x40060400
    const map = detectAceIceFirmwareMap(buf);
    expect(map.some((b) => b.blockType === "config_block_candidate")).toBe(true);
    expect(map.some((b) => b.blockType === "runtime_config_reference")).toBe(true);
    expect(map.some((b) => b.blockType === "peripheral_register_reference")).toBe(true);
  });

  it("detects Thumb-like code patterns", () => {
    const buf = new Uint8Array(0x120);
    for (let i = 0; i < 0x100; i += 8) {
      buf.set([0x00, 0xb5, 0x4d, 0x20, 0x00, 0xe0, 0x00, 0xbd], i);
    }
    const patterns = detectArmThumbCodePatterns(buf);
    expect(patterns.some((p) => p.blockType === "handler_function_candidate")).toBe(true);
  });
});

describe("metadata blocks", () => {
  it("detects classic manifest markers and identity metadata", () => {
    const buf = u8FromAscii(
      "D73D....Apple Inc.\0iPhone\0D37DEV....IM4M....BORD....CHIP",
    );
    const meta = detectMetadataBlocks(buf);
    expect(meta.metadataBlocks.some((b) => b.category === "Classic Apple Manifest")).toBe(true);
    expect(meta.metadataBlocks.some((b) => b.category === "Apple Identity")).toBe(true);
  });

  it("ranks useful generic strings", () => {
    const buf = u8FromAscii("xxxx D37DEV yyyy Thunderbolt zzz FW000.000.00");
    const g = detectGenericAsciiMetadata(buf);
    expect(g.top.length).toBeGreaterThan(0);
    expect(g.top[0].primaryValue).toBeDefined();
  });
});

describe("stats", () => {
  it("computes FF/00 percentages and entropy", () => {
    const buf = new Uint8Array([0xff, 0xff, 0x00, 0x01]);
    const s = calculateByteStats(buf);
    expect(s.ffPercentage).toBeCloseTo(50, 5);
    expect(s.zeroPercentage).toBeCloseTo(25, 5);
    const e = calculateEntropy(buf);
    expect(e).toBeGreaterThan(0);
  });
});

