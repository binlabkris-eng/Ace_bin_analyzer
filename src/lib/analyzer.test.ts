import { describe, expect, it } from "vitest";
import {
  calculateByteStats,
  calculateEntropy,
  compareFiles,
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
    expect(main?.confidence).toBeGreaterThanOrEqual(0.9); // Apple+type+model (0.4+0.3+0.2)
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

