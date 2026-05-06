import { describe, expect, it } from "vitest";
import {
  compareFiles,
  detectAppleBlocks,
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
      "b.bin",
      b,
      "shaB",
      [],
    );
    expect(res.identical).toBe(false);
    expect(res.differingBytes).toBe(2);
    expect(res.differingRanges.length).toBe(2);
    expect(res.summary).toContain("different SHA256 hashes");
  });
});

