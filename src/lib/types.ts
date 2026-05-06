export type BlockType =
  | "main_device_block"
  | "secondary_subsystem_block"
  | "manifest_block"
  | "unknown_block";

export type OffsetHex = `0x${string}`;

export type DetectedField<T extends string = string> = {
  offset: number;
  offsetHex: OffsetHex;
  value: T;
};

export type AppleBlock = {
  blockType: BlockType;
  appleOffset: number;
  appleOffsetHex: OffsetHex;
  marker?: DetectedField<string>;
  manufacturer: "Apple Inc.";
  deviceType?: DetectedField<"iPhone" | "iPad" | "ACE1P">;
  modelCode?: DetectedField<string>;
  confidence: number; // 0..1
  nearbyManifestMarkers: ManifestMarker[];
  notes: string[];
};

export type ManifestMarkerName =
  | "IM4M"
  | "MANB"
  | "MANP"
  | "BORD"
  | "CHIP"
  | "CPRO"
  | "CSEC"
  | "ECID"
  | "SDOM";

export type ManifestMarker = {
  marker: ManifestMarkerName;
  offset: number;
  offsetHex: OffsetHex;
};

export type FileAnalysis = {
  fileName: string;
  sizeBytes: number;
  sha256: string;
  deviceBlocks: AppleBlock[];
  manifestMarkers: ManifestMarker[];
  notes: string[];
};

export type DiffRange = { start: number; end: number; length: number };

export type CompareResult = {
  fileA: Pick<FileAnalysis, "fileName" | "sizeBytes" | "sha256">;
  fileB: Pick<FileAnalysis, "fileName" | "sizeBytes" | "sha256">;
  identical: boolean;
  differingBytes: number;
  differingRanges: DiffRange[];
  largestRanges: DiffRange[];
  summary: string;
  mainModelA?: string;
  mainModelB?: string;
};

