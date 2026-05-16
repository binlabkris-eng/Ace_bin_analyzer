export type BlockType =
  | "main_device_block"
  | "secondary_subsystem_block"
  | "macintosh_device_block"
  | "cd3217_firmware_block"
  | "thunderbolt_drom_block"
  | "retimer_config_block"
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
  deviceType?: DetectedField<"iPhone" | "iPad" | "Macintosh" | "ACE1P">;
  modelCode?: DetectedField<string>;
  confidence: number; // 0..1
  duplicateGroup?: string;
  nearbyManifestMarkers: ManifestMarker[];
  notes: string[];
};

export type FileStats = {
  ffPercentage: number;
  zeroPercentage: number;
  entropy: number;
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
  | "SDOM"
  | "CEPO"
  | "EKEY"
  | "BNCN"
  | "BNCH"
  | "NONC"
  | "RAND"
  | "DGST"
  | "CERT"
  | "KBAG"
  | "SEPO"
  | "SRTG"
  | "LOVE"
  | "PROS"
  | "TYPE"
  | "VERS";

export type ManifestMarker = {
  marker: ManifestMarkerName;
  offset: number;
  offsetHex: OffsetHex;
};

export type MetadataCategory =
  | "Classic Apple Manifest"
  | "Apple Identity"
  | "ACE/ICE Commands"
  | "ACE/ICE Firmware Map"
  | "MacBook SPI Metadata"
  | "CD3217 Firmware Metadata"
  | "Thunderbolt / DROM"
  | "Retimer / Config"
  | "Generic Strings";

export type MetadataSubtype =
  | "apple_manifest_marker"
  | "apple_firmware_manifest_block"
  | "iphone_identity_metadata"
  | "ipad_identity_metadata"
  | "macintosh_identity_metadata"
  | "ace_identity_metadata"
  | "ace_ice_command_table_metadata"
  | "ace_ice_state_table_metadata"
  | "ace_ice_firmware_map_metadata"
  | "macbook_spi_metadata_block"
  | "cd3217_firmware_metadata"
  | "thunderbolt_drom_metadata"
  | "retimer_config_metadata"
  | "patch_config_metadata"
  | "generic_ascii_string";

export type MetadataBlock = {
  category: MetadataCategory;
  subtype: MetadataSubtype;
  offset: number;
  offsetHex: OffsetHex;
  markers: string[];
  primaryValue?: string;
  score: number; // 0..1 for blocks, or >=0 for ranked strings (UI uses as "confidence/score")
  notes?: string;
  relatedOffsets?: Record<string, OffsetHex>;
};

export type Cd3217FirmwareBlock = {
  blockType: "cd3217_firmware_block";
  offset: number;
  offsetHex: OffsetHex;
  chip: "CD3217";
  hw?: string;
  fwVersion?: string;
  variant?: string;
  duplicateGroup?: string;
  notes: string[];
};

export type ThunderboltBlock = {
  blockType: "thunderbolt_drom_block" | "retimer_config_block";
  offset: number;
  offsetHex: OffsetHex;
  markers: string[];
  duplicateGroup?: string;
  notes: string[];
};

export type AceIceCommandTag = {
  tag: string;
  offset: number;
  offsetHex: OffsetHex;
  asciiValue: string;
  meaning: string;
  groupId: string;
  confidence: number;
  isCommandPrefixDelimiter?: boolean;
};

export type AceIceCommandTableBlock = {
  blockType: "command_table_block" | "state_string_table_block";
  startOffset: number;
  startOffsetHex: OffsetHex;
  endOffset: number;
  endOffsetHex: OffsetHex;
  tags: AceIceCommandTag[];
  confidence: number;
  notes: string[];
};

export type AceIceFirmwareMapBlock = {
  blockType:
    | "boot_header_candidate"
    | "main_firmware_candidate"
    | "secondary_firmware_candidate"
    | "config_block_candidate"
    | "runtime_config_reference"
    | "peripheral_register_reference";
  offset?: number;
  offsetHex?: OffsetHex;
  range?: string;
  reason: string;
  confidence: number;
  notes: string;
};

export type AceIceHandlerReference = {
  commandTag?: string;
  possibleHandlerFunction: string;
  source: string;
  confidence: number;
  notes: string;
};

export type ArmThumbCodePattern = {
  blockType:
    | "arm_thumb_code_region"
    | "dispatcher_function_candidate"
    | "handler_function_candidate";
  startOffset: number;
  startOffsetHex: OffsetHex;
  endOffset: number;
  endOffsetHex: OffsetHex;
  confidence: number;
  reason: string;
  notes: string[];
};

export type FileAnalysis = {
  fileName: string;
  sizeBytes: number;
  sha256: string;
  fileStats: FileStats;
  detectedFamily:
    | "iphone_ipad_firmware_config"
    | "macbook_spi_cd3217"
    | "ace_ice_firmware"
    | "thunderbolt_retimer"
    | "unknown";
  deviceBlocks: AppleBlock[];
  firmwareBlocks: Cd3217FirmwareBlock[];
  thunderboltBlocks: ThunderboltBlock[];
  aceIceCommandTables: AceIceCommandTableBlock[];
  aceIceFirmwareMap: AceIceFirmwareMapBlock[];
  aceIceHandlerReferences: AceIceHandlerReference[];
  aceIceConclusion?: string;
  armThumbCodePatterns: ArmThumbCodePattern[];
  manifestMarkers: ManifestMarker[];
  metadataBlocks: MetadataBlock[];
  genericStringsAll: MetadataBlock[];
  notes: string[];
};

export type DiffRange = { start: number; end: number; length: number };

export type CompareResult = {
  fileA: Pick<FileAnalysis, "fileName" | "sizeBytes" | "sha256" | "fileStats">;
  fileB: Pick<FileAnalysis, "fileName" | "sizeBytes" | "sha256" | "fileStats">;
  identical: boolean;
  differingBytes: number;
  differingRanges: DiffRange[];
  largestRanges: DiffRange[];
  summary: string;
  mainModelA?: string;
  mainModelB?: string;
  cd3217VariantA?: string;
  cd3217VariantB?: string;
  aceIceTagsA: string[];
  aceIceTagsB: string[];
  aceIceMissingFromA: string[];
  aceIceMissingFromB: string[];
  aceIceCommandTableOffsetA?: OffsetHex;
  aceIceCommandTableOffsetB?: OffsetHex;
  aceIceStateTableOffsetA?: OffsetHex;
  aceIceStateTableOffsetB?: OffsetHex;
  aceIceFirmwareMapDiffs: string[];
  aceIceHandlerDiffs: string[];
  aceIceCapabilityDiffs: string[];
};

