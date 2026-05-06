import { useMemo, useState } from "react";
import {
  analyzeFile,
  compareFiles,
  hexdump,
  sha256Hex,
  toHexOffset,
} from "./lib/analyzer";
import type { AppleBlock, CompareResult, FileAnalysis } from "./lib/types";

type Tab =
  | "Summary"
  | "Apple Device Blocks"
  | "MacBook SPI Blocks"
  | "CD3217 Firmware"
  | "Thunderbolt / Retimer"
  | "Metadata / Manifest"
  | "Hex Preview"
  | "Compare"
  | "Export";

type LoadedFile = {
  id: string;
  file: File;
  buf: Uint8Array;
  sha256: string;
  analysis: FileAnalysis;
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(2)} MB`;
}

function badgeClass(t: string): string {
  if (t === "main_device_block") return "badge green";
  if (t === "secondary_subsystem_block") return "badge blue";
  if (t === "macintosh_device_block") return "badge purple";
  if (t === "cd3217_firmware_block") return "badge blue";
  if (t === "thunderbolt_drom_block") return "badge purple";
  if (t === "retimer_config_block") return "badge blue";
  if (t === "manifest_block") return "badge purple";
  return "badge gray";
}

export default function App() {
  const [tab, setTab] = useState<Tab>("Summary");
  const [files, setFiles] = useState<LoadedFile[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [compareA, setCompareA] = useState<string | null>(null);
  const [compareB, setCompareB] = useState<string | null>(null);
  const [compareResult, setCompareResult] = useState<CompareResult | null>(null);
  const [showAllStrings, setShowAllStrings] = useState(false);
  const [metadataCategory, setMetadataCategory] = useState<string>("All");
  const [hexModalOffset, setHexModalOffset] = useState<number | null>(null);
  const [hexStart, setHexStart] = useState<number>(0);
  const [hexLen, setHexLen] = useState<number>(4096);
  const [hexBytesPerLine, setHexBytesPerLine] = useState<number>(16);

  const selectedFile = useMemo(
    () => files.find((f) => f.id === selectedFileId) ?? null,
    [files, selectedFileId],
  );

  const [hexTarget, setHexTarget] = useState<
    | { kind: "apple"; appleOffset: number }
    | { kind: "manifest"; offset: number }
    | null
  >(null);

  function removeFile(id: string) {
    setFiles((prev) => {
      const next = prev.filter((f) => f.id !== id);
      // adjust selected
      if (selectedFileId === id) setSelectedFileId(next[0]?.id ?? null);
      // adjust compare picks
      if (compareA === id) setCompareA(null);
      if (compareB === id) setCompareB(null);
      // clear compare result if it referenced removed file
      if (compareResult && (compareA === id || compareB === id)) setCompareResult(null);
      return next;
    });
  }

  async function onUpload(inputFiles: FileList | null) {
    if (!inputFiles?.length) return;
    setBusy(true);
    setError(null);
    try {
      const next: LoadedFile[] = [];
      for (const file of Array.from(inputFiles)) {
        const ab = await file.arrayBuffer();
        const u8 = new Uint8Array(ab);
        const sha = await sha256Hex(ab);
        const analysis = await analyzeFile(file);
        next.push({
          id: crypto.randomUUID(),
          file,
          buf: u8,
          sha256: sha,
          analysis,
        });
      }
      setFiles((prev) => {
        const merged = [...prev, ...next];
        if (!selectedFileId && merged.length) setSelectedFileId(merged[0].id);
        return merged;
      });
      if (!selectedFileId && next.length) setSelectedFileId(next[0].id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function clearAll() {
    setFiles([]);
    setSelectedFileId(null);
    setCompareA(null);
    setCompareB(null);
    setCompareResult(null);
    setHexTarget(null);
  }

  function mainDevice(blocks: AppleBlock[]): { type?: string; model?: string } {
    const mains = blocks
      .filter((b) => b.blockType === "main_device_block" && b.modelCode?.value)
      .sort((a, b) => b.confidence - a.confidence);
    const m = mains[0];
    return { type: m?.deviceType?.value, model: m?.modelCode?.value };
  }

  function reportForSelected(): string {
    if (!selectedFile) return "";
    return JSON.stringify(selectedFile.analysis, null, 2);
  }

  async function copyReportJson() {
    const text = reportForSelected();
    if (!text) return;
    await navigator.clipboard.writeText(text);
  }

  function downloadJson() {
    if (!selectedFile) return;
    const blob = new Blob([reportForSelected()], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedFile.analysis.fileName}.report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function runCompare() {
    setCompareResult(null);
    setError(null);
    if (!compareA || !compareB || compareA === compareB) {
      setError("Select two different files to compare.");
      return;
    }
    const a = files.find((f) => f.id === compareA);
    const b = files.find((f) => f.id === compareB);
    if (!a || !b) {
      setError("Selected files not found.");
      return;
    }
    const res = compareFiles(
      a.analysis.fileName,
      a.buf,
      a.sha256,
      a.analysis.deviceBlocks,
      a.analysis.fileStats,
      a.analysis.firmwareBlocks,
      b.analysis.fileName,
      b.buf,
      b.sha256,
      b.analysis.deviceBlocks,
      b.analysis.fileStats,
      b.analysis.firmwareBlocks,
    );
    setCompareResult(res);
    setTab("Compare");
  }

  const hexPreview = useMemo(() => {
    if (!selectedFile) return "";
    const start = Math.max(0, Math.min(selectedFile.buf.length, hexStart));
    const len = Math.max(0, Math.min(selectedFile.buf.length - start, hexLen));
    return hexdump(selectedFile.buf, start, len, hexBytesPerLine);
  }, [selectedFile, hexStart, hexLen, hexBytesPerLine]);

  const hexModalPreview = useMemo(() => {
    if (!selectedFile || hexModalOffset === null) return "";
    const start = Math.max(0, hexModalOffset - 64);
    return hexdump(selectedFile.buf, start, 256, 16);
  }, [selectedFile, hexModalOffset]);

  async function copyHexModal() {
    if (!hexModalPreview) return;
    await navigator.clipboard.writeText(hexModalPreview);
  }

  return (
    <div className="container">
      <div className="header">
        <div>
          <div className="title">Apple BIN Device Structure Analyzer</div>
          <div className="subtitle">
            Local, browser-only analysis. Files are not uploaded anywhere.
          </div>
        </div>
        <div className="row">
          <button className="btn danger" onClick={clearAll} disabled={!files.length}>
            Clear all
          </button>
        </div>
      </div>

      <div className="grid">
        <div className="panel">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div style={{ fontWeight: 700 }}>Upload</div>
            <div className="small">{busy ? "Scanning…" : ""}</div>
          </div>
          <div style={{ marginTop: 8 }}>
            <input
              type="file"
              multiple
              accept=".bin,.BIN,application/octet-stream"
              onChange={(e) => onUpload(e.target.files)}
              disabled={busy}
            />
          </div>
          <div className="small" style={{ marginTop: 8 }}>
            Shows filename, size, SHA256. Detects blocks by structure/patterns (not fixed offsets).
          </div>

          {error ? (
            <div className="error" style={{ marginTop: 10 }}>
              {error}
            </div>
          ) : null}

          <div style={{ marginTop: 14, fontWeight: 700 }}>Files</div>
          {!files.length ? (
            <div className="small" style={{ marginTop: 8 }}>
              Upload one or more Apple `.bin` dumps to start.
            </div>
          ) : (
            <div style={{ marginTop: 8 }}>
              <table className="table">
              <thead>
                <tr>
                  <th>Pick</th>
                  <th>Filename</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => {
                  const main = mainDevice(f.analysis.deviceBlocks);
                  return (
                    <tr key={f.id}>
                      <td className="mono">
                        <div className="row">
                          <input
                            type="radio"
                            name="selected"
                            checked={selectedFileId === f.id}
                            onChange={() => setSelectedFileId(f.id)}
                            title="Select file for analysis tabs"
                          />
                          <label className="small">View</label>
                        </div>
                        <div className="row" style={{ marginTop: 6 }}>
                          <input
                            type="radio"
                            name="compareA"
                            checked={compareA === f.id}
                            onChange={() => {
                              setCompareA(f.id);
                              if (compareB === f.id) setCompareB(null);
                            }}
                            title="Compare as A"
                          />
                          <label className="small">A</label>
                          <input
                            type="radio"
                            name="compareB"
                            checked={compareB === f.id}
                            onChange={() => {
                              setCompareB(f.id);
                              if (compareA === f.id) setCompareA(null);
                            }}
                            title="Compare as B"
                          />
                          <label className="small">B</label>
                          <button
                            className="btn danger"
                            onClick={() => removeFile(f.id)}
                            title="Remove file from list"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600 }}>{f.analysis.fileName}</div>
                        <div className="small mono" style={{ marginTop: 2 }}>
                          {f.analysis.sha256.slice(0, 16)}…
                        </div>
                        <div className="small" style={{ marginTop: 2 }}>
                          {main.type ? (
                            <>
                              <span className="badge green">
                                {main.type} / {main.model ?? "?"}
                              </span>
                            </>
                          ) : (
                            <span className="badge gray">No main device block</span>
                          )}
                        </div>
                      </td>
                      <td className="mono">{fmtBytes(f.analysis.sizeBytes)}</td>
                    </tr>
                  );
                })}
              </tbody>
              </table>
            </div>
          )}

          <div className="row" style={{ marginTop: 12 }}>
            <button
              className="btn primary"
              onClick={runCompare}
              disabled={!compareA || !compareB || compareA === compareB}
              title="Pick A and B first"
            >
              Compare selected files
            </button>
          </div>
        </div>

        <div className="panel panelRight">
          <div className="tabs">
            {(
              [
                "Summary",
                "Apple Device Blocks",
                "MacBook SPI Blocks",
                "CD3217 Firmware",
                "Thunderbolt / Retimer",
                "Metadata / Manifest",
                "Hex Preview",
                "Compare",
                "Export",
              ] as Tab[]
            ).map(
              (t) => (
                <button
                  key={t}
                  className={tab === t ? "tab active" : "tab"}
                  onClick={() => setTab(t)}
                >
                  {t}
                </button>
              ),
            )}
          </div>

          {!selectedFile ? (
            <div className="small" style={{ marginTop: 10 }}>
              Select a file to view results.
            </div>
          ) : tab === "Summary" ? (
            <div style={{ marginTop: 10 }}>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>filename</th>
                    <th>size</th>
                    <th>sha256</th>
                    <th>main device type</th>
                    <th>main model code</th>
                    <th>family</th>
                    <th># Apple blocks</th>
                    <th># CD3217 blocks</th>
                    <th># Thunderbolt blocks</th>
                    <th># manifest markers</th>
                    <th>FF%</th>
                    <th>00%</th>
                    <th>entropy</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const main = mainDevice(selectedFile.analysis.deviceBlocks);
                    return (
                      <tr>
                        <td>{selectedFile.analysis.fileName}</td>
                        <td className="mono">{fmtBytes(selectedFile.analysis.sizeBytes)}</td>
                        <td className="mono">{selectedFile.analysis.sha256}</td>
                        <td>{main.type ?? "—"}</td>
                        <td className="mono">{main.model ?? "—"}</td>
                        <td className="mono">{selectedFile.analysis.detectedFamily}</td>
                        <td className="mono">{selectedFile.analysis.deviceBlocks.length}</td>
                        <td className="mono">{selectedFile.analysis.firmwareBlocks.length}</td>
                        <td className="mono">{selectedFile.analysis.thunderboltBlocks.length}</td>
                        <td className="mono">{selectedFile.analysis.manifestMarkers.length}</td>
                        <td className="mono">
                          {selectedFile.analysis.fileStats.ffPercentage.toFixed(2)}
                        </td>
                        <td className="mono">
                          {selectedFile.analysis.fileStats.zeroPercentage.toFixed(2)}
                        </td>
                        <td className="mono">
                          {selectedFile.analysis.fileStats.entropy.toFixed(2)}
                        </td>
                      </tr>
                    );
                  })()}
                </tbody>
                </table>
              </div>
            </div>
          ) : tab === "Apple Device Blocks" ? (
            <div style={{ marginTop: 10 }}>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>block type</th>
                    <th>Apple Inc. offset</th>
                    <th>marker</th>
                    <th>type</th>
                    <th>model</th>
                    <th>confidence</th>
                    <th>actions</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedFile.analysis.deviceBlocks
                    .filter(
                      (b) =>
                        b.blockType === "main_device_block" ||
                        b.blockType === "secondary_subsystem_block" ||
                        b.blockType === "unknown_block",
                    )
                    .map((b, idx) => (
                    <tr key={`${b.appleOffset}-${idx}`}>
                      <td>
                        <span className={badgeClass(b.blockType)}>{b.blockType}</span>
                      </td>
                      <td className="mono">{b.appleOffsetHex}</td>
                      <td className="mono">
                        {b.marker ? `${b.marker.value} @ ${b.marker.offsetHex}` : "—"}
                      </td>
                      <td className="mono">
                        {b.deviceType ? `${b.deviceType.value} @ ${b.deviceType.offsetHex}` : "—"}
                      </td>
                      <td className="mono">
                        {b.modelCode ? `${b.modelCode.value} @ ${b.modelCode.offsetHex}` : "—"}
                      </td>
                      <td className="mono">{b.confidence.toFixed(2)}</td>
                      <td>
                        <button
                          className="btn"
                          onClick={() => {
                            setHexTarget({ kind: "apple", appleOffset: b.appleOffset });
                            setTab("Hex Preview");
                          }}
                        >
                          Hex
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
              <div className="small" style={{ marginTop: 10 }}>
                Detection is heuristic: it finds `Apple Inc.` then looks near it for `iPhone` / `iPad` / `ACE1P`,
                plus a plausible model code (`DxxDEV` / `Jxxx`) and nearby manifest markers.
              </div>
            </div>
          ) : tab === "MacBook SPI Blocks" ? (
            <div style={{ marginTop: 10 }}>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>block type</th>
                    <th>Apple Inc. offset</th>
                    <th>marker</th>
                    <th>type</th>
                    <th>platform code</th>
                    <th>confidence</th>
                    <th>duplicate group</th>
                    <th>actions</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedFile.analysis.deviceBlocks
                    .filter((b) => b.blockType === "macintosh_device_block")
                    .map((b, idx) => (
                      <tr key={`${b.appleOffset}-${idx}`}>
                        <td>
                          <span className={badgeClass(b.blockType)}>{b.blockType}</span>
                        </td>
                        <td className="mono">{b.appleOffsetHex}</td>
                        <td className="mono">
                          {b.marker ? `${b.marker.value} @ ${b.marker.offsetHex}` : "—"}
                        </td>
                        <td className="mono">
                          {b.deviceType
                            ? `${b.deviceType.value} @ ${b.deviceType.offsetHex}`
                            : "—"}
                        </td>
                        <td className="mono">
                          {b.modelCode
                            ? `${b.modelCode.value} @ ${b.modelCode.offsetHex}`
                            : "—"}
                        </td>
                        <td className="mono">{b.confidence.toFixed(2)}</td>
                        <td className="mono">{b.duplicateGroup ?? "—"}</td>
                        <td>
                          <button
                            className="btn"
                            onClick={() => {
                              setHexTarget({ kind: "apple", appleOffset: b.appleOffset });
                              setTab("Hex Preview");
                            }}
                          >
                            Hex
                          </button>
                        </td>
                      </tr>
                    ))}
                </tbody>
                </table>
              </div>
              <div className="small" style={{ marginTop: 10 }}>
                Macintosh SPI heuristic: `Apple Inc.` → `Macintosh` → platform code like `J314P01P`. Duplicates may
                appear in mirrored regions of the dump.
              </div>
            </div>
          ) : tab === "CD3217 Firmware" ? (
            <div style={{ marginTop: 10 }}>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>offset</th>
                    <th>chip</th>
                    <th>HW</th>
                    <th>FW version</th>
                    <th>variant</th>
                    <th>duplicate group</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedFile.analysis.firmwareBlocks.map((b) => (
                    <tr key={`${b.offset}-${b.variant ?? ""}`}>
                      <td className="mono">{b.offsetHex}</td>
                      <td className="mono">{b.chip}</td>
                      <td className="mono">{b.hw ?? "—"}</td>
                      <td className="mono">{b.fwVersion ?? "—"}</td>
                      <td className="mono">{b.variant ?? "—"}</td>
                      <td className="mono">{b.duplicateGroup ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
            </div>
          ) : tab === "Thunderbolt / Retimer" ? (
            <div style={{ marginTop: 10 }}>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>block type</th>
                    <th>offset</th>
                    <th>markers</th>
                    <th>duplicate group</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedFile.analysis.thunderboltBlocks.map((b) => (
                    <tr key={`${b.blockType}-${b.offset}`}>
                      <td>
                        <span className={badgeClass(b.blockType)}>{b.blockType}</span>
                      </td>
                      <td className="mono">{b.offsetHex}</td>
                      <td className="small mono">{b.markers.join(", ")}</td>
                      <td className="mono">{b.duplicateGroup ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
            </div>
          ) : tab === "Metadata / Manifest" ? (
            <div style={{ marginTop: 10 }}>
              <div className="small" style={{ marginBottom: 10 }}>
                This view treats “manifest” broadly as metadata/config blocks (classic Apple markers, identity blocks,
                CD3217/Thunderbolt/retimer sections, and ranked ASCII strings). Missing IM4M does not mean “no metadata”.
              </div>
              <div className="row" style={{ marginBottom: 10 }}>
                <label className="small">Category</label>
                <select
                  className="btn"
                  value={metadataCategory}
                  onChange={(e) => setMetadataCategory(e.target.value)}
                >
                  <option>All</option>
                  <option>Classic Apple Manifest</option>
                  <option>Apple Identity</option>
                  <option>MacBook SPI Metadata</option>
                  <option>CD3217 Firmware Metadata</option>
                  <option>Thunderbolt / DROM</option>
                  <option>Retimer / Config</option>
                  <option>Generic Strings</option>
                </select>
                <label className="small">
                  <input
                    type="checkbox"
                    checked={showAllStrings}
                    onChange={(e) => setShowAllStrings(e.target.checked)}
                    style={{ marginRight: 8 }}
                  />
                  Show all extracted strings
                </label>
              </div>
              <div className="tableWrap">
                <table className="table tableWide">
                <thead>
                  <tr>
                    <th>category</th>
                    <th>subtype</th>
                    <th>marker</th>
                    <th>offset</th>
                    <th>value</th>
                    <th>confidence / score</th>
                    <th>notes</th>
                  </tr>
                </thead>
                <tbody>
                  {(showAllStrings
                    ? [
                        ...selectedFile.analysis.metadataBlocks.filter(
                          (m) => m.subtype !== "generic_ascii_string",
                        ),
                        ...selectedFile.analysis.genericStringsAll,
                      ]
                    : selectedFile.analysis.metadataBlocks
                  )
                    .filter((m) =>
                      metadataCategory === "All" ? true : m.category === metadataCategory,
                    )
                    .map((m) => (
                    <tr key={`${m.category}-${m.subtype}-${m.offset}-${m.primaryValue ?? ""}`}>
                      <td className="small">{m.category}</td>
                      <td className="small mono">{m.subtype}</td>
                      <td className="mono">{m.markers[0] ?? "—"}</td>
                      <td className="mono">
                        <button
                          className="btn"
                          onClick={() => {
                            setHexModalOffset(m.offset);
                          }}
                          title="Open hex snippet preview"
                        >
                          {m.offsetHex}
                        </button>
                      </td>
                      <td className="small mono">{m.primaryValue ?? m.markers.join(" ")}</td>
                      <td className="mono">
                        {m.score <= 1 ? m.score.toFixed(2) : m.score.toFixed(0)}
                      </td>
                      <td className="small">{m.notes ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
            </div>
          ) : tab === "Hex Preview" ? (
            <div style={{ marginTop: 10 }}>
              <div className="row">
                <div style={{ fontWeight: 700 }}>Hex preview</div>
                <div className="small">
                  {selectedFile ? `File: ${selectedFile.analysis.fileName}` : "Select a file to preview."}
                </div>
              </div>
              {selectedFile ? (
                <div className="row" style={{ marginTop: 10, alignItems: "flex-end" }}>
                  <div>
                    <div className="small">Start offset (hex)</div>
                    <input
                      className="btn mono"
                      value={toHexOffset(hexStart)}
                      onChange={(e) => {
                        const raw = e.target.value.trim().toLowerCase().replace(/^0x/, "");
                        const n = Number.parseInt(raw || "0", 16);
                        if (Number.isFinite(n)) setHexStart(Math.max(0, Math.min(n, selectedFile.buf.length)));
                      }}
                      style={{ width: 150 }}
                    />
                  </div>
                  <div>
                    <div className="small">Bytes to show</div>
                    <input
                      className="btn mono"
                      value={hexLen}
                      onChange={(e) => setHexLen(Math.max(0, Number(e.target.value) || 0))}
                      style={{ width: 140 }}
                    />
                  </div>
                  <div>
                    <div className="small">Bytes/line</div>
                    <input
                      className="btn mono"
                      value={hexBytesPerLine}
                      onChange={(e) =>
                        setHexBytesPerLine(Math.max(8, Math.min(32, Number(e.target.value) || 16)))
                      }
                      style={{ width: 120 }}
                    />
                  </div>
                  <div className="row">
                    <button
                      className="btn"
                      onClick={() => {
                        setHexStart(0);
                        setHexLen(4096);
                      }}
                    >
                      From start
                    </button>
                    <button
                      className="btn"
                      onClick={() => {
                        const base = hexTarget
                          ? hexTarget.kind === "apple"
                            ? hexTarget.appleOffset
                            : hexTarget.offset
                          : 0;
                        setHexStart(Math.max(0, base - 64));
                        setHexLen(512);
                      }}
                      disabled={!hexTarget}
                      title="Use last selected block/marker as center"
                    >
                      Around hit
                    </button>
                    <button
                      className="btn primary"
                      onClick={() => {
                        setHexStart(0);
                        setHexLen(selectedFile.buf.length);
                      }}
                      title="May be heavy for large files"
                    >
                      Full file
                    </button>
                  </div>
                  <div className="small mono" style={{ marginLeft: "auto" }}>
                    size: {selectedFile.buf.length.toLocaleString()} bytes
                  </div>
                </div>
              ) : null}
              <div className="codebox mono" style={{ marginTop: 10 }}>
                {selectedFile ? (hexPreview || "—") : "—"}
              </div>
            </div>
          ) : tab === "Compare" ? (
            <div style={{ marginTop: 10 }}>
              {!compareResult ? (
                <div className="small">Run “Compare selected files” to generate results.</div>
              ) : (
                <>
                  <div style={{ fontWeight: 700, marginBottom: 6 }}>Conclusion</div>
                  <div className="panel" style={{ marginBottom: 10 }}>
                    {compareResult.summary}
                  </div>
                  <div className="tableWrap">
                    <table className="table tableWide">
                    <thead>
                      <tr>
                        <th>field</th>
                        <th>file A</th>
                        <th>file B</th>
                        <th>result</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>filename</td>
                        <td>{compareResult.fileA.fileName}</td>
                        <td>{compareResult.fileB.fileName}</td>
                        <td className="mono">—</td>
                      </tr>
                      <tr>
                        <td>size</td>
                        <td className="mono">{fmtBytes(compareResult.fileA.sizeBytes)}</td>
                        <td className="mono">{fmtBytes(compareResult.fileB.sizeBytes)}</td>
                        <td>{compareResult.fileA.sizeBytes === compareResult.fileB.sizeBytes ? "same" : "different"}</td>
                      </tr>
                      <tr>
                        <td>sha256</td>
                        <td className="mono">{compareResult.fileA.sha256}</td>
                        <td className="mono">{compareResult.fileB.sha256}</td>
                        <td>{compareResult.fileA.sha256 === compareResult.fileB.sha256 ? "same" : "different"}</td>
                      </tr>
                      <tr>
                        <td>main model code</td>
                        <td className="mono">{compareResult.mainModelA ?? "—"}</td>
                        <td className="mono">{compareResult.mainModelB ?? "—"}</td>
                        <td>
                          {compareResult.mainModelA && compareResult.mainModelB
                            ? compareResult.mainModelA === compareResult.mainModelB
                              ? "match"
                              : "different"
                            : "unknown"}
                        </td>
                      </tr>
                      <tr>
                        <td>CD3217 variant</td>
                        <td className="mono">{compareResult.cd3217VariantA ?? "—"}</td>
                        <td className="mono">{compareResult.cd3217VariantB ?? "—"}</td>
                        <td>
                          {compareResult.cd3217VariantA && compareResult.cd3217VariantB
                            ? compareResult.cd3217VariantA === compareResult.cd3217VariantB
                              ? "match"
                              : "different"
                            : "unknown"}
                        </td>
                      </tr>
                      <tr>
                        <td>FF% / 00% / entropy</td>
                        <td className="mono">
                          {compareResult.fileA.fileStats.ffPercentage.toFixed(2)} /{" "}
                          {compareResult.fileA.fileStats.zeroPercentage.toFixed(2)} /{" "}
                          {compareResult.fileA.fileStats.entropy.toFixed(2)}
                        </td>
                        <td className="mono">
                          {compareResult.fileB.fileStats.ffPercentage.toFixed(2)} /{" "}
                          {compareResult.fileB.fileStats.zeroPercentage.toFixed(2)} /{" "}
                          {compareResult.fileB.fileStats.entropy.toFixed(2)}
                        </td>
                        <td className="mono">—</td>
                      </tr>
                      <tr>
                        <td>identical</td>
                        <td className="mono" colSpan={2}>
                          —
                        </td>
                        <td>{compareResult.identical ? "yes" : "no"}</td>
                      </tr>
                      <tr>
                        <td>differing bytes</td>
                        <td className="mono" colSpan={2}>
                          —
                        </td>
                        <td className="mono">{compareResult.differingBytes}</td>
                      </tr>
                      <tr>
                        <td>differing ranges</td>
                        <td className="mono" colSpan={2}>
                          —
                        </td>
                        <td className="mono">{compareResult.differingRanges.length}</td>
                      </tr>
                      <tr>
                        <td>largest ranges</td>
                        <td colSpan={3}>
                          {compareResult.largestRanges.length ? (
                            <div className="small mono">
                              {compareResult.largestRanges
                                .map(
                                  (r) =>
                                    `${toHexOffset(r.start)}..${toHexOffset(r.end)} (len=${r.length})`,
                                )
                                .join("\n")}
                            </div>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          ) : (
            <div style={{ marginTop: 10 }}>
              <div className="row">
                <button className="btn primary" onClick={copyReportJson} disabled={!selectedFile}>
                  Copy report JSON
                </button>
                <button className="btn" onClick={downloadJson} disabled={!selectedFile}>
                  Download JSON
                </button>
              </div>
              <div className="codebox mono" style={{ marginTop: 10 }}>
                {reportForSelected() || "—"}
              </div>
            </div>
          )}
        </div>
      </div>

      {selectedFile && hexModalOffset !== null ? (
        <div
          className="modalBackdrop"
          onClick={() => setHexModalOffset(null)}
          role="presentation"
        >
          <div
            className="modal"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            <div className="modalHeader">
              <div>
                <div style={{ fontWeight: 700 }}>Hex snippet</div>
                <div className="small mono">
                  {selectedFile.analysis.fileName} · offset {toHexOffset(hexModalOffset)}
                </div>
              </div>
              <div className="row">
                <button className="btn" onClick={copyHexModal}>
                  Copy hexdump
                </button>
                <button className="btn danger" onClick={() => setHexModalOffset(null)}>
                  Close
                </button>
              </div>
            </div>
            <div className="codebox mono">{hexModalPreview || "—"}</div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

