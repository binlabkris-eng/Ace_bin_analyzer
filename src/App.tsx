import { useMemo, useState } from "react";
import {
  analyzeFile,
  compareFiles,
  hexdump,
  sha256Hex,
  toHexOffset,
} from "./lib/analyzer";
import type { AppleBlock, CompareResult, FileAnalysis } from "./lib/types";

type Tab = "Summary" | "Device Blocks" | "Manifest" | "Hex Preview" | "Compare" | "Export";

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

  const selectedFile = useMemo(
    () => files.find((f) => f.id === selectedFileId) ?? null,
    [files, selectedFileId],
  );

  const [hexTarget, setHexTarget] = useState<
    | { kind: "apple"; appleOffset: number }
    | { kind: "manifest"; offset: number }
    | null
  >(null);

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
      b.analysis.fileName,
      b.buf,
      b.sha256,
      b.analysis.deviceBlocks,
    );
    setCompareResult(res);
    setTab("Compare");
  }

  const hexPreview = useMemo(() => {
    if (!selectedFile || !hexTarget) return "";
    const base =
      hexTarget.kind === "apple" ? hexTarget.appleOffset : hexTarget.offset;
    const start = Math.max(0, base - 64);
    return hexdump(selectedFile.buf, start, 256, 16);
  }, [selectedFile, hexTarget]);

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
            Clear
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
            <table className="table" style={{ marginTop: 8 }}>
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
                            onChange={() => setCompareA(f.id)}
                            title="Compare as A"
                          />
                          <label className="small">A</label>
                          <input
                            type="radio"
                            name="compareB"
                            checked={compareB === f.id}
                            onChange={() => setCompareB(f.id)}
                            title="Compare as B"
                          />
                          <label className="small">B</label>
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
          )}

          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn primary" onClick={runCompare} disabled={files.length < 2}>
              Compare selected files
            </button>
          </div>
        </div>

        <div className="panel">
          <div className="tabs">
            {(["Summary", "Device Blocks", "Manifest", "Hex Preview", "Compare", "Export"] as Tab[]).map(
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
              <table className="table">
                <thead>
                  <tr>
                    <th>filename</th>
                    <th>size</th>
                    <th>sha256</th>
                    <th>main device type</th>
                    <th>main model code</th>
                    <th># Apple blocks</th>
                    <th># manifest markers</th>
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
                        <td className="mono">{selectedFile.analysis.deviceBlocks.length}</td>
                        <td className="mono">{selectedFile.analysis.manifestMarkers.length}</td>
                      </tr>
                    );
                  })()}
                </tbody>
              </table>
            </div>
          ) : tab === "Device Blocks" ? (
            <div style={{ marginTop: 10 }}>
              <table className="table">
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
                  {selectedFile.analysis.deviceBlocks.map((b, idx) => (
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
              <div className="small" style={{ marginTop: 10 }}>
                Detection is heuristic: it finds `Apple Inc.` then looks near it for `iPhone` / `iPad` / `ACE1P`,
                plus a plausible model code (`DxxDEV` / `Jxxx`) and nearby manifest markers.
              </div>
            </div>
          ) : tab === "Manifest" ? (
            <div style={{ marginTop: 10 }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>marker</th>
                    <th>offset</th>
                    <th>notes</th>
                    <th>actions</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedFile.analysis.manifestMarkers.map((m) => (
                    <tr key={`${m.marker}-${m.offset}`}>
                      <td className="mono">
                        <span className="badge purple">{m.marker}</span>
                      </td>
                      <td className="mono">{m.offsetHex}</td>
                      <td className="small">
                        {m.marker === "IM4M" || m.marker === "BORD" || m.marker === "CHIP"
                          ? "Strong proximity hint for Apple structure area."
                          : "Manifest marker."}
                      </td>
                      <td>
                        <button
                          className="btn"
                          onClick={() => {
                            setHexTarget({ kind: "manifest", offset: m.offset });
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
          ) : tab === "Hex Preview" ? (
            <div style={{ marginTop: 10 }}>
              <div className="row">
                <div style={{ fontWeight: 700 }}>Hex preview</div>
                <div className="small">
                  {hexTarget
                    ? `Centered near ${hexTarget.kind} @ ${toHexOffset(
                        hexTarget.kind === "apple" ? hexTarget.appleOffset : hexTarget.offset,
                      )}`
                    : "Select a block/marker to preview."}
                </div>
              </div>
              <div className="codebox mono" style={{ marginTop: 10 }}>
                {hexTarget ? hexPreview : "—"}
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
                  <table className="table">
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
    </div>
  );
}

