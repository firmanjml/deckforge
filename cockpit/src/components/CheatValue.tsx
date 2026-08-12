// Dynamic number control for value cheats.
// If the cheat uses a scan resolver, shows a scan workflow:
//   1. Enter current value → scan
//   2. Change in-game → enter new value → filter
//   3. When resolved → normal Set input
// If already resolved or using a static resolver, shows normal Set input.

import { useEffect, useState, type CSSProperties } from "react";
import { Button, ButtonItem, PanelSectionRow, TextField } from "@decky/ui";
import type { CheatInfo } from "../lib/types";
import { backend, ForgeError } from "../lib/backend";

interface Props {
  cheat: CheatInfo;
  busy: boolean;
  onSet: (id: string, value: number) => void;
}

export function CheatValue({ cheat, busy, onSet }: Props) {
  const [text, setText] = useState("");
  const [scanText, setScanText] = useState("");
  const [scanCount, setScanCount] = useState<number | null>(null);
  const [scanResolved, setScanResolved] = useState(false);
  const [scanMsg, setScanMsg] = useState("");

  // Check scan status on mount and when cheat changes
  useEffect(() => {
    setScanCount(null);
    setScanResolved(false);
    setScanMsg("");
    backend
      .scanResolveCount(cheat.id)
      .then((r) => {
        setScanCount(r.count);
        setScanResolved(r.resolved);
      })
      .catch(() => { });
  }, [cheat.id]);

  const handleScanStart = async () => {
    const val = Number(scanText);
    if (Number.isNaN(val)) return;
    setScanMsg("Scanning... this takes a few seconds");
    try {
      const r = await backend.scanResolveStart(cheat.id, val);
      setScanCount(r.count);
      setScanResolved(r.resolved);
      if (r.count <= 5 && r.count > 0) {
        setScanMsg(`Found ${r.count} matches! Change value in-game, then enter new value.`);
      } else if (r.count > 5) {
        setScanMsg(`Found ${r.count} matches. Change value in-game, then enter new value.`);
      } else {
        setScanMsg("No matches found. Check the value and try again.");
      }
    } catch (e) {
      setScanMsg(e instanceof ForgeError ? e.message : "Scan failed");
    }
    setScanText("");
  };

  const handleScanFilter = async () => {
    const val = Number(scanText);
    if (Number.isNaN(val)) return;
    setScanMsg("Filtering...");
    try {
      const r = await backend.scanResolveFilter(cheat.id, val);
      setScanCount(r.count);
      setScanResolved(r.resolved);
      if (r.count <= 5 && r.count > 0) {
        setScanMsg(`${r.count} matches! Press "Done" to lock the address.`);
      } else if (r.count > 5) {
        setScanMsg(`${r.count} matches. Change value again and filter.`);
      } else {
        setScanMsg("No matches. Value may have changed — start over.");
      }
    } catch (e) {
      setScanMsg(e instanceof ForgeError ? e.message : "Filter failed");
    }
    setScanText("");
  };

  const handleScanDone = async () => {
    setScanMsg("Resolving...");
    try {
      const r = await backend.scanResolveDone(cheat.id);
      setScanResolved(true);
      setScanMsg(`Resolved! Current value: ${r.current_value ?? "?"}`);
    } catch (e) {
      setScanMsg(e instanceof ForgeError ? e.message : "Resolve failed");
    }
  };

  const handleSet = () => {
    const n = Number(text);
    if (Number.isNaN(n)) return;
    onSet(cheat.id, n);
    setText("");
  };

  // Scan-resolve workflow
  if (scanCount !== null && !scanResolved) {
    return (
      <PanelSectionRow>
        <div style={valueControlWrap}>
          <div style={{ marginBottom: "4px", fontWeight: "bold" }}>{cheat.name}</div>
          {scanCount === 0 && (
            <div style={{ marginBottom: "4px" }}>
              <span style={{ fontSize: "13px", color: "#9a9a9a" }}>
                Not found yet. Enter current in-game value:
              </span>
            </div>
          )}
          {scanCount !== null && scanCount > 0 && scanCount <= 5 && (
            <ButtonItem layout="below" disabled={busy} onClick={handleScanDone}>
              Lock Address ({scanCount} matches)
            </ButtonItem>
          )}
          <div style={valueLabel}>
            {scanCount === 0 ? "Current value" : "New value (after changing in-game)"}
          </div>
          <div style={valueInputRow}>
            <div style={valueInputWrap}>
              <TextField
                value={scanText}
                style={valueTextField}
                mustBeNumeric
                disabled={busy}
                onChange={(e) => setScanText(e.target.value)}
              />
            </div>
            <Button
              style={valueButton}
              disabled={busy}
              onClick={scanCount === 0 ? handleScanStart : handleScanFilter}
            >
              {scanCount === 0 ? "Scan" : "Filter"}
            </Button>
          </div>
          {scanMsg && (
            <div style={{ fontSize: "12px", marginTop: "4px", color: "#9a9a9a" }}>
              {scanMsg}
            </div>
          )}
          {cheat.last_error && (
            <div style={{ fontSize: "12px", color: "#ff6b6b", marginTop: "4px" }}>
              {cheat.last_error}
            </div>
          )}
        </div>
      </PanelSectionRow>
    );
  }

  // Normal value input (resolved or non-scan cheat)
  return (
    <PanelSectionRow>
      <div style={valueLabel}>{cheat.name}</div>
      <div style={valueInputRow}>
        <div style={valueInputWrap}>
          <TextField
            value={text}
            style={valueTextField}
            mustBeNumeric
            disabled={busy}
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <Button style={valueButton} disabled={busy} onClick={handleSet}>
          Set
        </Button>
      </div>
      {scanResolved && (
        <div style={{ fontSize: "11px", paddingLeft: "16px", color: "#66c0f4" }}>
          ✓ Address resolved
        </div>
      )}
      {cheat.last_error && (
        <div
          style={{
            color: "#ff6b6b",
            fontSize: "12px",
            paddingLeft: "16px",
            paddingBottom: "6px",
          }}
        >
          {cheat.last_error}
        </div>
      )}
    </PanelSectionRow>
  );
}

const valueControlWrap: CSSProperties = {
  boxSizing: "border-box",
  minWidth: 0,
  width: "100%",
  padding: "6px 16px 8px",
  overflow: "hidden",
};

const valueLabel: CSSProperties = {
  fontSize: "14px",
  fontWeight: 600,
  lineHeight: "18px",
  marginBottom: "6px",
};

const valueInputRow: CSSProperties = {
  alignItems: "center",
  boxSizing: "border-box",
  display: "flex",
  gap: "8px",
  minHeight: "40px",
  minWidth: 0,
  width: "100%",
};

const valueInputWrap: CSSProperties = {
  flex: "1 1 auto",
  minWidth: 0,
};

const valueTextField: CSSProperties = {
  boxSizing: "border-box",
  maxWidth: "100%",
  minWidth: 0,
  width: "100%",
};

const valueButton: CSSProperties = {
  boxSizing: "border-box",
  flex: "0 0 64px",
  height: "40px",
  lineHeight: "18px",
  margin: 0,
  maxWidth: "64px",
  minHeight: "40px",
  minWidth: "64px",
  padding: "0 8px",
};
