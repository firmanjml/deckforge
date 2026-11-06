// Number control for value cheats: enter a value and press Set.

import { useState, type CSSProperties } from "react";
import { Button, PanelSectionRow, TextField } from "@decky/ui";
import type { CheatInfo } from "../lib/types";

interface Props {
  cheat: CheatInfo;
  busy: boolean;
  onSet: (id: string, value: number) => void;
}

export function CheatValue({ cheat, busy, onSet }: Props) {
  const [text, setText] = useState("");

  const handleSet = () => {
    const n = Number(text);
    if (Number.isNaN(n)) return;
    onSet(cheat.id, n);
    setText("");
  };

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
