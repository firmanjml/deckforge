// Action control: a button that triggers a value write (e.g. "Set Currency 99999").
// For auto-scan cheats, pressing the button finds and writes automatically.

import { ButtonItem, PanelSectionRow } from "@decky/ui";
import type { CheatInfo } from "../lib/types";

interface Props {
  cheat: CheatInfo;
  busy: boolean;
  onTrigger: (id: string) => void;
}

export function CheatAction({ cheat, busy, onTrigger }: Props) {
  return (
    <PanelSectionRow>
      <ButtonItem layout="below" disabled={busy} onClick={() => onTrigger(cheat.id)}>
        {cheat.name}
      </ButtonItem>
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
