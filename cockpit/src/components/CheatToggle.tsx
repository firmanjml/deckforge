// Dynamic toggle control for `control: "toggle"` cheats (patch actions).
// Reflects Forge's truth: `checked` follows the engine-reported `enabled` state,
// and the control is locked while a request is in flight. UI updates only after
// Forge reports success.

import { PanelSectionRow, ToggleField } from "@decky/ui";
import type { CheatInfo } from "../lib/types";

interface Props {
  cheat: CheatInfo;
  busy: boolean;
  onToggle: (id: string, next: boolean) => void;
}

export function CheatToggle({ cheat, busy, onToggle }: Props) {
  return (
    <PanelSectionRow>
      <ToggleField
        label={cheat.name}
        checked={cheat.enabled}
        disabled={busy}
        onChange={(checked: boolean) => onToggle(cheat.id, checked)}
      />
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
