// DeckForge cockpit entry point.
//
// Presentation only. Polls engine status, lets the user attach a running Steam
// game by AppID, and renders cheats dynamically from the trainer definition
// returned by Forge. Toggles/edits flow Cockpit → Relay → Forge; the UI only
// reflects a change after Forge confirms it.

import { useCallback, useEffect, useState } from "react";
import {
  ButtonItem,
  DialogButton,
  Focusable,
  PanelSection,
  PanelSectionRow,
  Navigation,
  TextField,
  staticClasses,
} from "@decky/ui";
import { definePlugin, routerHook, toaster } from "@decky/api";
import { FaGamepad, FaStore, FaSyncAlt } from "react-icons/fa";

import { ForgeError, backend } from "./lib/backend";
import type { EngineStatus, TrainerInfo } from "./lib/types";
import { CheatToggle } from "./components/CheatToggle";
import { CheatValue } from "./components/CheatValue";
import { CheatAction } from "./components/CheatAction";
import { StorePage } from "./components/StorePage";

// Module-level ref so TitleView can trigger the reload handler owned by Content.
// Content sets this on every render; TitleView calls it when the reload icon is pressed.
let reloadTrainerFn: (() => Promise<void>) | null = null;

function Content() {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [trainer, setTrainer] = useState<TrainerInfo | null>(null);
  const [connected, setConnected] = useState(false);
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  // const [appIdInput, setAppIdInput] = useState("");
  // const [attaching, setAttaching] = useState(false);

  const refresh = useCallback(async () => {
    try {
      let st = await backend.getStatus();
      // Auto-discovery: when nothing is attached, look for a running Steam
      // game and attach automatically (silent — no toasts on this path).
      // Auto-detach is handled engine-side: get_status drops dead processes,
      // so a game that exited shows up here as unattached and is re-detected.
      if (!st.attached) {
        const detected = await backend.detectGame().catch(() => null);
        if (detected) {
          await backend.attachGame(detected.appId).catch(() => {});
          st = await backend.getStatus().catch(() => st);
        }
      }
      setStatus(st);
      // The engine is "connected" only when this full path succeeds.
      setConnected(st.running);
      if (st.attached) {
        setTrainer(await backend.getTrainer());
      } else {
        setTrainer(null);
      }
    } catch {
      setConnected(false);
      setStatus(null);
      setTrainer(null);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 4000);
    return () => clearInterval(id);
  }, [refresh]);

  const setBusy = (id: string, on: boolean) => {
    setBusyIds((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const errMsg = (e: unknown): string =>
    e instanceof ForgeError ? e.message : "operation failed";

  const handleToggle = async (id: string, next: boolean) => {
    setBusy(id, true);
    try {
      if (next) await backend.enableCheat(id);
      else await backend.disableCheat(id);
      setTrainer(await backend.getTrainer());
    } catch (e) {
      toaster.toast({ title: "DeckForge", body: errMsg(e) });
      await refresh();
    } finally {
      setBusy(id, false);
    }
  };

  const handleSet = async (id: string, value: number) => {
    setBusy(id, true);
    try {
      await backend.setValue(id, value);
      toaster.toast({ title: "DeckForge", body: `${id} = ${value}` });
      setTrainer(await backend.getTrainer());
    } catch (e) {
      toaster.toast({ title: "DeckForge", body: errMsg(e) });
    } finally {
      setBusy(id, false);
    }
  };

  const handleTrigger = async (id: string) => {
    setBusy(id, true);
    try {
      const cheat = trainer?.cheats.find((c) => c.id === id);
      await backend.triggerCheat(id);
      toaster.toast({ title: "DeckForge", body: `${cheat?.name ?? id} applied!` });
      setTrainer(await backend.getTrainer());
    } catch (e) {
      toaster.toast({ title: "DeckForge", body: errMsg(e) });
    } finally {
      setBusy(id, false);
    }
  };

  // const handleAttach = async () => {
  //   const appId = Number(appIdInput);
  //   if (!appId) return;
  //   setAttaching(true);
  //   try {
  //     await backend.attachGame(appId);
  //     await refresh();
  //   } catch (e) {
  //     toaster.toast({ title: "DeckForge", body: errMsg(e) });
  //   } finally {
  //     setAttaching(false);
  //   }
  // };

  const handleReload = async () => {
    try {
      await backend.reloadTrainer();
      setTrainer(await backend.getTrainer());
    } catch (e) {
      toaster.toast({ title: "DeckForge", body: errMsg(e) });
    }
  };

  // Expose reload handler to the title bar's reload icon.
  reloadTrainerFn = handleReload;

  const gameName = status?.game?.name ?? "Not detected";
  const trainerName = status?.game?.name ? status?.trainer?.name : "None";

  return (
    <div>
      <PanelSection title="DeckForge">
        <PanelSectionRow>
          <div style={statusRow}>
            <span>Engine</span>
            <span>{connected ? "Connected ●" : "Disconnected ○"}</span>
          </div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={statusRow}>
            <span>Game</span>
            <span>{gameName}</span>
          </div>
        </PanelSectionRow>
        <PanelSectionRow>
          <div style={statusRow}>
            <span>Trainer</span>
            <span>{trainerName}</span>
          </div>
        </PanelSectionRow>
      </PanelSection>

      {/* The trainer store is opened from the Shop icon button next to the
          DeckForge title in the QAM header. It opens as a full-page route,
          just like CSSLoader's theme manager. */}

      {/* {connected && !status?.attached && (
        <PanelSection title="Attach Game">
          <PanelSectionRow>
            <div style={{ padding: "0 16px" }}>
              <TextField
                label="Steam AppID"
                value={appIdInput}
                mustBeNumeric
                disabled={attaching}
                onChange={(e) => setAppIdInput(e.target.value)}
                inlineControls={
                  <ButtonItem layout="inline" disabled={attaching} onClick={handleAttach}>
                    Attach
                  </ButtonItem>
                }
              />
            </div>
          </PanelSectionRow>
        </PanelSection>
      )} */}

      {!connected && (
        <PanelSection title="">
          <PanelSectionRow>
            <div style={{ padding: "8px 16px", color: "#9a9a9a" }}>
              Engine not connected. Make sure DeckForge is running.
            </div>
          </PanelSectionRow>
        </PanelSection>
      )}

      {trainer && (
        <PanelSection title={trainer.game.name}>
          {[...trainer.cheats]
            .sort((a, b) => cheatControlRank(a.control) - cheatControlRank(b.control))
            .map((cheat) => {
              const busy = busyIds.has(cheat.id);
              if (cheat.control === "toggle") {
                return (
                  <CheatToggle
                    key={cheat.id}
                    cheat={cheat}
                    busy={busy}
                    onToggle={handleToggle}
                  />
                );
              }
              if (cheat.control === "number") {
                return (
                  <CheatValue key={cheat.id} cheat={cheat} busy={busy} onSet={handleSet} />
                );
              }
              if (cheat.control === "action") {
                return (
                  <CheatAction
                    key={cheat.id}
                    cheat={cheat}
                    busy={busy}
                    onTrigger={handleTrigger}
                  />
                );
              }
              // slider / select controls are rendered in a later milestone.
              return null;
            })}
        </PanelSection>
      )}
    </div>
  );
}

const statusRow: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  padding: "8px 16px",
};

const cheatControlRank = (control: string) => {
  if (control === "toggle") return 0;
  if (control === "action") return 1;
  if (control === "select") return 2;
  if (control === "slider") return 3;
  if (control === "number") return 4;
  return 1;
};

/** Custom title bar — "DeckForge" on the left, reload + store icon buttons on the right. */
function TitleView() {
  const [reloading, setReloading] = useState(false);

  const onStoreClick = () => {
    Navigation.CloseSideMenus();
    Navigation.Navigate("/deckforge/store");
  };

  const onReloadClick = async () => {
    if (reloading) return;
    setReloading(true);
    try {
      if (reloadTrainerFn) await reloadTrainerFn();
    } finally {
      setReloading(false);
    }
  };

  return (
    <Focusable
      style={{
        display: "flex",
        padding: "0",
        width: "100%",
        boxShadow: "none",
        alignItems: "center",
        justifyContent: "space-between",
      }}
      className={staticClasses.Title}
    >
      <style>{`
        @keyframes deckforge-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
      <div style={{ marginRight: "auto" }}>DeckForge</div>
      <DialogButton
        style={{
          height: "28px",
          width: "40px",
          minWidth: 0,
          padding: "10px 12px",
        }}
        onClick={onReloadClick}
      >
        <FaSyncAlt
          style={{
            marginTop: "-4px",
            display: "block",
            animation: reloading ? "deckforge-spin 0.8s linear infinite" : "",
          }}
        />
      </DialogButton>
      <DialogButton
        style={{
          height: "28px",
          width: "40px",
          minWidth: 0,
          padding: "10px 12px",
        }}
        onClick={onStoreClick}
      >
        <FaStore style={{ marginTop: "-4px", display: "block" }} />
      </DialogButton>
    </Focusable>
  );
}

const STORE_ROUTE = "/deckforge/store";

export default definePlugin(() => {
  routerHook.addRoute(STORE_ROUTE, StorePage);

  return {
    name: "DeckForge",
    titleView: <TitleView />,
    content: <Content />,
    icon: <FaGamepad />,
    onDismount() {
      routerHook.removeRoute(STORE_ROUTE);
    },
  };
});
