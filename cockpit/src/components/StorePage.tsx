// Trainer store — full-page route.
//
// Presentation only. This is the DeckForge equivalent of CSSLoader's theme
// manager: a dedicated full-screen page registered via routerHook.addRoute.
// Two tabs: "Browse" (remote catalog) and "Installed" (locally installed
// trainers). A search field filters both tabs by game name. All memory/trainer
// logic stays in Forge.
//
// Opened from the shop icon button next to the DeckForge title in the QAM.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  DialogButton,
  DialogButtonPrimary,
  Navigation,
  PanelSectionRow,
  ScrollPanel,
  Tabs,
  TextField,
} from "@decky/ui";
import { toaster } from "@decky/api";
import { FaArrowLeft, FaSearch, FaStore, FaSyncAlt } from "react-icons/fa";

import { backend, ForgeError } from "../lib/backend";
import type { InstalledTrainer, StoreTrainer } from "../lib/types";

function errMsg(e: unknown): string {
  return e instanceof ForgeError ? e.message : "operation failed";
}

export function StorePage() {
  const [activeTab, setActiveTab] = useState("browse");
  const [catalog, setCatalog] = useState<StoreTrainer[] | null>(null);
  const [installed, setInstalled] = useState<InstalledTrainer[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  // appId -> progress (0..1) while an install is in flight.
  const [progress, setProgress] = useState<Record<number, number>>({});
  const polling = useRef<Record<number, ReturnType<typeof setInterval>>>({});

  const refreshCatalog = useCallback(async () => {
    setLoading(true);
    try {
      setCatalog(await backend.repoList());
    } catch (e) {
      toaster.toast({ title: "DeckForge Store", body: errMsg(e) });
      setCatalog(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshInstalled = useCallback(async () => {
    try {
      setInstalled(await backend.repoListInstalled());
    } catch {
      setInstalled(null);
    }
  }, []);

  // Auto-load both lists on first mount.
  useEffect(() => {
    refreshCatalog();
    refreshInstalled();
  }, [refreshCatalog, refreshInstalled]);

  const clearPoll = useCallback((appId: number) => {
    const id = polling.current[appId];
    if (id !== undefined) {
      clearInterval(id);
      delete polling.current[appId];
    }
  }, []);

  const dropProgress = (appId: number) =>
    setProgress((p) => {
      const next = { ...p };
      delete next[appId];
      return next;
    });

  const handleInstall = useCallback(
    async (appId: number) => {
      try {
        const jobId = await backend.repoInstall(appId);
        setProgress((p) => ({ ...p, [appId]: 0 }));
        polling.current[appId] = setInterval(async () => {
          try {
            const st = await backend.installStatus(jobId);
            if (st.state === "done") {
              clearPoll(appId);
              dropProgress(appId);
              toaster.toast({ title: "DeckForge Store", body: "Trainer installed" });
              setCatalog(await backend.repoList());
              refreshInstalled();
            } else if (st.state === "failed") {
              clearPoll(appId);
              dropProgress(appId);
              toaster.toast({ title: "DeckForge Store", body: st.error ?? "install failed" });
            } else {
              setProgress((p) => ({ ...p, [appId]: st.progress }));
            }
          } catch (e) {
            clearPoll(appId);
            dropProgress(appId);
            toaster.toast({ title: "DeckForge Store", body: errMsg(e) });
          }
        }, 700);
      } catch (e) {
        toaster.toast({ title: "DeckForge Store", body: errMsg(e) });
      }
    },
    [clearPoll, refreshInstalled]
  );

  const handleUninstall = useCallback(
    async (appId: number) => {
      try {
        await backend.repoUninstall(appId);
        toaster.toast({ title: "DeckForge Store", body: "Trainer removed" });
        setCatalog(await backend.repoList());
        refreshInstalled();
      } catch (e) {
        toaster.toast({ title: "DeckForge Store", body: errMsg(e) });
      }
    },
    [refreshInstalled]
  );

  // Clean up any polling intervals on unmount.
  useEffect(
    () => () => {
      Object.values(polling.current).forEach((id) => clearInterval(id));
    },
    []
  );

  const isInstalling = (appId: number) => progress[appId] !== undefined;

  // Filter both lists by game name (case-insensitive).
  const q = search.trim().toLowerCase();
  const filteredCatalog = useMemo(
    () => (q && catalog ? catalog.filter((t) => t.gameName.toLowerCase().includes(q)) : catalog),
    [catalog, q]
  );
  const filteredInstalled = useMemo(
    () => (q && installed ? installed.filter((t) => t.gameName.toLowerCase().includes(q)) : installed),
    [installed, q]
  );

  const goBack = () => {
    Navigation.NavigateBack();
  };

  const refreshAll = () => {
    refreshCatalog();
    refreshInstalled();
  };

  return (
    <div style={pageStyle}>
      {/* Top bar — back button, title, refresh */}
      <div style={headerStyle}>
        <DialogButton style={iconBtnStyle} onClick={goBack}>
          <FaArrowLeft style={iconCentered} />
        </DialogButton>
        <div style={titleStyle}>
          <FaStore style={{ marginRight: "8px" }} />
          Trainer Store
        </div>
        <DialogButton style={iconBtnStyle} disabled={loading} onClick={refreshAll}>
          <FaSyncAlt
            style={{ ...iconCentered, animation: loading ? "spin 1s linear infinite" : "" }}
          />
        </DialogButton>
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>

      {/* Search filter — shared across both tabs */}
      <div style={searchBarStyle}>
        <FaSearch style={searchIconStyle} />
        <div style={searchFieldWrapStyle}>
          <TextField
            label="Filter by game name"
            value={search}
            bShowClearAction
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Tabs: Browse | Installed */}
      <div style={tabsWrapStyle}>
        <Tabs
          activeTab={activeTab}
          onShowTab={setActiveTab}
          tabs={[
            {
              id: "browse",
              title: "Browse",
              content: (
                <ScrollPanel>
                  <div style={listStyle}>
                    {loading && !catalog && (
                      <div style={emptyStyle}>Loading catalog…</div>
                    )}

                    {catalog && filteredCatalog?.length === 0 && (
                      <div style={emptyStyle}>
                        {q
                          ? `No trainers matching "${search}".`
                          : "No trainers available in the repository."}
                      </div>
                    )}

                    {filteredCatalog?.map((t) => {
                      const busy = isInstalling(t.appId);
                      const pct = busy ? Math.round((progress[t.appId] ?? 0) * 100) : 0;
                      return (
                        <PanelSectionRow key={t.appId}>
                          <div style={cardStyle}>
                            <div style={cardInfoStyle}>
                              <div style={cardNameStyle}>{t.gameName}</div>
                              <div style={cardMetaStyle}>
                                v{t.version}
                                {t.author ? ` · ${t.author}` : ""}
                                {busy
                                  ? ` · installing ${pct}%`
                                  : t.installed
                                  ? t.updateAvailable
                                    ? " · update available"
                                    : " · installed"
                                  : ""}
                              </div>
                              {busy && (
                                <div style={progressBarOuter}>
                                  <div style={{ ...progressBarInner, width: `${pct}%` }} />
                                </div>
                              )}
                            </div>
                            <div style={cardActionsStyle}>
                              {busy ? (
                                <span style={busyStyle}>…</span>
                              ) : t.installed ? (
                                <>
                                  {t.updateAvailable && (
                                    <DialogButtonPrimary
                                      style={actionBtnStyle}
                                      onClick={() => handleInstall(t.appId)}
                                    >
                                      Update
                                    </DialogButtonPrimary>
                                  )}
                                  <DialogButton
                                    style={actionBtnStyle}
                                    onClick={() => handleUninstall(t.appId)}
                                  >
                                    Remove
                                  </DialogButton>
                                </>
                              ) : (
                                <DialogButtonPrimary
                                  style={actionBtnStyle}
                                  onClick={() => handleInstall(t.appId)}
                                >
                                  Install
                                </DialogButtonPrimary>
                              )}
                            </div>
                          </div>
                        </PanelSectionRow>
                      );
                    })}
                  </div>
                </ScrollPanel>
              ),
            },
            {
              id: "installed",
              title: "Installed",
              content: (
                <ScrollPanel>
                  <div style={listStyle}>
                    {installed === null && (
                      <div style={emptyStyle}>Unable to load installed trainers.</div>
                    )}

                    {installed !== null && filteredInstalled?.length === 0 && (
                      <div style={emptyStyle}>
                        {q
                          ? `No installed trainers matching "${search}".`
                          : "No trainers installed."}
                      </div>
                    )}

                    {filteredInstalled?.map((t) => (
                      <PanelSectionRow key={t.appId}>
                        <div style={cardStyle}>
                          <div style={cardInfoStyle}>
                            <div style={cardNameStyle}>{t.gameName}</div>
                            <div style={cardMetaStyle}>
                              {t.trainerName}
                              {t.version ? ` · v${t.version}` : ""}
                              {t.author ? ` · ${t.author}` : ""}
                              {" · installed"}
                            </div>
                          </div>
                          <div style={cardActionsStyle}>
                            <DialogButton
                              style={actionBtnStyle}
                              onClick={() => handleUninstall(t.appId)}
                            >
                              Remove
                            </DialogButton>
                          </div>
                        </div>
                      </PanelSectionRow>
                    ))}
                  </div>
                </ScrollPanel>
              ),
            },
          ]}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const pageStyle: React.CSSProperties = {
  marginTop: "40px",
  height: "calc(100% - 40px)",
  display: "flex",
  flexDirection: "column",
  background: "#0e141b",
};

const headerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  padding: "10px 16px",
  borderBottom: "1px solid #2a3f5c",
  flexShrink: 0,
};

const iconBtnStyle: React.CSSProperties = {
  height: "36px",
  width: "36px",
  minWidth: 0,
  padding: "0",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
};

const iconCentered: React.CSSProperties = {
  display: "block",
  margin: "0 auto",
};

const titleStyle: React.CSSProperties = {
  flex: 1,
  display: "flex",
  alignItems: "center",
  fontSize: "18px",
  fontWeight: 600,
  color: "#c7d5e0",
};

const searchBarStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  padding: "4px 16px 0px",
  flexShrink: 0,
};

const searchIconStyle: React.CSSProperties = {
  color: "#9a9a9a",
  fontSize: "14px",
  flexShrink: 0,
  marginTop: "4px",
};

const searchFieldWrapStyle: React.CSSProperties = {
  flex: 1,
  minWidth: 0,
};

const tabsWrapStyle: React.CSSProperties = {
  flex: 1,
  minHeight: 0,
  overflow: "hidden",
};

const listStyle: React.CSSProperties = {
  padding: "8px 0",
};

const emptyStyle: React.CSSProperties = {
  padding: "32px 16px",
  color: "#9a9a9a",
  textAlign: "center",
  fontSize: "14px",
};

const cardStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "10px 16px",
  gap: "12px",
  borderBottom: "1px solid rgba(255,255,255,0.05)",
};

const cardInfoStyle: React.CSSProperties = {
  flex: 1,
  minWidth: 0,
};

const cardNameStyle: React.CSSProperties = {
  fontSize: "15px",
  fontWeight: 500,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

const cardMetaStyle: React.CSSProperties = {
  fontSize: "12px",
  color: "#9a9a9a",
  marginTop: "2px",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

const cardActionsStyle: React.CSSProperties = {
  display: "flex",
  gap: "6px",
  flexShrink: 0,
};

const actionBtnStyle: React.CSSProperties = {
  height: "32px",
  padding: "0 12px",
  fontSize: "13px",
};

const busyStyle: React.CSSProperties = {
  color: "#9a9a9a",
  fontSize: "14px",
};

const progressBarOuter: React.CSSProperties = {
  marginTop: "6px",
  height: "4px",
  background: "rgba(255,255,255,0.1)",
  borderRadius: "2px",
  overflow: "hidden",
};

const progressBarInner: React.CSSProperties = {
  height: "100%",
  background: "#1a9fff",
  borderRadius: "2px",
  transition: "width 0.3s ease",
};
