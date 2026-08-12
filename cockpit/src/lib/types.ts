// Shared Cockpit types mirroring the Forge protocol response payloads.
// Cockpit is presentation only — these are view models, not state of record.

export type Control = "toggle" | "number" | "slider" | "action" | "select";

export interface GameInfo {
  appId: number;
  pid: number;
  name: string;
  executable: string;
}

export interface TrainerSummary {
  id: string;
  name: string;
  version: string;
}

export interface EngineStatus {
  engineVersion: string;
  running: boolean;
  attached: boolean;
  game: GameInfo | null;
  trainer: TrainerSummary | null;
}

export interface TrainerGameInfo {
  steamAppId: number;
  name: string;
  process: string;
}

export interface CheatInfo {
  id: string;
  name: string;
  control: Control;
  enabled: boolean;
  min?: number;
  max?: number;
  last_error?: string;
}

export interface TrainerInfo {
  game: TrainerGameInfo;
  trainer: TrainerSummary;
  cheats: CheatInfo[];
}

/** Raw envelope returned by every Relay RPC method. */
export interface EngineEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: { code: string; message: string };
}

export interface CheatResult {
  cheatId: string;
  enabled: boolean;
}

export interface ValueResult {
  cheatId: string;
  value: number;
}

/** Result of a one-shot `action`-control trigger (a button press). */
export interface TriggerResult {
  cheatId: string;
  value: number;
}

// ---------------------------------------------------------------------------
// Trainer store
// ---------------------------------------------------------------------------

/** A trainer package in the remote catalog, annotated with install status. */
export interface StoreTrainer {
  appId: number;
  gameName: string;
  trainerName: string;
  version: string;
  author?: string;
  fileCount: number;
  installed: boolean;
  installedVersion?: string;
  updateAvailable: boolean;
}

export type InstallState = "queued" | "downloading" | "validating" | "done" | "failed";

/** Snapshot of an install job, returned by `install_status`. */
export interface JobStatus {
  state: InstallState;
  progress: number;
  error?: string;
  appId: number;
  reloaded: boolean;
}

/** A locally installed trainer (no network). */
export interface InstalledTrainer {
  appId: number;
  gameName: string;
  trainerName: string;
  version: string;
  author?: string;
}
