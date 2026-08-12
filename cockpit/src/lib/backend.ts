// Cockpit → Relay backend client.
//
// All Decky RPC calls are funneled through this module so React components never
// scatter raw `callable()` invocations. Each method unwraps the structured
// envelope: it returns the `data` on success and throws a typed `ForgeError`
// (carrying the stable `code`) on failure. Components branch on `error.code`,
// never on message strings. No memory logic lives here.

import { callable } from "@decky/api";
import type {
  CheatResult,
  EngineEnvelope,
  EngineStatus,
  GameInfo,
  InstalledTrainer,
  JobStatus,
  StoreTrainer,
  TrainerInfo,
  TriggerResult,
  ValueResult,
} from "./types";

const rpc = {
  getStatus: callable<[], EngineEnvelope<EngineStatus>>("get_status"),
  getActiveGame: callable<[], EngineEnvelope<GameInfo | null>>("get_active_game"),
  detectGame: callable<[], EngineEnvelope<GameInfo | null>>("detect_game"),
  attachGame: callable<[appId: number], EngineEnvelope<GameInfo>>("attach_game"),
  getTrainer: callable<[appId?: number], EngineEnvelope<TrainerInfo | null>>("get_trainer"),
  enableCheat: callable<[cheatId: string], EngineEnvelope<CheatResult>>("enable_cheat"),
  disableCheat: callable<[cheatId: string], EngineEnvelope<CheatResult>>("disable_cheat"),
  setValue: callable<
    [cheatId: string, value: number],
    EngineEnvelope<ValueResult>
  >("set_value"),
  triggerCheat: callable<[cheatId: string], EngineEnvelope<TriggerResult>>("trigger_cheat"),
  reloadTrainer: callable<[], EngineEnvelope<{ reloaded: boolean }>>("reload_trainer"),
  scanResolveStart: callable<[cheatId: string, value: number], EngineEnvelope<{ count: number; resolved: boolean }>>("scan_resolve_start"),
  scanResolveFilter: callable<[cheatId: string, value: number], EngineEnvelope<{ count: number; resolved: boolean }>>("scan_resolve_filter"),
  scanResolveCount: callable<[cheatId: string], EngineEnvelope<{ count: number; resolved: boolean }>>("scan_resolve_count"),
  scanResolveDone: callable<[cheatId: string], EngineEnvelope<{ address: number; current_value: number | null }>>("scan_resolve_done"),
  // Trainer store
  repoList: callable<[], EngineEnvelope<{ trainers: StoreTrainer[] }>>("repo_list"),
  repoInstall: callable<[appId: number], EngineEnvelope<{ jobId: string }>>("repo_install"),
  installStatus: callable<[jobId: string], EngineEnvelope<JobStatus>>("install_status"),
  repoUninstall: callable<[appId: number], EngineEnvelope<{ appId: number; uninstalled: boolean }>>("repo_uninstall"),
  repoListInstalled: callable<[], EngineEnvelope<{ trainers: InstalledTrainer[] }>>("repo_list_installed"),
};

/** A structured error from Forge, carrying a stable `code` for branching. */
export class ForgeError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ForgeError";
  }
}

function unwrap<T>(env: EngineEnvelope<T>): T {
  if (env.ok && env.data !== undefined) {
    return env.data;
  }
  const err = env.error ?? { code: "UNKNOWN", message: "unknown engine error" };
  throw new ForgeError(err.code, err.message);
}

export const backend = {
  getStatus: (): Promise<EngineStatus> => rpc.getStatus().then(unwrap),
  getActiveGame: (): Promise<GameInfo | null> => rpc.getActiveGame().then(unwrap),
  detectGame: (): Promise<GameInfo | null> => rpc.detectGame().then(unwrap),
  attachGame: (appId: number): Promise<GameInfo> => rpc.attachGame(appId).then(unwrap),
  getTrainer: (appId?: number): Promise<TrainerInfo | null> =>
    (appId === undefined ? rpc.getTrainer() : rpc.getTrainer(appId)).then(unwrap),
  enableCheat: (cheatId: string): Promise<CheatResult> =>
    rpc.enableCheat(cheatId).then(unwrap),
  disableCheat: (cheatId: string): Promise<CheatResult> =>
    rpc.disableCheat(cheatId).then(unwrap),
  setValue: (cheatId: string, value: number): Promise<ValueResult> =>
    rpc.setValue(cheatId, value).then(unwrap),
  triggerCheat: (cheatId: string): Promise<TriggerResult> =>
    rpc.triggerCheat(cheatId).then(unwrap),
  reloadTrainer: (): Promise<{ reloaded: boolean }> => rpc.reloadTrainer().then(unwrap),
  scanResolveStart: (cheatId: string, value: number) =>
    rpc.scanResolveStart(cheatId, value).then(unwrap),
  scanResolveFilter: (cheatId: string, value: number) =>
    rpc.scanResolveFilter(cheatId, value).then(unwrap),
  scanResolveCount: (cheatId: string) =>
    rpc.scanResolveCount(cheatId).then(unwrap),
  scanResolveDone: (cheatId: string) =>
    rpc.scanResolveDone(cheatId).then(unwrap),
  // Trainer store
  repoList: (): Promise<StoreTrainer[]> =>
    rpc.repoList().then(unwrap).then((d) => d.trainers),
  repoInstall: (appId: number): Promise<string> =>
    rpc.repoInstall(appId).then(unwrap).then((d) => d.jobId),
  installStatus: (jobId: string): Promise<JobStatus> =>
    rpc.installStatus(jobId).then(unwrap),
  repoUninstall: (appId: number): Promise<void> =>
    rpc.repoUninstall(appId).then(unwrap).then(() => undefined),
  repoListInstalled: (): Promise<InstalledTrainer[]> =>
    rpc.repoListInstalled().then(unwrap).then((d) => d.trainers),
};
