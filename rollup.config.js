import deckyPlugin from "@decky/rollup";

// DeckForge keeps its frontend source under cockpit/src/ rather than the
// Decky-template default ./src. @decky/rollup merges user options *under* its
// own defaults (later wins), so we override `input` after the preset is built.
const config = deckyPlugin({});
config.input = "cockpit/src/index.tsx";

export default config;
