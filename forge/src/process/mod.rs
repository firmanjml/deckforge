//! Process discovery, `/proc` inspection, and module enumeration.

pub mod discovery;
pub mod modules;
pub mod procfs;

pub use discovery::find_game_process;
pub use procfs::GameProcess;
