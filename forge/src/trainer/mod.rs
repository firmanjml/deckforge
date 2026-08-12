//! Trainer loading, validation, definition models, and runtime.

pub mod components;
pub mod definition;
pub mod loader;
pub mod package;
pub mod runtime;
pub mod session;
pub mod validator;

#[allow(unused_imports)]
pub use definition::{CheatAction, CheatDefinition, Control, GameDefinition, TrainerDefinition, TrainerMetadata, ValueType};
#[allow(unused_imports)]
pub use loader::{
    install_root, installed_trainers, load_trainer, load_trainer_from_dir, trainer_dir,
    trainer_path, InstalledTrainer,
};
pub use runtime::TrainerRuntime;
