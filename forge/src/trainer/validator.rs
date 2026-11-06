//! Trainer validation: format version, AppID match, unique cheat ids, and
//! per-cheat structural checks.

use std::collections::HashSet;

use crate::error::{EngineError, EngineResult};
use crate::resolver::parse_hex_bytes;

use super::definition::{CheatAction, CheatDefinition, Control, TrainerDefinition};

pub fn validate(def: &TrainerDefinition, expected_app_id: u64) -> EngineResult<()> {
    if def.format_version != 1 {
        return Err(EngineError::InvalidTrainer(format!(
            "unsupported formatVersion {}",
            def.format_version
        )));
    }
    if def.game.steam_app_id != expected_app_id {
        return Err(EngineError::InvalidTrainer(format!(
            "steamAppId {} does not match requested {}",
            def.game.steam_app_id, expected_app_id
        )));
    }

    // Bootstrap components: unique ids.
    let mut components = HashSet::new();
    for entry in &def.scripts.bootstrap {
        let id = entry.id();
        if !components.insert(id.clone()) {
            return Err(EngineError::InvalidTrainer(format!(
                "duplicate bootstrap component id '{id}'"
            )));
        }
    }

    let mut seen = HashSet::new();
    for cheat in &def.cheats {
        if !seen.insert(cheat.id.as_str()) {
            return Err(EngineError::InvalidTrainer(format!(
                "duplicate cheat id '{}'",
                cheat.id
            )));
        }
        // Runtime dependencies must reference declared bootstrap components.
        for req in &cheat.requires {
            if !components.contains(req) {
                return Err(EngineError::InvalidTrainer(format!(
                    "cheat '{}' requires unknown component '{req}' (declare it under scripts.bootstrap)",
                    cheat.id
                )));
            }
        }
        validate_cheat(cheat)?;
    }
    Ok(())
}

fn validate_cheat(cheat: &CheatDefinition) -> EngineResult<()> {
    match &cheat.action {
        CheatAction::Patch {
            expected, enabled, ..
        } => {
            let exp = parse_hex_bytes(expected)?;
            let en = parse_hex_bytes(enabled)?;
            if en.is_empty() {
                return Err(EngineError::InvalidTrainer(format!(
                    "cheat '{}' has empty enabled bytes",
                    cheat.id
                )));
            }
            // Patch length: expected (verification window) and enabled (write)
            // should match so the verification covers the bytes we change.
            if exp.len() != en.len() {
                return Err(EngineError::InvalidTrainer(format!(
                    "cheat '{}': expected ({} bytes) and enabled ({} bytes) lengths differ",
                    cheat.id,
                    exp.len(),
                    en.len()
                )));
            }
        }
        CheatAction::Value { .. } => {}
        CheatAction::Freeze {
            restore_on_disable, ..
        } => {
            if *restore_on_disable && cheat.control != Control::Toggle {
                return Err(EngineError::InvalidTrainer(format!(
                    "cheat '{}': restoreOnDisable requires control \"toggle\"",
                    cheat.id
                )));
            }
        }
        CheatAction::AutoAssembler { .. } => {
            // Auto Assembler scripts have enable/disable semantics; only the
            // toggle control maps onto that.
            if cheat.control != Control::Toggle {
                return Err(EngineError::InvalidTrainer(format!(
                    "cheat '{}': auto_assembler actions require control \"toggle\"",
                    cheat.id
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trainer::definition::TrainerDefinition;

    fn sample_trainer_json() -> &'static str {
        r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 123456, "name": "Example Game", "process": "ExampleGame.exe" },
          "trainer": { "id": "ex", "name": "Example Trainer", "version": "1.0.0" },
          "cheats": [
            {
              "id": "infinite_ammo", "name": "Infinite Ammo", "control": "toggle",
              "action": {
                "type": "patch",
                "resolver": { "type": "signature", "module": "ExampleGame.exe", "pattern": "89 43 20 48 8B ?? ??" },
                "offset": 0,
                "expected": "89 43 20",
                "enabled": "90 90 90"
              }
            },
            {
              "id": "money", "name": "Money", "control": "number", "min": 0, "max": 999999999,
              "action": {
                "type": "value",
                "valueType": "int32",
                "resolver": { "type": "module_offset", "module": "ExampleGame.exe", "offset": "0x777777" }
              }
            }
          ]
        }"#
    }

    #[test]
    fn parses_full_trainer() {
        let def: TrainerDefinition = serde_json::from_str(sample_trainer_json()).unwrap();
        assert_eq!(def.format_version, 1);
        assert_eq!(def.game.steam_app_id, 123456);
        assert_eq!(def.cheats.len(), 2);
    }

    #[test]
    fn validates_good_trainer() {
        let def: TrainerDefinition = serde_json::from_str(sample_trainer_json()).unwrap();
        assert!(validate(&def, 123456).is_ok());
    }

    #[test]
    fn rejects_wrong_appid() {
        let def: TrainerDefinition = serde_json::from_str(sample_trainer_json()).unwrap();
        assert!(matches!(
            validate(&def, 999),
            Err(EngineError::InvalidTrainer(_))
        ));
    }

    #[test]
    fn rejects_bad_format_version() {
        let def: TrainerDefinition = serde_json::from_str(sample_trainer_json()).unwrap();
        let mut def = def;
        def.format_version = 2;
        assert!(matches!(
            validate(&def, 123456),
            Err(EngineError::InvalidTrainer(_))
        ));
    }

    #[test]
    fn rejects_patch_length_mismatch() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "c", "name": "C", "control": "toggle",
            "action": { "type": "patch", "resolver": { "type": "absolute", "address": "0x1000" },
                        "expected": "89 43", "enabled": "90 90 90" }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        assert!(matches!(
            validate(&def, 1),
            Err(EngineError::InvalidTrainer(_))
        ));
    }

    fn freeze_trainer_json(control: &str, restore: bool) -> String {
        format!(
            r#"{{
          "formatVersion": 1,
          "game": {{ "steamAppId": 1, "name": "G", "process": "g.exe" }},
          "trainer": {{ "id": "t", "name": "T", "version": "1" }},
          "cheats": [{{
            "id": "c", "name": "C", "control": "{control}",
            "action": {{ "type": "freeze", "valueType": "float64", "value": 1.0,
              "restoreOnDisable": {restore},
              "resolver": {{ "type": "module_offset", "module": "g.exe", "offset": "0x1000" }} }}
          }}]
        }}"#
        )
    }

    #[test]
    fn restore_on_disable_requires_a_toggle() {
        let toggle: TrainerDefinition =
            serde_json::from_str(&freeze_trainer_json("toggle", true)).unwrap();
        assert!(validate(&toggle, 1).is_ok());
        let button: TrainerDefinition =
            serde_json::from_str(&freeze_trainer_json("action", true)).unwrap();
        assert!(validate(&button, 1).is_err());
        let plain_button: TrainerDefinition =
            serde_json::from_str(&freeze_trainer_json("action", false)).unwrap();
        assert!(validate(&plain_button, 1).is_ok());
    }

    #[test]
    fn value_range_is_enforced() {
        let def: TrainerDefinition = serde_json::from_str(sample_trainer_json()).unwrap();
        let money = def.cheats.iter().find(|c| c.id == "money").unwrap();
        assert!(money.check_range(&serde_json::json!(0)).is_ok());
        assert!(money.check_range(&serde_json::json!(999999999)).is_ok());
        assert!(money.check_range(&serde_json::json!(-1)).is_err());
        assert!(money.check_range(&serde_json::json!(1000000000)).is_err());
        assert!(money.check_range(&serde_json::json!("10")).is_err());
    }

    #[test]
    fn rejects_scan_resolver() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "money", "name": "Money", "control": "number",
            "action": { "type": "value", "valueType": "int32",
              "resolver": { "type": "scan", "valueType": "int32" } }
          }]
        }"#;
        assert!(serde_json::from_str::<TrainerDefinition>(json).is_err());
    }

    fn lua_trainer_json(script: &str) -> String {
        format!(
            r#"{{
          "formatVersion": 1,
          "game": {{ "steamAppId": 1, "name": "G", "process": "g.exe" }},
          "trainer": {{ "id": "t", "name": "T", "version": "1" }},
          "cheats": [{{
            "id": "c", "name": "C", "control": "toggle",
            "action": {{ "type": "freeze", "valueType": "float64", "value": 1.0,
              "resolver": {{ "type": "script", "code": "{script}" }} }}
          }}]
        }}"#
        )
    }

    #[test]
    fn accepts_script_resolver() {
        let def: TrainerDefinition =
            serde_json::from_str(&lua_trainer_json("return 0x1000")).unwrap();
        assert!(validate(&def, 1).is_ok());
        assert!(matches!(def.cheats[0].action, CheatAction::Freeze { .. }));
    }

    #[test]
    fn accepts_trainer_script_setup() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scriptSetup": "function helper() return 1 end",
          "cheats": []
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(
            def.script_setup.as_deref(),
            Some("function helper() return 1 end")
        );
        assert!(validate(&def, 1).is_ok());
    }

    #[test]
    fn rejects_unknown_requires_component() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scripts": { "bootstrap": [ { "id": "player_instance", "file": "scripts/p.asm" } ] },
          "cheats": [{
            "id": "c", "name": "C", "control": "toggle",
            "requires": ["nonexistent"],
            "action": { "type": "auto_assembler", "file": "scripts/c.asm" }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        let err = validate(&def, 1).unwrap_err();
        assert!(err.message().contains("unknown component 'nonexistent'"));
    }

    #[test]
    fn rejects_auto_assembler_without_toggle() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "c", "name": "C", "control": "number",
            "action": { "type": "auto_assembler", "file": "scripts/c.asm" }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        let err = validate(&def, 1).unwrap_err();
        assert!(err.message().contains("toggle"));
    }

    #[test]
    fn accepts_bootstrap_string_form() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scripts": { "bootstrap": ["scripts/common/player_instance.asm"] },
          "cheats": [{
            "id": "c", "name": "C", "control": "toggle",
            "requires": ["player_instance"],
            "action": { "type": "auto_assembler", "file": "scripts/c.asm" }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(def.scripts.bootstrap[0].id(), "player_instance");
        assert!(validate(&def, 1).is_ok());
    }

    #[test]
    fn rejects_duplicate_component_ids() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "scripts": { "bootstrap": [
            { "id": "dup", "file": "scripts/a.asm" },
            { "id": "dup", "file": "scripts/b.asm" }
          ] },
          "cheats": []
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        assert!(validate(&def, 1).is_err());
    }

    #[test]
    fn validates_action_control_freeze() {
        // The Islets-style "button" cheat: control "action" + freeze action.
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "enable_jump", "name": "Enable Jump", "control": "action",
            "action": { "type": "freeze", "valueType": "float64", "value": 1.0,
              "resolver": { "type": "module_offset", "module": "g.exe", "offset": "0x1000" } }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(def.cheats[0].control, Control::Action);
        assert!(matches!(def.cheats[0].action, CheatAction::Freeze { .. }));
        assert!(validate(&def, 1).is_ok());
    }

    #[test]
    fn value_action_with_declared_value_roundtrips() {
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "set_currency", "name": "Set Currency", "control": "action",
            "action": { "type": "value", "valueType": "int32", "value": 99999,
              "resolver": { "type": "module_offset", "module": "g.exe", "offset": "0x2000" } }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        match &def.cheats[0].action {
            CheatAction::Value { value, .. } => {
                assert_eq!(value.as_ref().unwrap(), &serde_json::json!(99999));
            }
            other => panic!("expected value action, got {other:?}"),
        }
        assert!(validate(&def, 1).is_ok());
    }

    #[test]
    fn value_action_without_declared_value_is_none() {
        // A plain number-control value cheat (no `value` field) still loads:
        // the field is optional and only read by trigger_cheat.
        let json = r#"{
          "formatVersion": 1,
          "game": { "steamAppId": 1, "name": "G", "process": "g.exe" },
          "trainer": { "id": "t", "name": "T", "version": "1" },
          "cheats": [{
            "id": "money", "name": "Money", "control": "number", "min": 0, "max": 999,
            "action": { "type": "value", "valueType": "int32",
              "resolver": { "type": "module_offset", "module": "g.exe", "offset": "0x2000" } }
          }]
        }"#;
        let def: TrainerDefinition = serde_json::from_str(json).unwrap();
        match &def.cheats[0].action {
            CheatAction::Value { value, .. } => assert!(value.is_none()),
            other => panic!("expected value action, got {other:?}"),
        }
        assert!(validate(&def, 1).is_ok());
    }
}
