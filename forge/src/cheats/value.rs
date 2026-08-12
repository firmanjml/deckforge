//! Value cheats: write a typed value to a resolved address.
//!
//! Conversion from a JSON number to the target width is centralized here so the
//! rest of the engine never builds raw value buffers by hand.

use serde_json::Value;

use crate::error::{EngineError, EngineResult};
use crate::memory::MemoryAccess;
use crate::trainer::definition::ValueType;

fn as_i64(v: &Value) -> EngineResult<i64> {
    if let Some(i) = v.as_i64() {
        return Ok(i);
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            return Ok(f as i64);
        }
    }
    Err(EngineError::InvalidRequest(format!(
        "expected integer, got {v}"
    )))
}

fn as_u64(v: &Value) -> EngineResult<u64> {
    if let Some(u) = v.as_u64() {
        return Ok(u);
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 {
            return Ok(f as u64);
        }
    }
    Err(EngineError::InvalidRequest(format!(
        "expected unsigned integer, got {v}"
    )))
}

fn as_f64(v: &Value) -> EngineResult<f64> {
    v.as_f64()
        .ok_or_else(|| EngineError::InvalidRequest(format!("expected number, got {v}")))
}

/// Convert a JSON value to little-endian bytes for `vt`.
pub fn value_to_bytes(vt: ValueType, value: &Value) -> EngineResult<Vec<u8>> {
    Ok(match vt {
        ValueType::Int8 => (as_i64(value)? as i8).to_ne_bytes().to_vec(),
        ValueType::Int16 => (as_i64(value)? as i16).to_ne_bytes().to_vec(),
        ValueType::Int32 => (as_i64(value)? as i32).to_ne_bytes().to_vec(),
        ValueType::Int64 => as_i64(value)?.to_ne_bytes().to_vec(),
        ValueType::UInt8 => (as_u64(value)? as u8).to_ne_bytes().to_vec(),
        ValueType::UInt16 => (as_u64(value)? as u16).to_ne_bytes().to_vec(),
        ValueType::UInt32 => (as_u64(value)? as u32).to_ne_bytes().to_vec(),
        ValueType::UInt64 => as_u64(value)?.to_ne_bytes().to_vec(),
        ValueType::Float32 => (as_f64(value)? as f32).to_ne_bytes().to_vec(),
        ValueType::Float64 => as_f64(value)?.to_ne_bytes().to_vec(),
    })
}

/// Read a typed value back as JSON (for future read-back / verification).
pub fn read_value(mem: &MemoryAccess, addr: usize, vt: ValueType) -> EngineResult<Value> {
    let bytes = mem.read_bytes(addr, vt.size())?;
    let v = match vt {
        ValueType::Int8 => Value::from(i8::from_ne_bytes([bytes[0]]) as i64),
        ValueType::Int16 => Value::from(i16::from_ne_bytes(bytes[..2].try_into().unwrap()) as i64),
        ValueType::Int32 => Value::from(i32::from_ne_bytes(bytes[..4].try_into().unwrap()) as i64),
        ValueType::Int64 => Value::from(i64::from_ne_bytes(bytes[..8].try_into().unwrap())),
        ValueType::UInt8 => Value::from(bytes[0] as u64),
        ValueType::UInt16 => Value::from(u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64),
        ValueType::UInt32 => Value::from(u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64),
        ValueType::UInt64 => Value::from(u64::from_ne_bytes(bytes[..8].try_into().unwrap())),
        ValueType::Float32 => Value::from(f32::from_ne_bytes(bytes[..4].try_into().unwrap()) as f64),
        ValueType::Float64 => Value::from(f64::from_ne_bytes(bytes[..8].try_into().unwrap())),
    };
    Ok(v)
}

/// Resolve-then-write a value (called by the trainer runtime).
pub fn write_value(
    mem: &MemoryAccess,
    addr: usize,
    vt: ValueType,
    value: &Value,
) -> EngineResult<()> {
    let bytes = value_to_bytes(vt, value)?;
    mem.write_bytes(addr, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int32_roundtrip_bytes() {
        let bytes = value_to_bytes(ValueType::Int32, &serde_json::json!(999999)).unwrap();
        assert_eq!(bytes, (999999i32).to_ne_bytes().to_vec());
    }

    #[test]
    fn int32_accepts_integral_float_json() {
        let bytes = value_to_bytes(ValueType::Int32, &serde_json::json!(9999.0)).unwrap();
        assert_eq!(bytes, (9999i32).to_ne_bytes().to_vec());
    }

    #[test]
    fn int32_rejects_fractional_float_json() {
        let err = value_to_bytes(ValueType::Int32, &serde_json::json!(9999.5)).unwrap_err();
        assert!(err.message().contains("expected integer"), "{}", err.message());
    }

    #[test]
    fn float32_bytes() {
        let bytes = value_to_bytes(ValueType::Float32, &serde_json::json!(1.5)).unwrap();
        assert_eq!(bytes, (1.5f32).to_ne_bytes().to_vec());
    }

    #[test]
    fn uint8_clamps_via_cast() {
        let bytes = value_to_bytes(ValueType::UInt8, &serde_json::json!(255)).unwrap();
        assert_eq!(bytes, vec![255]);
    }

    #[test]
    fn rejects_non_number() {
        assert!(value_to_bytes(ValueType::Int32, &serde_json::json!("x")).is_err());
    }
}
