//! Strict Core-profile RFC 8785 canonical JSON and domain-separated SHA-256.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{Result, invalid};

pub const IJSON_MIN: i64 = -9_007_199_254_740_991;
pub const IJSON_MAX: i64 = 9_007_199_254_740_991;

/// Parse JSON while rejecting duplicate keys, floats, constants, and unsafe integers.
pub fn strict_json_loads(text: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| invalid(format!("invalid strict JSON: {error}")))?
        .0;
    deserializer
        .end()
        .map_err(|error| invalid(format!("invalid trailing JSON content: {error}")))?;
    canonical_json(&value)?;
    Ok(value)
}

/// Return canonical UTF-8 JSON under the Core no-float profile.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canonical_json(value)?.into_bytes())
}

pub fn json_line(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonical_bytes(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn digest(domain: &str, value: &Value) -> Result<String> {
    if domain.is_empty() {
        return Err(invalid("digest domain must be a non-empty string"));
    }
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical_bytes(value)?);
    Ok(hex::encode(hasher.finalize()))
}

pub fn raw_sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn write_value(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => write_number(number, output)?,
        Value::String(text) => write_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(item, output)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by_key(|key| key.encode_utf16().collect::<Vec<_>>());
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_string(key, output);
                output.push(':');
                write_value(&map[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_number(number: &Number, output: &mut String) -> Result<()> {
    if let Some(value) = number.as_i64() {
        if !(IJSON_MIN..=IJSON_MAX).contains(&value) {
            return Err(invalid("integer is outside the I-JSON safe range"));
        }
        output.push_str(&value.to_string());
        return Ok(());
    }
    if let Some(value) = number.as_u64() {
        if value > IJSON_MAX as u64 {
            return Err(invalid("integer is outside the I-JSON safe range"));
        }
        output.push_str(&value.to_string());
        return Ok(());
    }
    Err(invalid("floating JSON numbers are forbidden"))
}

fn write_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            control if control <= '\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", control as u32);
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict no-float I-JSON")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(IJSON_MIN..=IJSON_MAX).contains(&value) {
            return Err(E::custom("integer is outside the I-JSON safe range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > IJSON_MAX as u64 {
            return Err(E::custom("integer is outside the I-JSON safe range"));
        }
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating JSON numbers are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        let mut map = Map::new();
        while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            map.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(map)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_order_uses_utf16_code_units() {
        let value =
            strict_json_loads(r#"{"\u20ac":1,"\ud83d\ude00":2,"a":3}"#).expect("valid JSON");
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":3,"€":1,"😀":2}"#);
    }

    #[test]
    fn duplicate_float_and_unsafe_integer_are_rejected() {
        assert!(strict_json_loads(r#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json_loads("1.0").is_err());
        assert!(strict_json_loads("9007199254740992").is_err());
    }
}
