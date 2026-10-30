//! Deterministic JSON (RFC 8785 subset) shared with the TypeScript issuer/verifier.
//!
//! Signed payloads only contain objects, arrays, strings, booleans, null and unsigned integers,
//! with ASCII object keys. Under those limits this output is byte-identical to
//! `canonicalizeJson` in `packages/core-crypto/canonical.ts` (JSON.stringify escaping, keys
//! sorted). Keys are sorted here explicitly so the result does not depend on serde_json's
//! `preserve_order` feature, which another crate in the build graph could switch on.

use serde_json::Value;

use crate::Error;

pub fn canonicalize(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Floats and negatives format differently across languages; signed data never needs them.
            let n = n.as_u64().ok_or(Error::Malformed("only unsigned integers may be signed"))?;
            if n > MAX_SAFE_INTEGER {
                return Err(Error::Malformed("integer exceeds 2^53-1"));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            if keys.iter().any(|k| !k.is_ascii()) {
                return Err(Error::Malformed("object keys must be ASCII"));
            }
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Same escaping as ECMAScript `JSON.stringify` for well-formed strings.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_escapes_like_json_stringify() {
        let v = json!({"b": 1, "a": ["x\n\"y\"", true, null], "c": {"z": "\u{01}é", "y": 0}});
        assert_eq!(
            canonicalize(&v).unwrap(),
            r#"{"a":["x\n\"y\"",true,null],"b":1,"c":{"y":0,"z":"\u0001é"}}"#
        );
    }

    #[test]
    fn rejects_floats_and_negatives() {
        assert!(canonicalize(&json!({"a": 1.5})).is_err());
        assert!(canonicalize(&json!({"a": -1})).is_err());
    }
}
