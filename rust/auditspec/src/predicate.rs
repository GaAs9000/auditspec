//! Closed JSON predicate evaluator used by audit-time re-verification.

use serde_json::Value;

use crate::{Result, invalid};

pub fn evaluate(node: &Value, world: &Value) -> Result<Value> {
    let object = node
        .as_object()
        .ok_or_else(|| invalid("predicate node must be an object"))?;
    let operation = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("predicate operation is absent"))?;
    match operation {
        "field" => {
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("predicate field name is absent"))?;
            world
                .as_object()
                .and_then(|values| values.get(name))
                .cloned()
                .ok_or_else(|| invalid(format!("predicate field is absent: {name}")))
        }
        "const" => object
            .get("value")
            .cloned()
            .ok_or_else(|| invalid("predicate constant is absent")),
        "and" | "or" => {
            let arguments = object
                .get("args")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("predicate arguments are absent"))?;
            let mut values = Vec::with_capacity(arguments.len());
            for argument in arguments {
                values.push(as_bool(&evaluate(argument, world)?)?);
            }
            Ok(Value::Bool(if operation == "and" {
                values.into_iter().all(|value| value)
            } else {
                values.into_iter().any(|value| value)
            }))
        }
        "eq" | "ne" | "gt" => {
            let left = evaluate(
                object
                    .get("left")
                    .ok_or_else(|| invalid("predicate left operand is absent"))?,
                world,
            )?;
            let right = evaluate(
                object
                    .get("right")
                    .ok_or_else(|| invalid("predicate right operand is absent"))?,
                world,
            )?;
            let answer = match operation {
                "eq" => left == right,
                "ne" => left != right,
                "gt" => greater_than(&left, &right)?,
                _ => unreachable!(),
            };
            Ok(Value::Bool(answer))
        }
        _ => Err(invalid(format!(
            "unsupported predicate operation: {operation}"
        ))),
    }
}

pub fn evaluate_bool(node: &Value, world: &Value) -> Result<bool> {
    as_bool(&evaluate(node, world)?)
}

fn as_bool(value: &Value) -> Result<bool> {
    value
        .as_bool()
        .ok_or_else(|| invalid("predicate boolean operation received a non-boolean"))
}

fn greater_than(left: &Value, right: &Value) -> Result<bool> {
    if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
        return Ok(left > right);
    }
    if let (Some(left), Some(right)) = (left.as_str(), right.as_str()) {
        return Ok(left > right);
    }
    Err(invalid(
        "predicate greater-than operands are not comparable",
    ))
}
