//! Verification for finite claim-relative lifecycle certificates.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::canonical::{canonical_json, digest};
use crate::{Result, invalid};

const QUOTIENT_SCHEMA: &str = "AuditSpec-auditability-quotient-certificate-v1";
const LIFECYCLE_SCHEMA: &str = "AuditSpec-claim-relative-lifecycle-certificate-v1";
const MIGRATION_BUNDLE_SCHEMA: &str = "AuditSpec-claim-relative-migration-bundle-v1";

/// Verify one migration bundle and return the certificate for `claim_id`.
pub fn verify_migration_bundle(bundle: &Value, claim_id: &str) -> Result<Value> {
    exact_keys(
        bundle,
        &[
            "bundle_root",
            "certificates",
            "claim_ids",
            "schema",
            "transformation_id",
        ],
        "migration bundle",
    )?;
    if field_str(bundle, "schema")? != MIGRATION_BUNDLE_SCHEMA {
        return Err(invalid("migration bundle schema mismatch"));
    }
    let mut body = object(bundle)?.clone();
    body.remove("bundle_root");
    if field_str(bundle, "bundle_root")? != digest(MIGRATION_BUNDLE_SCHEMA, &Value::Object(body))? {
        return Err(invalid("migration bundle root mismatch"));
    }
    let certificates = object(field(bundle, "certificates")?)?;
    let claim_ids = string_array(field(bundle, "claim_ids")?)?;
    if claim_ids != certificates.keys().cloned().collect::<Vec<_>>() {
        return Err(invalid("migration bundle claim population mismatch"));
    }
    let certificate = certificates
        .get(claim_id)
        .ok_or_else(|| invalid("claim-relative migration certificate is absent"))?;
    if field_str(certificate, "transformation_id")? != field_str(bundle, "transformation_id")?
        || !verify_lifecycle_certificate(certificate)?
    {
        return Err(invalid("migration transformation binding mismatch"));
    }
    Ok(certificate.clone())
}

/// Recompute the finite decoder-fiber criterion encoded by a certificate.
pub fn verify_lifecycle_certificate(certificate: &Value) -> Result<bool> {
    exact_keys(
        certificate,
        &[
            "boundaries",
            "certificate_root",
            "claim_id",
            "induced_decoder",
            "kernel_inclusion",
            "lifecycle_twin",
            "rows",
            "schema",
            "source_factorization_root",
            "source_image_root",
            "status",
            "transformation_id",
            "transformation_table_root",
            "transformed_image_root",
        ],
        "lifecycle certificate",
    )?;
    if field_str(certificate, "schema")? != LIFECYCLE_SCHEMA {
        return Ok(false);
    }
    let claim_id = field_str(certificate, "claim_id")?;
    let transformation_id = field_str(certificate, "transformation_id")?;
    identifier(claim_id, "claim_id")?;
    identifier(transformation_id, "transformation_id")?;
    let rows = normalize_rows(field(certificate, "rows")?)?;
    let rebuilt = lifecycle_certificate(claim_id, transformation_id, &rows)?;
    Ok(certificate == &rebuilt)
}

fn lifecycle_certificate(claim_id: &str, transformation_id: &str, rows: &[Value]) -> Result<Value> {
    let source_rows = rows
        .iter()
        .map(|row| {
            Ok(json!({
                "world_id": field(row, "state_id")?.clone(),
                "world": {"source_evidence": field(row, "source_evidence")?.clone()},
                "claim_value": field(row, "claim_value")?.clone(),
                "evidence_value": field(row, "source_evidence")?.clone()
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let source = quotient_certificate(
        claim_id,
        &format!("{transformation_id}:source"),
        &source_rows,
    )?;
    if field(&source, "factorization_exists")?.as_bool() != Some(true) {
        return Err(invalid(
            "capture-time evidence does not support the supplied claim",
        ));
    }
    let twin = first_twin(rows, "transformed_evidence", "state_id")?;
    let decoder = if twin.is_none() {
        partition(rows, "transformed_evidence", "state_id")?
            .into_iter()
            .map(|group| {
                let index = field(&group, "row_indexes")?
                    .as_array()
                    .and_then(|values| values.first())
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("lifecycle partition index is invalid"))?
                    as usize;
                Ok(json!({
                    "transformed_evidence": field(&rows[index], "transformed_evidence")?.clone(),
                    "claim_value": field(&rows[index], "claim_value")?.clone()
                }))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let transformation_table = rows
        .iter()
        .map(|row| {
            Ok(json!({
                "source_evidence": field(row, "source_evidence")?.clone(),
                "transformed_evidence": field(row, "transformed_evidence")?.clone()
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let source_image = rows
        .iter()
        .map(|row| field(row, "source_evidence").cloned())
        .collect::<Result<Vec<_>>>()?;
    let transformed_image = rows
        .iter()
        .map(|row| field(row, "transformed_evidence").cloned())
        .collect::<Result<Vec<_>>>()?;
    let body = json!({
        "schema": LIFECYCLE_SCHEMA,
        "claim_id": claim_id,
        "transformation_id": transformation_id,
        "rows": rows,
        "source_factorization_root": field(&source, "certificate_root")?.clone(),
        "source_image_root": digest("AuditSpec-lifecycle-source-image-v1", &Value::Array(source_image))?,
        "transformation_table_root": digest("AuditSpec-lifecycle-transformation-table-v1", &Value::Array(transformation_table))?,
        "transformed_image_root": digest("AuditSpec-lifecycle-transformed-image-v1", &Value::Array(transformed_image))?,
        "status": if twin.is_none() {"PRESERVED"} else {"HARD_SEMANTIC_GAP"},
        "kernel_inclusion": twin.is_none(),
        "induced_decoder": decoder,
        "lifecycle_twin": twin,
        "boundaries": {
            "finite_declared_image_only": true,
            "transformation_semantics_supplied": true,
            "open_world_completeness_proven": false
        }
    });
    with_root(LIFECYCLE_SCHEMA, body, "certificate_root")
}

fn quotient_certificate(claim_id: &str, evidence_id: &str, rows: &[Value]) -> Result<Value> {
    let twin = first_twin(rows, "evidence_value", "world_id")?;
    let evidence_partition = partition(rows, "evidence_value", "world_id")?;
    let claim_partition = partition(rows, "claim_value", "world_id")?;
    let decoder = if twin.is_none() {
        evidence_partition
            .iter()
            .map(|group| {
                let index = field(group, "row_indexes")?
                    .as_array()
                    .and_then(|values| values.first())
                    .and_then(Value::as_u64)
                    .ok_or_else(|| invalid("quotient partition index is invalid"))?
                    as usize;
                Ok(json!({
                    "evidence_value": field(&rows[index], "evidence_value")?.clone(),
                    "claim_value": field(&rows[index], "claim_value")?.clone()
                }))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let world_table = rows
        .iter()
        .map(|row| {
            Ok(json!({
                "world_id": field(row, "world_id")?.clone(),
                "world": field(row, "world")?.clone()
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let body = json!({
        "schema": QUOTIENT_SCHEMA,
        "claim_id": claim_id,
        "evidence_id": evidence_id,
        "rows": rows,
        "world_count": rows.len(),
        "world_table_root": digest("AuditSpec-finite-information-world-table-v1", &Value::Array(world_table))?,
        "claim_partition": claim_partition,
        "evidence_partition": evidence_partition,
        "claim_partition_root": digest("AuditSpec-claim-partition-v1", &Value::Array(partition(rows, "claim_value", "world_id")?))?,
        "evidence_partition_root": digest("AuditSpec-evidence-partition-v1", &Value::Array(partition(rows, "evidence_value", "world_id")?))?,
        "kernel_inclusion": twin.is_none(),
        "factorization_exists": twin.is_none(),
        "status": if twin.is_none() {"FACTORIZATION"} else {"TWIN_OBSTRUCTION"},
        "decoder_table": decoder,
        "twin": twin,
        "boundaries": {
            "finite_declared_table_only": true,
            "open_world_completeness_proven": false,
            "claim_semantics_supplied": true
        }
    });
    with_root(QUOTIENT_SCHEMA, body, "certificate_root")
}

fn normalize_rows(value: &Value) -> Result<Vec<Value>> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("lifecycle rows are not an array"))?;
    if rows.is_empty() {
        return Err(invalid("lifecycle states are empty or duplicated"));
    }
    let mut normalized = Vec::new();
    let mut ids = BTreeSet::new();
    let mut transformation = BTreeMap::new();
    for row in rows {
        exact_keys(
            row,
            &[
                "claim_value",
                "source_evidence",
                "state_id",
                "transformed_evidence",
            ],
            "lifecycle row",
        )?;
        let state_id = field_str(row, "state_id")?;
        identifier(state_id, "state_id")?;
        if !ids.insert(state_id.to_owned()) {
            return Err(invalid("lifecycle states are empty or duplicated"));
        }
        let source_key = canonical_json(field(row, "source_evidence")?)?;
        let transformed_key = canonical_json(field(row, "transformed_evidence")?)?;
        if transformation
            .insert(source_key, transformed_key.clone())
            .is_some_and(|prior| prior != transformed_key)
        {
            return Err(invalid("lifecycle transformation is not deterministic"));
        }
        normalized.push(row.clone());
    }
    normalized.sort_by_key(|row| field_str(row, "state_id").unwrap_or("").to_owned());
    Ok(normalized)
}

fn partition(rows: &[Value], field_name: &str, id_field: &str) -> Result<Vec<Value>> {
    let mut groups: BTreeMap<String, (Value, Vec<usize>)> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let value = field(row, field_name)?.clone();
        let key = canonical_json(&value)?;
        groups
            .entry(key)
            .or_insert_with(|| (value, Vec::new()))
            .1
            .push(index);
    }
    groups
        .into_values()
        .map(|(value, indexes)| {
            let ids = indexes
                .iter()
                .map(|index| field(&rows[*index], id_field).cloned())
                .collect::<Result<Vec<_>>>()?;
            let mut group = Map::new();
            group.insert("value".to_owned(), value);
            group.insert(
                (if id_field == "world_id" {
                    "world_ids"
                } else {
                    "state_ids"
                })
                .to_owned(),
                Value::Array(ids),
            );
            group.insert("row_indexes".to_owned(), json!(indexes));
            Ok(Value::Object(group))
        })
        .collect()
}

fn first_twin(rows: &[Value], value_field: &str, id_field: &str) -> Result<Option<Value>> {
    let mut buckets: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let value_key = canonical_json(field(row, value_field)?)?;
        let claim_key = canonical_json(field(row, "claim_value")?)?;
        if let Some((prior_index, prior_claim)) = buckets.get(&value_key) {
            if prior_claim != &claim_key {
                let prior = &rows[*prior_index];
                let body = json!({
                    "left_id": field(prior, id_field)?.clone(),
                    "right_id": field(row, id_field)?.clone(),
                    "shared_value": field(row, value_field)?.clone(),
                    "left_claim_value": field(prior, "claim_value")?.clone(),
                    "right_claim_value": field(row, "claim_value")?.clone()
                });
                let mut result = object(&body)?.clone();
                result.insert(
                    "witness_root".to_owned(),
                    Value::String(digest("AuditSpec-information-order-twin-v1", &body)?),
                );
                return Ok(Some(Value::Object(result)));
            }
        } else {
            buckets.insert(value_key, (index, claim_key));
        }
    }
    Ok(None)
}

fn with_root(domain: &str, body: Value, root_field: &str) -> Result<Value> {
    let root = digest(domain, &body)?;
    let mut value = object(&body)?.clone();
    value.insert(root_field.to_owned(), Value::String(root));
    Ok(Value::Object(value))
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let actual = object(value)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid(format!("{label} keys mismatch")));
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("JSON value must be an object"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    object(value)?
        .get(name)
        .ok_or_else(|| invalid(format!("JSON field is absent: {name}")))
}

fn field_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| invalid(format!("JSON field is not a string: {name}")))
}

fn string_array(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| invalid("JSON value must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("JSON array item is not a string"))
        })
        .collect()
}

fn identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/claim_relative_migration_bundle.json"
        ))
        .unwrap()
    }

    #[test]
    fn python_claim_relative_bundle_replays_in_rust() {
        let bundle = fixture();
        let safe = verify_migration_bundle(&bundle, "claim.approval").unwrap();
        let hard = verify_migration_bundle(&bundle, "claim.comment").unwrap();
        assert_eq!(safe["status"], "PRESERVED");
        assert_eq!(hard["status"], "HARD_SEMANTIC_GAP");
        assert!(hard["lifecycle_twin"].is_object());
    }

    #[test]
    fn tampered_lifecycle_certificate_is_rejected() {
        let mut bundle = fixture();
        bundle["certificates"]["claim.approval"]["status"] =
            Value::String("HARD_SEMANTIC_GAP".to_owned());
        assert!(verify_migration_bundle(&bundle, "claim.approval").is_err());
    }
}
