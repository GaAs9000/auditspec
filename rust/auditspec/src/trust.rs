//! Fail-closed institutional trust evaluation for the System 1.1 C6 split.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};

use crate::canonical::digest;
use crate::{Result, invalid};

const REQUEST_SET_SCHEMA: &str = "AuditSpec-institutional-authority-request-set-v1";
const RESPONSE_SCHEMA: &str = "AuditSpec-institutional-authority-response-v1";
const ROOT_SCHEMA: &str = "AuditSpec-institution-root-record-v1";

pub fn evaluate_institutional_responses(
    request_set: &Value,
    responses: &[Value],
    institution_roots: &[Value],
    external_onboarding_authority: Option<&Value>,
) -> Result<Value> {
    validate_request_set(request_set)?;
    let requests = array(field(request_set, "requests")?)?
        .iter()
        .map(|row| Ok((field_str(row, "role")?.to_owned(), row)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let root_by_institution = institution_roots
        .iter()
        .filter_map(|row| {
            field_str(row, "institution_id")
                .ok()
                .map(|id| (id.to_owned(), row))
        })
        .collect::<BTreeMap<_, _>>();
    let mut response_by_role: BTreeMap<String, &Value> = BTreeMap::new();
    let mut failures = Vec::new();
    for response in responses {
        let role = field_str(response, "role").unwrap_or("");
        let Some(request) = requests.get(role) else {
            failures.push(failure("RESPONSE_ROLE_POPULATION_INVALID", role));
            continue;
        };
        if response_by_role.contains_key(role) {
            failures.push(failure("RESPONSE_ROLE_POPULATION_INVALID", role));
            continue;
        }
        let institution_id = field_str(response, "institution_id").unwrap_or("");
        let root = root_by_institution.get(institution_id).copied();
        if let Err(error) = validate_response(response, request, root) {
            failures.push(failure(
                "RESPONSE_SIGNATURE_OR_BINDING_INVALID",
                &error.to_string(),
            ));
            continue;
        }
        response_by_role.insert(role.to_owned(), response);
    }
    for role in requests.keys() {
        if !response_by_role.contains_key(role) {
            failures.push(failure("EXTERNAL_INSTITUTION_RESPONSE_MISSING", role));
        }
    }
    let rows = response_by_role.values().copied().collect::<Vec<_>>();
    for (field_name, subtype) in [
        ("institution_id", "INSTITUTION_ID_NOT_UNIQUE"),
        ("control_domain", "CONTROL_DOMAIN_NOT_UNIQUE"),
        ("principal_id", "PRINCIPAL_ID_NOT_UNIQUE"),
        ("key_domain", "KEY_DOMAIN_NOT_UNIQUE"),
    ] {
        let values = rows
            .iter()
            .filter_map(|row| field_str(row, field_name).ok())
            .collect::<Vec<_>>();
        if values.len() != values.iter().copied().collect::<BTreeSet<_>>().len() {
            failures.push(failure(subtype, field_name));
        }
    }
    let institution_ids = rows
        .iter()
        .filter_map(|row| field_str(row, "institution_id").ok())
        .collect::<BTreeSet<_>>();
    for row in &rows {
        let institution_id = field_str(row, "institution_id")?;
        let expected = institution_ids
            .iter()
            .filter(|id| **id != institution_id)
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>();
        let actual = string_array(field(row, "independent_from_institution_ids")?)?;
        if actual != expected {
            failures.push(failure(
                "PAIRWISE_INDEPENDENCE_ACKNOWLEDGEMENT_INCOMPLETE",
                institution_id,
            ));
        }
    }
    let roots_external = !rows.is_empty()
        && rows.iter().all(|row| {
            let Ok(institution_id) = field_str(row, "institution_id") else {
                return false;
            };
            let Some(root) = root_by_institution.get(institution_id) else {
                return false;
            };
            field_str(root, "root_source").ok() == Some("external_institution_onboarding")
                && field(root, "external_registry_evidence")
                    .ok()
                    .is_some_and(|value| !value.is_null() && value != &Value::Bool(false))
        });
    let onboarding_verified =
        verify_onboarding_authority(institution_roots, external_onboarding_authority);
    let crypto_complete = failures.is_empty() && rows.len() == requests.len();
    let institutional = crypto_complete && roots_external && onboarding_verified;
    if crypto_complete && !roots_external {
        failures.push(failure("FIXTURE_NOT_EXTERNAL", "root_source"));
    }
    if crypto_complete && roots_external && !onboarding_verified {
        failures.push(failure(
            "EXTERNAL_ONBOARDING_AUTHORITY_UNRESOLVED",
            "onboarding",
        ));
    }
    let mut sorted_responses = responses.to_vec();
    sorted_responses.sort_by_key(|row| field_str(row, "role").unwrap_or("").to_owned());
    Ok(json!({
        "schema": "AuditSpec-institutional-trust-evaluation-v1",
        "status": if institutional {"PASS"} else {"TCB_GAP"},
        "verdict": if institutional {"VERIFIED_AUDITABLE"} else {"TCB_GAP"},
        "failure_subtype": if institutional {Value::Null} else {failures.first().and_then(|row| field(row, "subtype").ok()).cloned().unwrap_or(Value::Null)},
        "failures": failures,
        "request_set_root": field(request_set, "request_set_root")?.clone(),
        "valid_response_count": rows.len(),
        "required_response_count": requests.len(),
        "distinct_institution_count": institution_ids.len(),
        "cryptographic_response_validation_pass": crypto_complete,
        "external_root_provenance_pass": roots_external,
        "external_onboarding_authority_pass": onboarding_verified,
        "institutional_independence_proven": institutional,
        "core_c6_complete": institutional,
        "response_set_root": digest("AuditSpec-institutional-authority-response-set-v1", &Value::Array(sorted_responses))?
    }))
}

fn validate_request_set(value: &Value) -> Result<()> {
    if field_str(value, "schema")? != REQUEST_SET_SCHEMA
        || field(value, "required_role_count")?.as_u64() != Some(6)
        || field(value, "required_pair_count")?.as_u64() != Some(15)
        || field_str(value, "request_set_root")?
            != digest(REQUEST_SET_SCHEMA, field(value, "requests")?)?
    {
        return Err(invalid("institutional request set mismatch"));
    }
    Ok(())
}

fn validate_response(response: &Value, request: &Value, root: Option<&Value>) -> Result<()> {
    exact_keys(
        response,
        &[
            "challenge",
            "control_domain",
            "independent_from_institution_ids",
            "institution_id",
            "key_domain",
            "legal_entity_identifier",
            "principal_id",
            "request_id",
            "response_id",
            "role",
            "schema",
            "signature",
            "signed_at",
        ],
    )?;
    if field_str(response, "schema")? != RESPONSE_SCHEMA
        || field(response, "request_id")? != field(request, "request_id")?
        || field(response, "role")? != field(request, "role")?
        || field(response, "challenge")? != field(request, "challenge")?
    {
        return Err(invalid("institutional response request binding mismatch"));
    }
    let root = root.ok_or_else(|| invalid("institution root is absent"))?;
    if field_str(root, "schema")? != ROOT_SCHEMA {
        return Err(invalid("institution root is absent"));
    }
    for name in [
        "institution_id",
        "legal_entity_identifier",
        "control_domain",
        "principal_id",
        "key_domain",
    ] {
        if field(root, name)? != field(response, name)? {
            return Err(invalid("institution root/response projection mismatch"));
        }
    }
    let mut unsigned = object(response)?.clone();
    unsigned.remove("signature");
    let message = digest(RESPONSE_SCHEMA, &Value::Object(unsigned))?;
    verify_signature(
        field_str(root, "public_key_hex")?,
        field_str(field(response, "signature")?, "hex")?,
        &hex::decode(message).map_err(|_| invalid("institutional response digest invalid"))?,
    )
    .map_err(|_| invalid("institutional response signature invalid"))
}

fn verify_onboarding_authority(roots: &[Value], authority: Option<&Value>) -> bool {
    let Some(authority) = authority else {
        return false;
    };
    let result = (|| -> Result<bool> {
        if field_str(authority, "schema")? != "AuditSpec-external-onboarding-authority-v1" {
            return Ok(false);
        }
        let mut sorted = roots.to_vec();
        sorted.sort_by_key(|row| field_str(row, "institution_id").unwrap_or("").to_owned());
        let root_digest = digest("AuditSpec-institution-root-set-v1", &Value::Array(sorted))?;
        if field_str(authority, "institution_root_set_digest")? != root_digest {
            return Ok(false);
        }
        verify_signature(
            field_str(authority, "public_key_hex")?,
            field_str(authority, "signature_hex")?,
            &hex::decode(root_digest).map_err(|_| invalid("onboarding digest invalid"))?,
        )?;
        Ok(true)
    })();
    result.unwrap_or(false)
}

fn verify_signature(public_hex: &str, signature_hex: &str, message: &[u8]) -> Result<()> {
    let public: [u8; 32] = hex::decode(public_hex)
        .map_err(|_| invalid("Ed25519 public key is invalid"))?
        .try_into()
        .map_err(|_| invalid("Ed25519 public key is invalid"))?;
    let signature: [u8; 64] = hex::decode(signature_hex)
        .map_err(|_| invalid("Ed25519 signature is invalid"))?
        .try_into()
        .map_err(|_| invalid("Ed25519 signature is invalid"))?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| invalid("Ed25519 public key is invalid"))?
        .verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| invalid("Ed25519 signature is invalid"))
}

fn failure(subtype: &str, detail: &str) -> Value {
    json!({"subtype": subtype, "detail": detail})
}

fn exact_keys(value: &Value, required: &[&str]) -> Result<()> {
    let actual = object(value)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = required.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid("institutional response keys/schema mismatch"));
    }
    Ok(())
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("institutional JSON value must be an object"))
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| invalid("institutional JSON value must be an array"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    object(value)?
        .get(name)
        .ok_or_else(|| invalid(format!("institutional JSON field absent: {name}")))
}

fn field_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| invalid(format!("institutional JSON field is not a string: {name}")))
}

fn string_array(value: &Value) -> Result<Vec<String>> {
    array(value)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("institutional string array is malformed"))
        })
        .collect()
}
