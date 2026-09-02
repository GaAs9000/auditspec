use auditspec::canonical::{canonical_json, digest, strict_json_loads};

const DOMAIN: &str = "AuditSpec-rust-canonical-vector-v1";

#[test]
fn python_reference_vectors_match_byte_for_byte() {
    let vectors = [
        (
            r#"{"z":1,"a":[true,null,"€","😀"],"control":"\n"}"#,
            r#"{"a":[true,null,"€","😀"],"control":"\n","z":1}"#,
            "f477ba1f7c1af51bfa1837fedf13fc60a15cfcc30eeeb4793f866f8066b9071f",
        ),
        (
            r#"{"😀":2,"€":1,"a":3}"#,
            r#"{"a":3,"€":1,"😀":2}"#,
            "b91648c30ff9abaf528e66adb594df671a0a3fcfa8595ce270796706b9c0588a",
        ),
        (
            r#"{"min":-9007199254740991,"max":9007199254740991,"slash":"a/b","quote":"\"\\"}"#,
            r#"{"max":9007199254740991,"min":-9007199254740991,"quote":"\"\\","slash":"a/b"}"#,
            "9a2cfc9dbd732e68f1e17376dbbe94d74513e4fe103b96a420a037bb967e51ec",
        ),
    ];
    for (source, expected_json, expected_digest) in vectors {
        let value = strict_json_loads(source).unwrap();
        assert_eq!(canonical_json(&value).unwrap(), expected_json);
        assert_eq!(digest(DOMAIN, &value).unwrap(), expected_digest);
    }
}
