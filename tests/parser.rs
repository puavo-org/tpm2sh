// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::parser::{parse_policy, PolicyExpr};
use rstest::rstest;

#[rstest]
#[case(r#"pcr("sha256:0")"#, PolicyExpr::Pcr { selection: "sha256:0".to_string(), digest: None, count: None })]
#[case(r#"pcr("sha1:0,15", "deadbeef")"#, PolicyExpr::Pcr { selection: "sha1:0,15".to_string(), digest: Some("deadbeef".to_string()), count: None })]
#[case(r#"pcr("sha256:23", "cafebabe", count=123)"#, PolicyExpr::Pcr { selection: "sha256:23".to_string(), digest: Some("cafebabe".to_string()), count: Some(123) })]
#[case(r#"secret(tpm://0x40000001)"#, PolicyExpr::Secret { auth_handle_uri: Box::new(PolicyExpr::TpmHandle(0x40000001)), password: None })]
#[case(r#"or(pcr("sha256:0"), secret(tpm://0x40000001))"#, PolicyExpr::Or(vec![PolicyExpr::Pcr { selection: "sha256:0".to_string(), digest: None, count: None }, PolicyExpr::Secret { auth_handle_uri: Box::new(PolicyExpr::TpmHandle(0x40000001)), password: None }]))]
fn test_policy_parser_valid(#[case] input: &str, #[case] expected: PolicyExpr) {
    let result = parse_policy(input)
        .unwrap_or_else(|e| panic!(r#"policy parser failed on valid input "{input}": {e}"#));
    assert_eq!(result, expected);
}

#[rstest]
#[case("pcr()")]
#[case(r#"pcr("sha256:0",)"#)]
#[case(r#"pcr("sha256:0", , "deadbeef")"#)]
#[case(r#"pcr("sha256:0", "deadbeef", count=)"#)]
#[case(r#"pcr("sha256:0", "deadbeef", count=abc)"#)]
#[case("secret()")]
#[case("or()")]
#[case(r#"or(pcr("sha256:0"))"#)]
#[case(r#"or(pcr("sha256:0"), )"#)]
#[case(r#"foo("bar")"#)]
#[case(r#"pcr("unterminated string)"#)]
#[case(r#""sha256:0""#)]
#[case("")]
fn test_policy_parser_invalid(#[case] input: &str) {
    assert!(
        parse_policy(input).is_err(),
        "parser should have failed for: {input}"
    );
}
