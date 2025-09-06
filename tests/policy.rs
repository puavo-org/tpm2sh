// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::policy::{parse, Expression, Parsing};
use rstest::rstest;

#[rstest]
#[case(r#"pcr("sha256:0")"#, Parsing::AuthorizationPolicy, true)]
#[case(
    r#"or(pcr("sha256:0"), secret(tpm://0x40000001))"#,
    Parsing::AuthorizationPolicy,
    true
)]
#[case("tpm://0x81000001", Parsing::AuthorizationPolicy, true)]
#[case("tpm://0x81000001", Parsing::Object, true)]
#[case("file:///path", Parsing::Object, true)]
#[case("data://hex,deadbeef", Parsing::Object, true)]
#[case(r#"pcr("sha256:0")"#, Parsing::Object, false)]
#[case("file:///path", Parsing::Data, true)]
#[case("data://hex,deadbeef", Parsing::Data, true)]
#[case("tpm://0x81000001", Parsing::Data, false)]
#[case(r#"pcr("sha256:0")"#, Parsing::Data, false)]
#[case(r#"pcr("sha256:0")"#, Parsing::PcrSelection, true)]
#[case(r#"pcr("sha256:0,7+sha1:2")"#, Parsing::PcrSelection, true)]
#[case(r#"pcr("sha256:0", "deadbeef")"#, Parsing::PcrSelection, false)]
#[case("tpm://0x81000001", Parsing::PcrSelection, false)]
#[case(
    "session://handle=0x80000001;nonce=1122;attrs=01;key=;alg=sha256",
    Parsing::Session,
    true
)]
#[case("file:///path/to/session.dat", Parsing::Session, true)]
#[case("data://utf8,session://...", Parsing::Session, true)]
#[case("tpm://0x03000000", Parsing::Session, false)]
fn test_policy_parsing_modes(
    #[case] input: &str,
    #[case] mode: Parsing,
    #[case] should_succeed: bool,
) {
    let result = parse(input, mode);
    if should_succeed {
        assert!(
            result.is_ok(),
            "'{input}' with mode {mode:?} failed: {:?}",
            result.err()
        );
    } else {
        assert!(result.is_err(), "'{input}' with mode {mode:?} succeeded.");
    }
}

#[rstest]
#[case(r#"pcr("sha256:0")"#, Expression::Pcr { selection: "sha256:0".to_string(), digest: None, count: None })]
#[case(r#"pcr("sha1:0,15", "deadbeef")"#, Expression::Pcr { selection: "sha1:0,15".to_string(), digest: Some("deadbeef".to_string()), count: None })]
#[case(r#"secret(tpm://0x40000001)"#, Expression::Secret { auth_handle_uri: Box::new(Expression::TpmHandle(0x40000001)), password: None })]
fn test_policy_parser_valid_ast(#[case] input: &str, #[case] expected: Expression) {
    let result = parse(input, Parsing::AuthorizationPolicy)
        .unwrap_or_else(|e| panic!(r#"policy parser failed on valid input "{input}": {e}"#));
    assert_eq!(result, expected);
}
