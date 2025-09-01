// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::{
    command::policy::{PolicyParser, Rule as PolicyRule},
    uri::{Rule as UriRule, UriParser},
};
use pest::Parser;
use rstest::rstest;

#[rstest]
#[case("sha1:0")]
#[case("sha256:0,1,23")]
#[case("sha384:15")]
#[case("sha1:0+sha256:1,2")]
#[case("sha1:0+sha256:1,2+sha384:3,4,5")]
fn test_pcr_selection_parser_valid(#[case] input: &str) {
    assert!(UriParser::parse(UriRule::selection_test, input).is_ok());
}

#[rstest]
#[case("sha1")]
#[case("sha256:")]
#[case("sha1:0,,1")]
#[case("sha1:0,")]
#[case("sha1:a")]
#[case("sha256:0+")]
#[case("foo:1")]
#[case("sha256: 0")]
fn test_pcr_selection_parser_invalid(#[case] input: &str) {
    assert!(UriParser::parse(UriRule::selection_test, input).is_err());
}

#[rstest]
#[case(r#"pcr("sha256:0")"#)]
#[case(r#"pcr("sha1:0,15", "deadbeef")"#)]
#[case(r#"pcr("sha256:23", "cafebabe", count=123)"#)]
#[case(r#"secret("tpm://0x40000001")"#)]
#[case(r#"or(pcr("sha256:0"), secret("tpm://0x40000001"))"#)]
#[case(r#"or(pcr("sha256:0"), pcr("sha256:1"), pcr("sha256:2"))"#)]
#[case(r#"or(pcr("sha256:0"), or(secret("tpm://0x40000001"), pcr("sha256:2")))"#)]
fn test_policy_parser_valid(#[case] input: &str) {
    PolicyParser::parse(PolicyRule::policy_expression, input).unwrap_or_else(|e| {
        panic!(r#"policy parser failed on valid input "{input}": {e}"#);
    });
}

#[rstest]
#[case("pcr()")]
#[case(r#"pcr("sha256:0",)"#)]
#[case(r#"pcr("sha256:0", ,"deadbeef")"#)]
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
    assert!(PolicyParser::parse(PolicyRule::policy_expression, input).is_err());
}
