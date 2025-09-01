// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::session::AuthSession;
use rstest::rstest;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmAlgId, TpmaSession},
    TpmSession,
};

#[rstest]
#[case(
    "handle=0x80000001;nonce=112233;attrs=01;key=;alg=sha256",
    0x80000001,
    &[0x11, 0x22, 0x33],
    TpmaSession::CONTINUE_SESSION,
    &[],
    TpmAlgId::Sha256
)]
#[case(
    "alg=sha384;handle=0x80000002;key=aabbcc;nonce=;attrs=00",
    0x80000002,
    &[],
    TpmaSession::empty(),
    &[0xaa, 0xbb, 0xcc],
    TpmAlgId::Sha384
)]
fn test_session_content_parser_valid(
    #[case] input: &str,
    #[case] handle: u32,
    #[case] nonce: &[u8],
    #[case] attrs: TpmaSession,
    #[case] key: &[u8],
    #[case] alg: TpmAlgId,
) {
    let session = AuthSession::from_str(input).expect("parsing valid session content failed");
    assert_eq!(session.handle, TpmSession(handle));
    assert_eq!(&*session.nonce_tpm, nonce);
    assert_eq!(session.attributes, attrs);
    assert_eq!(&*session.hmac_key, key);
    assert_eq!(session.auth_hash, alg);
}

#[rstest]
#[case("session://handle=0x123", "invalid format (contains scheme)")]
#[case("", "missing 'handle'")]
#[case("nonce=112233;attrs=01;key=;alg=sha256", "missing 'handle'")]
#[case("handle=0x123;nonce=112233;key=;alg=sha256", "missing 'attrs'")]
#[case("handle=0xGG", "invalid digit")]
#[case("handle=0x123;nonce=1122GG", "invalid digit")]
#[case("handle=0x123;attrs=123", "invalid length")]
#[case("handle=0x123;alg=foo", "invalid algorithm")]
fn test_session_content_parser_invalid(#[case] input: &str, #[case] _reason: &str) {
    assert!(
        AuthSession::from_str(input).is_err(),
        "parsing should fail for: {}",
        input
    );
}

#[rstest]
fn test_session_roundtrip() {
    let content = "handle=0x80000001;nonce=112233;attrs=01;key=;alg=sha256";
    let session = AuthSession::from_str(content).unwrap();
    let formatted = session.to_string();
    let result = AuthSession::from_str(&formatted).unwrap();
    assert_eq!(session.handle, result.handle);
    assert_eq!(session.nonce_tpm, result.nonce_tpm);
    assert_eq!(session.attributes, result.attributes);
    assert_eq!(session.hmac_key, result.hmac_key);
    assert_eq!(session.auth_hash, result.auth_hash);
}
