// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::{parser::PolicyExpr, session::AuthSession, uri::Uri};
use rstest::rstest;
use std::str::FromStr;
use tpm2_protocol::{
    data::{Tpm2bAuth, Tpm2bNonce, TpmAlgId, TpmaSession},
    TpmSession,
};

#[rstest]
#[case(
    "session://handle=0x80000001;nonce=112233;attrs=01;key=;alg=sha256",
    0x80000001,
    &[0x11, 0x22, 0x33],
    TpmaSession::CONTINUE_SESSION,
    &[],
    TpmAlgId::Sha256
)]
#[case(
    "session://alg=sha384;handle=0x80000002;key=aabbcc;nonce=;attrs=00",
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
    let uri = Uri::from_str(input).expect("parsing valid session uri failed");
    let ast = uri.ast();

    if let PolicyExpr::Session {
        handle: h,
        nonce: n,
        attrs: a,
        key: k,
        alg: al,
    } = ast
    {
        assert_eq!(*h, handle);
        assert_eq!(n, nonce);
        assert_eq!(TpmaSession::from_bits_truncate(*a), attrs);
        assert_eq!(k, key);
        assert_eq!(cli::key::tpm_alg_id_from_str(al).unwrap(), alg);
    } else {
        panic!("Parsed AST is not a session expression");
    }
}

#[rstest]
#[case("session://handle=0x123", "missing fields")]
#[case("session://", "missing fields")]
#[case("session://nonce=112233;attrs=01;key=;alg=sha256", "missing handle")]
#[case("session://handle=0x123;nonce=112233;key=;alg=sha256", "missing attrs")]
#[case("session://handle=0xGG", "invalid digit")]
#[case("session://handle=0x123;nonce=1122GG", "invalid digit")]
#[case("session://handle=0x123;attrs=123", "invalid length")]
#[case("session://handle=0x123;alg=foo", "invalid algorithm")]
fn test_session_content_parser_invalid(#[case] input: &str, #[case] _reason: &str) {
    assert!(
        Uri::from_str(input).is_err(),
        "parsing should fail for: {}",
        input
    );
}

#[rstest]
fn test_session_roundtrip() {
    let session = AuthSession {
        handle: TpmSession(0x80000001),
        nonce_tpm: Tpm2bNonce::try_from(&[0x11, 0x22, 0x33][..]).unwrap(),
        attributes: TpmaSession::CONTINUE_SESSION,
        hmac_key: Tpm2bAuth::try_from(&[][..]).unwrap(),
        auth_hash: TpmAlgId::Sha256,
    };
    let formatted = session.to_string();
    let parsed_uri = Uri::from_str(&format!("session://{formatted}")).unwrap();
    let ast = parsed_uri.ast();

    if let PolicyExpr::Session {
        handle,
        nonce,
        attrs,
        key,
        alg,
    } = ast
    {
        assert_eq!(*handle, session.handle.0);
        assert_eq!(**nonce, *session.nonce_tpm);
        assert_eq!(TpmaSession::from_bits_truncate(*attrs), session.attributes);
        assert_eq!(**key, *session.hmac_key);
        assert_eq!(
            cli::key::tpm_alg_id_from_str(alg).unwrap(),
            session.auth_hash
        );
    } else {
        panic!("Parsed AST is not a session expression");
    }
}
