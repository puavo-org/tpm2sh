// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::uri::Uri;
use rstest::rstest;
use std::str::FromStr;

#[rstest]
#[case("tpm://0x81000001")]
#[case("file:///path/to/some/file.txt")]
#[case("data://utf8,some string data")]
#[case("data://hex,deadbeef")]
#[case("data://base64,aGVsbG8gd29ybGQ=")]
#[case("pcr://sha256:7")]
#[case("pcr://sha1:0x10")]
fn test_uri_from_str_valid(#[case] input: &str) {
    let uri = Uri::from_str(input);
    assert!(uri.is_ok(), "Parsing failed for valid input: {input}");
    assert_eq!(&*uri.unwrap(), input);
}

#[rstest]
#[case("ftp://example.com/file")]
#[case("http://example.com")]
#[case("just_a_string")]
#[case("/path/without/scheme")]
#[case("tpm:/0x123")]
#[case("file:/path")]
#[case("")]
#[case("tpm://1234")]
#[case("tpm://0xGHI")]
#[case("file://")]
#[case("data://utf8")]
#[case("data://unsupported,data")]
#[case("pcr://sha256,")]
#[case("pcr://sha256:xyz")]
#[case("pcr://unsupported:7")]
fn test_uri_from_str_invalid(#[case] input: &str) {
    let uri = Uri::from_str(input);
    assert!(
        uri.is_err(),
        "Parsing unexpectedly succeeded for invalid input: {input}"
    );
}

#[rstest]
fn test_uri_deref() {
    let uri_str = "tpm://0x1234";
    let uri = Uri::from_str(uri_str).unwrap();
    assert_eq!(&*uri, uri_str);
    assert!(uri.starts_with("tpm://"));
}

#[rstest]
fn test_uri_display() {
    let uri_str = "file:///tmp/context.bin";
    let uri = Uri::from_str(uri_str).unwrap();
    assert_eq!(format!("{uri}"), uri_str);
}
