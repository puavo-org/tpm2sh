// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the `nom` parser for the unified policy language.

use crate::error::ParseError;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while, take_while1},
    character::complete::{char, space0},
    combinator::{map, map_res, opt, recognize},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, PartialEq, Clone)]
pub enum PolicyExpr {
    Pcr {
        selection: String,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle_uri: Box<PolicyExpr>,
        password: Option<String>,
    },
    Or(Vec<PolicyExpr>),
    TpmHandle(u32),
    FilePath(String),
    Data {
        encoding: String,
        value: String,
    },
    Session {
        handle: u32,
        nonce: Vec<u8>,
        attrs: u8,
        key: Vec<u8>,
        alg: String,
    },
}

impl Default for PolicyExpr {
    fn default() -> Self {
        Self::FilePath(String::new())
    }
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn is_dec_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn from_hex_str_u32(input: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(input, 16)
}

fn from_hex_str_u8(input: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(input, 16)
}

fn hex_u32(input: &str) -> IResult<&str, u32> {
    map_res(
        preceded(tag("0x"), take_while1(is_hex_digit)),
        from_hex_str_u32,
    )(input)
}

fn hex_u8(input: &str) -> IResult<&str, u8> {
    map_res(take_while1(is_hex_digit), from_hex_str_u8)(input)
}

fn pcr_index(input: &str) -> IResult<&str, u32> {
    map_res(take_while1(is_dec_digit), |s: &str| s.parse::<u32>())(input)
}

fn pcr_list(input: &str) -> IResult<&str, Vec<u32>> {
    separated_list1(char(','), pcr_index)(input)
}

fn alg(input: &str) -> IResult<&str, &str> {
    alt((tag("sha1"), tag("sha256"), tag("sha384"), tag("sha512")))(input)
}

fn pcr_bank(input: &str) -> IResult<&str, String> {
    map(
        separated_pair(alg, char(':'), pcr_list),
        |(alg_str, indices)| {
            format!(
                "{}:{}",
                alg_str,
                indices
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        },
    )(input)
}

fn pcr_selection_body(input: &str) -> IResult<&str, String> {
    map(separated_list1(char('+'), pcr_bank), |banks| {
        banks.join("+")
    })(input)
}

fn unquoted_string(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c != ',' && c != ')' && !c.is_whitespace())(input)
}

fn string_argument(input: &str) -> IResult<&str, String> {
    map(
        alt((
            delimited(char('\"'), recognize(many0(is_not("\""))), char('\"')),
            unquoted_string,
        )),
        |s: &str| s.to_string(),
    )(input)
}

fn pcr_selection_argument(input: &str) -> IResult<&str, String> {
    map(
        alt((
            delimited(char('\"'), recognize(many0(is_not("\""))), char('\"')),
            recognize(pcr_selection_body),
        )),
        |s: &str| s.to_string(),
    )(input)
}

fn count_parameter(input: &str) -> IResult<&str, u32> {
    map_res(
        preceded(tag("count="), take_while1(is_dec_digit)),
        |s: &str| s.parse::<u32>(),
    )(input)
}

fn comma_sep<'a, F, O>(f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    preceded(terminated(char(','), space0), f)
}

fn pcr_expression(input: &str) -> IResult<&str, PolicyExpr> {
    map(
        tuple((
            pcr_selection_argument,
            opt(comma_sep(string_argument)),
            opt(comma_sep(count_parameter)),
        )),
        |(selection, digest, count)| PolicyExpr::Pcr {
            selection,
            digest,
            count,
        },
    )(input)
}

fn secret_expression(input: &str) -> IResult<&str, PolicyExpr> {
    map(
        tuple((parse_policy_expr, opt(comma_sep(string_argument)))),
        |(uri_expr, password)| PolicyExpr::Secret {
            auth_handle_uri: Box::new(uri_expr),
            password,
        },
    )(input)
}

fn or_expression(input: &str) -> IResult<&str, PolicyExpr> {
    map(
        pair(
            parse_policy_expr,
            many1(preceded(terminated(char(','), space0), parse_policy_expr)),
        ),
        |(first, mut rest)| {
            let mut branches = vec![first];
            branches.append(&mut rest);
            PolicyExpr::Or(branches)
        },
    )(input)
}

fn call<'a, F, O>(name: &'static str, f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(
        terminated(tag(name), char('(')),
        delimited(space0, f, space0),
        char(')'),
    )
}

fn tpm_uri(input: &str) -> IResult<&str, PolicyExpr> {
    map(preceded(tag("tpm://"), hex_u32), PolicyExpr::TpmHandle)(input)
}

fn file_uri(input: &str) -> IResult<&str, PolicyExpr> {
    map(
        preceded(tag("file://"), take_while1(|c| c != ',' && c != ')')),
        |s: &str| PolicyExpr::FilePath(s.to_string()),
    )(input)
}

fn data_uri(input: &str) -> IResult<&str, PolicyExpr> {
    map(
        preceded(
            tag("data://"),
            separated_pair(
                alt((tag("utf8"), tag("hex"), tag("base64"))),
                char(','),
                take_while(|c: char| c != ',' && c != ')'),
            ),
        ),
        |(enc, val): (&str, &str)| PolicyExpr::Data {
            encoding: enc.to_string(),
            value: val.to_string(),
        },
    )(input)
}

fn pcr_uri(input: &str) -> IResult<&str, PolicyExpr> {
    map(preceded(tag("pcr://"), pcr_selection_body), |selection| {
        PolicyExpr::Pcr {
            selection,
            digest: None,
            count: None,
        }
    })(input)
}

fn session_kv_pair(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(
        alt((
            tag("handle"),
            tag("nonce"),
            tag("attrs"),
            tag("key"),
            tag("alg"),
        )),
        char('='),
        alt((
            recognize(hex_u32),
            recognize(hex_u8),
            alg,
            take_while(is_hex_digit),
        )),
    )(input)
}

fn session_kv_list(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    separated_list1(char(';'), session_kv_pair)(input)
}

fn session_body(input: &str) -> IResult<&str, PolicyExpr> {
    map_res(session_kv_list, |pairs| -> Result<_, String> {
        let mut handle = None;
        let mut nonce = None;
        let mut attrs = None;
        let mut key = None;
        let mut alg = None;
        for (k, v) in pairs {
            match k {
                "handle" => {
                    let stripped_v = v
                        .strip_prefix("0x")
                        .ok_or_else(|| "handle value must start with 0x".to_string())?;
                    handle = Some(from_hex_str_u32(stripped_v).map_err(|e| e.to_string())?);
                }
                "nonce" => nonce = Some(hex::decode(v).map_err(|e| e.to_string())?),
                "attrs" => attrs = Some(from_hex_str_u8(v).map_err(|e| e.to_string())?),
                "key" => key = Some(hex::decode(v).map_err(|e| e.to_string())?),
                "alg" => alg = Some(v.to_string()),
                _ => unreachable!(),
            }
        }
        Ok(PolicyExpr::Session {
            handle: handle.ok_or_else(|| "missing handle".to_string())?,
            nonce: nonce.ok_or_else(|| "missing nonce".to_string())?,
            attrs: attrs.ok_or_else(|| "missing attrs".to_string())?,
            key: key.ok_or_else(|| "missing key".to_string())?,
            alg: alg.ok_or_else(|| "missing alg".to_string())?,
        })
    })(input)
}

fn session_uri(input: &str) -> IResult<&str, PolicyExpr> {
    preceded(tag("session://"), session_body)(input)
}

/// Parses any valid policy language expression.
///
/// # Errors
///
/// Returns a `nom::Err` if the input string does not match any known expression format.
pub fn parse_policy_expr(input: &str) -> IResult<&str, PolicyExpr> {
    alt((
        call("pcr", pcr_expression),
        call("secret", secret_expression),
        call("or", or_expression),
        tpm_uri,
        file_uri,
        data_uri,
        pcr_uri,
        session_uri,
    ))(input)
}

/// Parses a policy language expression, ensuring the entire input is consumed.
///
/// # Errors
///
/// Returns a `ParseError` if the input is not a valid expression or if there is
/// trailing input left after parsing.
pub fn parse_policy(input: &str) -> Result<PolicyExpr, ParseError> {
    match parse_policy_expr(input) {
        Ok(("", expr)) => Ok(expr),
        Ok((rem, _)) => Err(ParseError::Custom(format!(
            "unexpected trailing input: '{rem}'"
        ))),
        Err(e) => Err(ParseError::Custom(e.to_string())),
    }
}
