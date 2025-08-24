// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{ContextData, ObjectData, PcrOutput, SessionData};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use log::trace;
use std::vec::Vec;
use tpm2_protocol::{
    self,
    data::{
        self, Tpm2bPublic, Tpm2bSensitiveCreate, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRh,
        TpmSe, TpmSt, TpmaAlgorithm, TpmaLocality, TpmaNv, TpmaObject, TpmaSession, TpmiYesNo,
        TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsCreationData,
        TpmsEccPoint, TpmsKeyedhashParms, TpmsPcrSelection, TpmsSensitiveCreate,
        TpmsSymcipherParms, TpmtHa, TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDefObject,
        TpmtTkCreation, TpmtTkHashcheck, TpmuCapabilities, TpmuHa, TpmuPublicId, TpmuPublicParms,
        TpmuSensitiveComposite, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{
        TpmCommandBody, TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreateCommand, TpmCreatePrimaryCommand,
        TpmCreatePrimaryResponse, TpmCreateResponse, TpmDictionaryAttackLockResetCommand,
        TpmDictionaryAttackLockResetResponse, TpmEvictControlCommand, TpmEvictControlResponse,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse, TpmLoadCommand,
        TpmLoadResponse, TpmPcrEventCommand, TpmPcrEventResponse, TpmPcrReadCommand,
        TpmPcrReadResponse, TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse,
        TpmPolicyOrCommand, TpmPolicyPcrCommand, TpmPolicySecretCommand, TpmReadPublicCommand,
        TpmReadPublicResponse, TpmResponseBody, TpmStartAuthSessionCommand,
        TpmStartAuthSessionResponse, TpmUnsealCommand, TpmUnsealResponse,
    },
    TpmBuffer, TpmList, TpmParse, TpmPersistent, TpmSession, TpmTransient,
};

const INDENT: usize = 2;

/// Pretty-prints a JSON object from the pipeline to stdout.
pub fn pretty_print_json_object_to_stdout(envelope: &json::JsonValue, indent: usize) {
    let prefix = " ".repeat(indent * INDENT);
    let obj_type = envelope["type"].as_str().unwrap_or("unknown");
    println!("{prefix}Type: {obj_type}");

    let data = &envelope["data"];
    match obj_type {
        "object" => {
            if let Ok(d) = ObjectData::from_json(data) {
                println!("{prefix}  Parent: {}", d.parent);
                if let Ok(pub_bytes) = base64_engine.decode(d.public) {
                    if let Ok((pub_obj, _)) = data::Tpm2bPublic::parse(&pub_bytes) {
                        println!("{prefix}  Public:");
                        pretty_print_tpmt_public(&pub_obj.inner, indent + 2);
                    }
                }
            }
        }
        "session" => {
            if let Ok(d) = SessionData::from_json(data) {
                println!("{prefix}  Handle: {:#010x}", d.handle);
                if let Ok(alg) = TpmAlgId::try_from(d.auth_hash) {
                    println!("{prefix}  Auth Hash: {alg}");
                }
                println!("{prefix}  Policy Digest: {}", d.policy_digest);
            }
        }
        "context" => {
            if let Ok(d) = ContextData::from_json(data) {
                if let Ok(ctx_bytes) = base64_engine.decode(d.context_blob) {
                    if let Ok((ctx_obj, _)) = data::TpmsContext::parse(&ctx_bytes) {
                        println!("{prefix}  Context:");
                        ctx_obj.pretty_trace("", indent + 2);
                    }
                }
            }
        }
        "pcr-values" => {
            if let Ok(d) = PcrOutput::from_json(data) {
                println!("{prefix}  Update Counter: {}", d.update_counter);
                for (bank, pcrs) in d.banks {
                    println!("{prefix}  Bank ({bank}):");
                    for (pcr, digest) in pcrs {
                        println!("{prefix}    PCR {pcr}: {digest}");
                    }
                }
            }
        }
        _ => println!("{prefix}  Data: {}", data.dump()),
    }
}

fn pretty_print_tpmt_public(public: &TpmtPublic, indent: usize) {
    let prefix = " ".repeat(indent * INDENT);
    println!("{prefix}Type: {}", public.object_type);
    println!("{prefix}Name Alg: {}", public.name_alg);
    let flags: Vec<_> = public.object_attributes.flag_names().collect();
    println!("{prefix}Attributes: {}", flags.join(" | "));

    match &public.parameters {
        TpmuPublicParms::Rsa(params) => {
            println!("{prefix}Parameters (RSA):");
            println!("{prefix}  Key Bits: {}", params.key_bits);
            let exp_val = if params.exponent == 0 {
                "65537 (default)".to_string()
            } else {
                params.exponent.to_string()
            };
            println!("{prefix}  Exponent: {exp_val}");
        }
        TpmuPublicParms::Ecc(params) => {
            println!("{prefix}Parameters (ECC):");
            println!("{prefix}  Curve: {:?}", params.curve_id);
        }
        _ => {}
    }
}

pub trait PrettyTrace {
    fn pretty_trace(&self, name: &str, indent: usize);
}

macro_rules! pretty_trace_simple {
    ($type:ty, $format:literal) => {
        impl PrettyTrace for $type {
            fn pretty_trace(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                trace!(
                    target: "cli::device",
                    "{prefix}{name}: {value}",
                    prefix = prefix,
                    name = name,
                    value = format_args!($format, self)
                );
            }
        }
    };
}

macro_rules! pretty_trace_bitflags {
    ($type:ty) => {
        impl PrettyTrace for $type {
            fn pretty_trace(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                let flags: Vec<&str> = self.flag_names().collect();
                let flags_str = if flags.is_empty() {
                    "NONE".to_string()
                } else {
                    flags.join(" | ")
                };
                trace!(
                    target: "cli::device",
                    "{prefix}{name}: {flags_str} ({value:#x})",
                    name = name,
                    prefix = prefix,
                    flags_str = flags_str,
                    value = self.bits()
                );
            }
        }
    };
}

pretty_trace_simple!(u8, "{:#04x}");
pretty_trace_simple!(u16, "{:#06x}");
pretty_trace_simple!(u32, "{:#010x}");
pretty_trace_simple!(u64, "{:#018x}");
pretty_trace_simple!(i32, "{}");
pretty_trace_simple!(TpmAlgId, "{}");
pretty_trace_simple!(TpmCc, "{}");
pretty_trace_simple!(TpmRh, "{}");
pretty_trace_simple!(TpmCap, "{}");
pretty_trace_simple!(TpmSe, "{:?}");
pretty_trace_simple!(TpmSt, "{:?}");
pretty_trace_simple!(TpmEccCurve, "{:?}");
pretty_trace_simple!(TpmiYesNo, "{:?}");
pretty_trace_simple!(TpmTransient, "{:#010x}");
pretty_trace_simple!(TpmPersistent, "{:#010x}");
pretty_trace_simple!(TpmSession, "{:#010x}");
pretty_trace_simple!(data::TpmiRhHierarchy, "{:#010x}");
pretty_trace_simple!(data::TpmiDhObject, "{:#010x}");
pretty_trace_simple!(data::TpmiShAuthSession, "{:#010x}");

pretty_trace_bitflags!(TpmaObject);
pretty_trace_bitflags!(TpmaAlgorithm);
pretty_trace_bitflags!(TpmaSession);
pretty_trace_bitflags!(TpmaLocality);
pretty_trace_bitflags!(TpmaNv);

impl<const CAPACITY: usize> PrettyTrace for TpmBuffer<CAPACITY> {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(
            target: "cli::device",
            "{}{}: (size={}) {}",
            prefix,
            name,
            self.len(),
            hex::encode(self)
        );
    }
}

impl<T, const CAPACITY: usize> PrettyTrace for TpmList<T, CAPACITY>
where
    T: PrettyTrace + Copy + Default,
{
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}: (count={})", prefix, name, self.len());
        for item in self.iter() {
            item.pretty_trace("", indent + 1);
        }
    }
}

macro_rules! pretty_trace_struct {
    ($type:ty, $($field:ident => $name:literal),* $(,)?) => {
        impl PrettyTrace for $type {
            fn pretty_trace(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                if !name.is_empty() {
                    trace!(target: "cli::device", "{}{}:", prefix, name);
                } else if stringify!($($field),*).is_empty() {
                    return;
                }

                #[allow(unused_variables)]
                let field_indent = if name.is_empty() { indent } else { indent + 1 };
                $(
                    self.$field.pretty_trace($name, field_indent);
                )*
            }
        }
    };
}

pretty_trace_struct!(TpmsAlgProperty, alg => "alg", alg_properties => "algProperties");
pretty_trace_struct!(TpmsPcrSelection, hash => "hash", pcr_select => "pcrSelect");
pretty_trace_struct!(TpmsKeyedhashParms, scheme => "scheme");
pretty_trace_struct!(TpmsSymcipherParms, sym => "sym");
pretty_trace_struct!(TpmtKdfScheme, scheme => "scheme");
pretty_trace_struct!(TpmtScheme, scheme => "scheme");
pretty_trace_struct!(TpmsEccPoint, x => "x", y => "y");
pretty_trace_struct!(TpmsContext, sequence => "sequence", saved_handle => "savedHandle", hierarchy => "hierarchy", context_blob => "contextBlob");
pretty_trace_struct!(TpmsAuthCommand, session_handle => "sessionHandle", nonce => "nonce", session_attributes => "sessionAttributes", hmac => "hmac");
pretty_trace_struct!(TpmsSensitiveCreate, user_auth => "userAuth", data => "data");
pretty_trace_struct!(TpmtTkCreation, tag => "tag", hierarchy => "hierarchy", digest => "digest");
pretty_trace_struct!(TpmtTkHashcheck, tag => "tag", hierarchy => "hierarchy", digest => "digest");
pretty_trace_struct!(
    TpmsCreationData,
    pcr_select => "pcrSelect",
    pcr_digest => "pcrDigest",
    locality => "locality",
    parent_name_alg => "parentNameAlg",
    parent_name => "parentName",
    parent_qualified_name => "parentQualifiedName",
    outside_info => "outsideInfo",
);
pretty_trace_struct!(Tpm2bPublic, inner => "inner");
pretty_trace_struct!(Tpm2bSensitiveCreate, inner => "inner");
pretty_trace_struct!(data::Tpm2bCreationData, inner => "inner");

// Commands
pretty_trace_struct!(TpmCreatePrimaryCommand, primary_handle => "primaryHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
pretty_trace_struct!(TpmContextSaveCommand, save_handle => "saveHandle");
pretty_trace_struct!(TpmEvictControlCommand, auth => "auth", object_handle => "objectHandle", persistent_handle => "persistentHandle");
pretty_trace_struct!(TpmFlushContextCommand, flush_handle => "flushHandle");
pretty_trace_struct!(TpmReadPublicCommand, object_handle => "objectHandle");
pretty_trace_struct!(TpmImportCommand, parent_handle => "parentHandle", encryption_key => "encryptionKey", object_public => "objectPublic", duplicate => "duplicate", in_sym_seed => "inSymSeed", symmetric_alg => "symmetricAlg");
pretty_trace_struct!(TpmLoadCommand, parent_handle => "parentHandle", in_private => "inPrivate", in_public => "inPublic");
pretty_trace_struct!(TpmPcrEventCommand, pcr_handle => "pcrHandle", event_data => "eventData");
pretty_trace_struct!(TpmPcrReadCommand, pcr_selection_in => "pcrSelectionIn");
pretty_trace_struct!(TpmPolicyPcrCommand, policy_session => "policySession", pcr_digest => "pcrDigest", pcrs => "pcrs");
pretty_trace_struct!(TpmPolicySecretCommand, auth_handle => "authHandle", policy_session => "policySession", nonce_tpm => "nonceTpm", cp_hash_a => "cpHashA", policy_ref => "policyRef", expiration => "expiration");
pretty_trace_struct!(TpmPolicyOrCommand, policy_session => "policySession", p_hash_list => "pHashList");
pretty_trace_struct!(TpmPolicyGetDigestCommand, policy_session => "policySession");
pretty_trace_struct!(TpmDictionaryAttackLockResetCommand, lock_handle => "lockHandle");
pretty_trace_struct!(TpmCreateCommand, parent_handle => "parentHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
pretty_trace_struct!(TpmUnsealCommand, item_handle => "itemHandle");
pretty_trace_struct!(TpmGetCapabilityCommand, cap => "cap", property => "property", property_count => "propertyCount");
pretty_trace_struct!(TpmStartAuthSessionCommand, tpm_key => "tpmKey", bind => "bind", nonce_caller => "nonceCaller", encrypted_salt => "encryptedSalt", session_type => "sessionType", symmetric => "symmetric", auth_hash => "authHash");
pretty_trace_struct!(TpmContextLoadCommand, context => "context");

// Responses
pretty_trace_struct!(TpmCreatePrimaryResponse, object_handle => "objectHandle", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket", name => "name");
pretty_trace_struct!(TpmContextSaveResponse, context => "context");
pretty_trace_struct!(TpmEvictControlResponse,);
pretty_trace_struct!(TpmFlushContextResponse,);
pretty_trace_struct!(TpmReadPublicResponse, out_public => "outPublic", name => "name", qualified_name => "qualifiedName");
pretty_trace_struct!(TpmImportResponse, out_private => "outPrivate");
pretty_trace_struct!(TpmLoadResponse, object_handle => "objectHandle", name => "name");
pretty_trace_struct!(TpmPcrEventResponse, digests => "digests");
pretty_trace_struct!(TpmPolicyGetDigestResponse, policy_digest => "policyDigest");
pretty_trace_struct!(TpmDictionaryAttackLockResetResponse,);
pretty_trace_struct!(TpmCreateResponse, out_private => "outPrivate", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket");
pretty_trace_struct!(TpmUnsealResponse, out_data => "outData");
pretty_trace_struct!(TpmGetCapabilityResponse, more_data => "moreData", capability_data => "capabilityData");
pretty_trace_struct!(TpmPcrReadResponse, pcr_update_counter => "pcrUpdateCounter", pcr_selection_out => "pcrSelectionOut", pcr_values => "pcrValues");
pretty_trace_struct!(TpmStartAuthSessionResponse, session_handle => "sessionHandle", nonce_tpm => "nonceTpm");
pretty_trace_struct!(TpmContextLoadResponse, loaded_handle => "loadedHandle");

impl PrettyTrace for TpmuHa {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        let (variant, bytes): (&str, &[u8]) = match self {
            Self::Sha1(d) => ("Sha1", d),
            Self::Sha256(d) => ("Sha256", d),
            Self::Sha384(d) => ("Sha384", d),
            Self::Sha512(d) => ("Sha512", d),
            Self::Sm3_256(d) => ("Sm3_256", d),
        };
        trace!(
            target: "cli::device",
            "{}{}: (size={}) {} ({})",
            prefix,
            name,
            bytes.len(),
            hex::encode(bytes),
            variant,
        );
    }
}

impl PrettyTrace for TpmtHa {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.hash_alg.pretty_trace("hashAlg", indent + 1);
        self.digest.pretty_trace("digest", indent + 1);
    }
}

impl PrettyTrace for TpmsCapabilityData {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.capability.pretty_trace("capability", indent + 1);
        self.data.pretty_trace("data", indent + 1);
    }
}

impl PrettyTrace for TpmuCapabilities {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::Algs(algs) => algs.pretty_trace(name, indent),
            Self::Handles(handles) => handles.pretty_trace(name, indent),
            Self::Pcrs(pcrs) => pcrs.pretty_trace(name, indent),
        }
    }
}

impl PrettyTrace for TpmtPublic {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.object_type.pretty_trace("type", indent + 1);
        self.name_alg.pretty_trace("nameAlg", indent + 1);
        self.object_attributes
            .pretty_trace("objectAttributes", indent + 1);
        self.auth_policy.pretty_trace("authPolicy", indent + 1);
        self.parameters.pretty_trace("parameters", indent + 1);
        self.unique.pretty_trace("unique", indent + 1);
    }
}

impl PrettyTrace for TpmuPublicId {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(b) => b.pretty_trace(&format!("{name} (keyedHash)"), indent),
            Self::SymCipher(b) => b.pretty_trace(&format!("{name} (sym)"), indent),
            Self::Rsa(b) => b.pretty_trace(&format!("{name} (rsa)"), indent),
            Self::Ecc(p) => p.pretty_trace(&format!("{name} (ecc)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmuPublicParms {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(details) => {
                details.pretty_trace(&format!("{name} (keyedHash)"), indent);
            }
            Self::SymCipher(details) => details.pretty_trace(&format!("{name} (sym)"), indent),
            Self::Rsa(params) => {
                trace!(target: "cli::device", "{prefix}{name}: (rsa)");
                params.symmetric.pretty_trace("symmetric", indent + 1);
                params.scheme.pretty_trace("scheme", indent + 1);
                params.key_bits.pretty_trace("keyBits", indent + 1);
                params.exponent.pretty_trace("exponent", indent + 1);
            }
            Self::Ecc(params) => {
                trace!(target: "cli::device", "{prefix}{name}: (ecc)");
                params.symmetric.pretty_trace("symmetric", indent + 1);
                params.scheme.pretty_trace("scheme", indent + 1);
                params.curve_id.pretty_trace("curveId", indent + 1);
                params.kdf.pretty_trace("kdf", indent + 1);
            }
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmtSymDefObject {
    fn pretty_trace(&self, name: &str, indent: usize) {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.pretty_trace(name, indent);
        } else {
            let prefix = " ".repeat(indent * INDENT);
            trace!(target: "cli::device", "{prefix}{name}:");
            self.algorithm.pretty_trace("algorithm", indent + 1);
            self.key_bits.pretty_trace("keyBits", indent + 1);
            self.mode.pretty_trace("mode", indent + 1);
        }
    }
}

impl PrettyTrace for TpmuSymKeyBits {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.pretty_trace(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.pretty_trace(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.pretty_trace(&format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.pretty_trace(&format!("{name} (xor)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmuSymMode {
    fn pretty_trace(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.pretty_trace(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.pretty_trace(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.pretty_trace(&format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.pretty_trace(&format!("{name} (xor)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl PrettyTrace for TpmuSensitiveComposite {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::Rsa(b) => b.pretty_trace(&format!("{name} (rsa)"), indent),
            Self::Ecc(b) => b.pretty_trace(&format!("{name} (ecc)"), indent),
            Self::Bits(b) => b.pretty_trace(&format!("{name} (bits)"), indent),
            Self::Sym(b) => b.pretty_trace(&format!("{name} (sym)"), indent),
        }
    }
}

impl PrettyTrace for TpmCommandBody {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::CreatePrimary(cmd) => cmd.pretty_trace(name, indent),
            Self::ContextSave(cmd) => cmd.pretty_trace(name, indent),
            Self::EvictControl(cmd) => cmd.pretty_trace(name, indent),
            Self::FlushContext(cmd) => cmd.pretty_trace(name, indent),
            Self::ReadPublic(cmd) => cmd.pretty_trace(name, indent),
            Self::Import(cmd) => cmd.pretty_trace(name, indent),
            Self::Load(cmd) => cmd.pretty_trace(name, indent),
            Self::PcrEvent(cmd) => cmd.pretty_trace(name, indent),
            Self::PcrRead(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyPcr(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicySecret(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyOr(cmd) => cmd.pretty_trace(name, indent),
            Self::PolicyGetDigest(cmd) => cmd.pretty_trace(name, indent),
            Self::DictionaryAttackLockReset(cmd) => cmd.pretty_trace(name, indent),
            Self::Create(cmd) => cmd.pretty_trace(name, indent),
            Self::Unseal(cmd) => cmd.pretty_trace(name, indent),
            Self::GetCapability(cmd) => cmd.pretty_trace(name, indent),
            Self::StartAuthSession(cmd) => cmd.pretty_trace(name, indent),
            Self::ContextLoad(cmd) => cmd.pretty_trace(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {self:?} (unimplemented pretty trace)");
            }
        }
    }
}

impl PrettyTrace for TpmResponseBody {
    fn pretty_trace(&self, name: &str, indent: usize) {
        match self {
            Self::GetCapability(resp) => resp.pretty_trace(name, indent),
            Self::PcrRead(resp) => resp.pretty_trace(name, indent),
            Self::StartAuthSession(resp) => resp.pretty_trace(name, indent),
            Self::CreatePrimary(resp) => resp.pretty_trace(name, indent),
            Self::ContextSave(resp) => resp.pretty_trace(name, indent),
            Self::EvictControl(resp) => resp.pretty_trace(name, indent),
            Self::FlushContext(resp) => resp.pretty_trace(name, indent),
            Self::ReadPublic(resp) => resp.pretty_trace(name, indent),
            Self::Import(resp) => resp.pretty_trace(name, indent),
            Self::Load(resp) => resp.pretty_trace(name, indent),
            Self::PcrEvent(resp) => resp.pretty_trace(name, indent),
            Self::PolicyGetDigest(resp) => resp.pretty_trace(name, indent),
            Self::DictionaryAttackLockReset(resp) => resp.pretty_trace(name, indent),
            Self::Create(resp) => resp.pretty_trace(name, indent),
            Self::Unseal(resp) => resp.pretty_trace(name, indent),
            Self::ContextLoad(resp) => resp.pretty_trace(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {self:?} (unimplemented pretty trace)");
            }
        }
    }
}
