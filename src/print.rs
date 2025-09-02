// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use log::trace;
use std::vec::Vec;
use tpm2_protocol::{
    self,
    data::{
        self, Tpm2bPublic, Tpm2bSensitiveCreate, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRh,
        TpmSe, TpmSt, TpmaAlgorithm, TpmaCc, TpmaLocality, TpmaNv, TpmaObject, TpmaSession,
        TpmiYesNo, TpmsAlgProperty, TpmsAuthCommand, TpmsCapabilityData, TpmsContext,
        TpmsCreationData, TpmsEccPoint, TpmsKeyedhashParms, TpmsPcrSelection, TpmsSensitiveCreate,
        TpmsSymcipherParms, TpmtHa, TpmtKdfScheme, TpmtPublic, TpmtPublicParms, TpmtScheme,
        TpmtSymDefObject, TpmtTkCreation, TpmtTkHashcheck, TpmuCapabilities, TpmuHa, TpmuPublicId,
        TpmuPublicParms, TpmuSensitiveComposite, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{
        TpmCommandBody, TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreateCommand, TpmCreatePrimaryCommand,
        TpmCreatePrimaryResponse, TpmCreateResponse, TpmDictionaryAttackLockResetCommand,
        TpmDictionaryAttackLockResetResponse, TpmEccParametersCommand, TpmEvictControlCommand,
        TpmEvictControlResponse, TpmFlushContextCommand, TpmFlushContextResponse,
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse,
        TpmLoadCommand, TpmLoadResponse, TpmPcrEventCommand, TpmPcrEventResponse,
        TpmPcrReadCommand, TpmPcrReadResponse, TpmPolicyGetDigestCommand,
        TpmPolicyGetDigestResponse, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmReadPublicCommand, TpmReadPublicResponse, TpmResponseBody,
        TpmStartAuthSessionCommand, TpmStartAuthSessionResponse, TpmTestParmsCommand,
        TpmUnsealCommand, TpmUnsealResponse,
    },
    TpmBuffer, TpmList, TpmPersistent, TpmSession, TpmTransient,
};

const INDENT: usize = 2;

pub trait TpmPrint {
    fn print(&self, name: &str, indent: usize);
}

macro_rules! tpm_print_simple {
    ($type:ty, $format:literal) => {
        impl TpmPrint for $type {
            fn print(&self, name: &str, indent: usize) {
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

macro_rules! tpm_print_bitflags {
    ($type:ty) => {
        impl TpmPrint for $type {
            fn print(&self, name: &str, indent: usize) {
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

tpm_print_simple!(u8, "{:#04x}");
tpm_print_simple!(u16, "{:#06x}");
tpm_print_simple!(u32, "{:#010x}");
tpm_print_simple!(u64, "{:#018x}");
tpm_print_simple!(i32, "{}");
tpm_print_simple!(TpmAlgId, "{}");
tpm_print_simple!(TpmCc, "{}");
tpm_print_simple!(TpmRh, "{}");
tpm_print_simple!(TpmCap, "{}");
tpm_print_simple!(TpmSe, "{:?}");
tpm_print_simple!(TpmSt, "{:?}");
tpm_print_simple!(TpmEccCurve, "{:?}");
tpm_print_simple!(TpmiYesNo, "{:?}");
tpm_print_simple!(TpmTransient, "{:#010x}");
tpm_print_simple!(TpmPersistent, "{:#010x}");
tpm_print_simple!(TpmSession, "{:#010x}");
tpm_print_simple!(data::TpmiRhHierarchy, "{:#010x}");
tpm_print_simple!(data::TpmiDhObject, "{:#010x}");
tpm_print_simple!(data::TpmiShAuthSession, "{:#010x}");

tpm_print_bitflags!(TpmaObject);
tpm_print_bitflags!(TpmaAlgorithm);
tpm_print_bitflags!(TpmaSession);
tpm_print_bitflags!(TpmaLocality);
tpm_print_bitflags!(TpmaNv);
tpm_print_bitflags!(TpmaCc);

impl<const CAPACITY: usize> TpmPrint for TpmBuffer<CAPACITY> {
    fn print(&self, name: &str, indent: usize) {
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

impl<T, const CAPACITY: usize> TpmPrint for TpmList<T, CAPACITY>
where
    T: TpmPrint + Copy + Default,
{
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{}{}: (count={})", prefix, name, self.len());
        for item in self.iter() {
            item.print("", indent + 1);
        }
    }
}

macro_rules! tpm_print_struct {
    ($type:ty, $($field:ident => $name:literal),* $(,)?) => {
        impl TpmPrint for $type {
            fn print(&self, name: &str, indent: usize) {
                let prefix = " ".repeat(indent * INDENT);
                if !name.is_empty() {
                    trace!(target: "cli::device", "{}{}:", prefix, name);
                } else if stringify!($($field),*).is_empty() {
                    return;
                }

                #[allow(unused_variables)]
                let field_indent = if name.is_empty() { indent } else { indent + 1 };
                $(
                    self.$field.print($name, field_indent);
                )*
            }
        }
    };
}

tpm_print_struct!(TpmsAlgProperty, alg => "alg", alg_properties => "algProperties");
tpm_print_struct!(TpmsPcrSelection, hash => "hash", pcr_select => "pcrSelect");
tpm_print_struct!(TpmsKeyedhashParms, scheme => "scheme");
tpm_print_struct!(TpmsSymcipherParms, sym => "sym");
tpm_print_struct!(TpmtKdfScheme, scheme => "scheme");
tpm_print_struct!(TpmtScheme, scheme => "scheme");
tpm_print_struct!(TpmsEccPoint, x => "x", y => "y");
tpm_print_struct!(TpmsContext, sequence => "sequence", saved_handle => "savedHandle", hierarchy => "hierarchy", context_blob => "contextBlob");
tpm_print_struct!(TpmsAuthCommand, session_handle => "sessionHandle", nonce => "nonce", session_attributes => "sessionAttributes", hmac => "hmac");
tpm_print_struct!(TpmsSensitiveCreate, user_auth => "userAuth", data => "data");
tpm_print_struct!(TpmtTkCreation, tag => "tag", hierarchy => "hierarchy", digest => "digest");
tpm_print_struct!(TpmtTkHashcheck, tag => "tag", hierarchy => "hierarchy", digest => "digest");
tpm_print_struct!(
    TpmsCreationData,
    pcr_select => "pcrSelect",
    pcr_digest => "pcrDigest",
    locality => "locality",
    parent_name_alg => "parentNameAlg",
    parent_name => "parentName",
    parent_qualified_name => "parentQualifiedName",
    outside_info => "outsideInfo",
);
tpm_print_struct!(Tpm2bPublic, inner => "inner");
tpm_print_struct!(Tpm2bSensitiveCreate, inner => "inner");
tpm_print_struct!(data::Tpm2bCreationData, inner => "inner");

tpm_print_struct!(TpmCreatePrimaryCommand, primary_handle => "primaryHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
tpm_print_struct!(TpmContextSaveCommand, save_handle => "saveHandle");
tpm_print_struct!(TpmEvictControlCommand, auth => "auth", object_handle => "objectHandle", persistent_handle => "persistentHandle");
tpm_print_struct!(TpmFlushContextCommand, flush_handle => "flushHandle");
tpm_print_struct!(TpmReadPublicCommand, object_handle => "objectHandle");
tpm_print_struct!(TpmImportCommand, parent_handle => "parentHandle", encryption_key => "encryptionKey", object_public => "objectPublic", duplicate => "duplicate", in_sym_seed => "inSymSeed", symmetric_alg => "symmetricAlg");
tpm_print_struct!(TpmLoadCommand, parent_handle => "parentHandle", in_private => "inPrivate", in_public => "inPublic");
tpm_print_struct!(TpmPcrEventCommand, pcr_handle => "pcrHandle", event_data => "eventData");
tpm_print_struct!(TpmPcrReadCommand, pcr_selection_in => "pcrSelectionIn");
tpm_print_struct!(TpmPolicyPcrCommand, policy_session => "policySession", pcr_digest => "pcrDigest", pcrs => "pcrs");
tpm_print_struct!(TpmPolicySecretCommand, auth_handle => "authHandle", policy_session => "policySession", nonce_tpm => "nonceTpm", cp_hash_a => "cpHashA", policy_ref => "policyRef", expiration => "expiration");
tpm_print_struct!(TpmPolicyOrCommand, policy_session => "policySession", p_hash_list => "pHashList");
tpm_print_struct!(TpmPolicyGetDigestCommand, policy_session => "policySession");
tpm_print_struct!(TpmDictionaryAttackLockResetCommand, lock_handle => "lockHandle");
tpm_print_struct!(TpmCreateCommand, parent_handle => "parentHandle", in_sensitive => "inSensitive", in_public => "inPublic", outside_info => "outsideInfo", creation_pcr => "creationPcr");
tpm_print_struct!(TpmUnsealCommand, item_handle => "itemHandle");
tpm_print_struct!(TpmGetCapabilityCommand, cap => "cap", property => "property", property_count => "propertyCount");
tpm_print_struct!(TpmStartAuthSessionCommand, tpm_key => "tpmKey", bind => "bind", nonce_caller => "nonceCaller", encrypted_salt => "encryptedSalt", session_type => "sessionType", symmetric => "symmetric", auth_hash => "authHash");
tpm_print_struct!(TpmContextLoadCommand, context => "context");
tpm_print_struct!(TpmTestParmsCommand, parameters => "parameters");
tpm_print_struct!(TpmEccParametersCommand, curve_id => "curveId");

tpm_print_struct!(TpmCreatePrimaryResponse, object_handle => "objectHandle", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket", name => "name");
tpm_print_struct!(TpmContextSaveResponse, context => "context");
tpm_print_struct!(TpmEvictControlResponse,);
tpm_print_struct!(TpmFlushContextResponse,);
tpm_print_struct!(TpmReadPublicResponse, out_public => "outPublic", name => "name", qualified_name => "qualifiedName");
tpm_print_struct!(TpmImportResponse, out_private => "outPrivate");
tpm_print_struct!(TpmLoadResponse, object_handle => "objectHandle", name => "name");
tpm_print_struct!(TpmPcrEventResponse, digests => "digests");
tpm_print_struct!(TpmPolicyGetDigestResponse, policy_digest => "policyDigest");
tpm_print_struct!(TpmDictionaryAttackLockResetResponse,);
tpm_print_struct!(TpmCreateResponse, out_private => "outPrivate", out_public => "outPublic", creation_data => "creationData", creation_hash => "creationHash", creation_ticket => "creationTicket");
tpm_print_struct!(TpmUnsealResponse, out_data => "outData");
tpm_print_struct!(TpmGetCapabilityResponse, more_data => "moreData", capability_data => "capabilityData");
tpm_print_struct!(TpmPcrReadResponse, pcr_update_counter => "pcrUpdateCounter", pcr_selection_out => "pcrSelectionOut", pcr_values => "pcrValues");
tpm_print_struct!(TpmStartAuthSessionResponse, session_handle => "sessionHandle", nonce_tpm => "nonceTpm");
tpm_print_struct!(TpmContextLoadResponse, loaded_handle => "loadedHandle");

impl TpmPrint for TpmuHa {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        let (variant, bytes): (&str, &[u8]) = match self {
            Self::Null => ("Null", &[]),
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

impl TpmPrint for TpmtHa {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.hash_alg.print("hashAlg", indent + 1);
        self.digest.print("digest", indent + 1);
    }
}

impl TpmPrint for TpmsCapabilityData {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.capability.print("capability", indent + 1);
        self.data.print("data", indent + 1);
    }
}

impl TpmPrint for TpmuCapabilities {
    fn print(&self, name: &str, indent: usize) {
        match self {
            Self::Algs(algs) => algs.print(name, indent),
            Self::Handles(handles) => handles.print(name, indent),
            Self::Commands(commands) => commands.print(name, indent),
            Self::Pcrs(pcrs) => pcrs.print(name, indent),
        }
    }
}

impl TpmPrint for TpmtPublic {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.object_type.print("type", indent + 1);
        self.name_alg.print("nameAlg", indent + 1);
        self.object_attributes.print("objectAttributes", indent + 1);
        self.auth_policy.print("authPolicy", indent + 1);
        self.parameters.print("parameters", indent + 1);
        self.unique.print("unique", indent + 1);
    }
}

impl TpmPrint for TpmuPublicId {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(b) => b.print(&format!("{name} (keyedHash)"), indent),
            Self::SymCipher(b) => b.print(&format!("{name} (sym)"), indent),
            Self::Rsa(b) => b.print(&format!("{name} (rsa)"), indent),
            Self::Ecc(p) => p.print(&format!("{name} (ecc)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmtPublicParms {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        trace!(target: "cli::device", "{prefix}{name}:");
        self.object_type.print("type", indent + 1);
        self.parameters.print("parameters", indent + 1);
    }
}

impl TpmPrint for TpmuPublicParms {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::KeyedHash(details) => {
                details.print(&format!("{name} (keyedHash)"), indent);
            }
            Self::SymCipher(details) => details.print(&format!("{name} (sym)"), indent),
            Self::Rsa(params) => {
                trace!(target: "cli::device", "{prefix}{name}: (rsa)");
                params.symmetric.print("symmetric", indent + 1);
                params.scheme.print("scheme", indent + 1);
                params.key_bits.print("keyBits", indent + 1);
                params.exponent.print("exponent", indent + 1);
            }
            Self::Ecc(params) => {
                trace!(target: "cli::device", "{prefix}{name}: (ecc)");
                params.symmetric.print("symmetric", indent + 1);
                params.scheme.print("scheme", indent + 1);
                params.curve_id.print("curveId", indent + 1);
                params.kdf.print("kdf", indent + 1);
            }
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmtSymDefObject {
    fn print(&self, name: &str, indent: usize) {
        if self.algorithm == TpmAlgId::Null {
            self.algorithm.print(name, indent);
        } else {
            let prefix = " ".repeat(indent * INDENT);
            trace!(target: "cli::device", "{prefix}{name}:");
            self.algorithm.print("algorithm", indent + 1);
            self.key_bits.print("keyBits", indent + 1);
            self.mode.print("mode", indent + 1);
        }
    }
}

impl TpmPrint for TpmuSymKeyBits {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.print(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.print(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.print(&format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.print(&format!("{name} (xor)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmuSymMode {
    fn print(&self, name: &str, indent: usize) {
        let prefix = " ".repeat(indent * INDENT);
        match self {
            Self::Aes(v) => v.print(&format!("{name} (aes)"), indent),
            Self::Sm4(v) => v.print(&format!("{name} (sm4)"), indent),
            Self::Camellia(v) => v.print(&format!("{name} (camellia)"), indent),
            Self::Xor(v) => v.print(&format!("{name} (xor)"), indent),
            Self::Null => trace!(target: "cli::device", "{prefix}{name}: null"),
        }
    }
}

impl TpmPrint for TpmuSensitiveComposite {
    fn print(&self, name: &str, indent: usize) {
        match self {
            Self::Rsa(b) => b.print(&format!("{name} (rsa)"), indent),
            Self::Ecc(b) => b.print(&format!("{name} (ecc)"), indent),
            Self::Bits(b) => b.print(&format!("{name} (bits)"), indent),
            Self::Sym(b) => b.print(&format!("{name} (sym)"), indent),
        }
    }
}

impl TpmPrint for TpmCommandBody {
    fn print(&self, name: &str, indent: usize) {
        match self {
            Self::CreatePrimary(cmd) => cmd.print(name, indent),
            Self::ContextSave(cmd) => cmd.print(name, indent),
            Self::EvictControl(cmd) => cmd.print(name, indent),
            Self::FlushContext(cmd) => cmd.print(name, indent),
            Self::ReadPublic(cmd) => cmd.print(name, indent),
            Self::Import(cmd) => cmd.print(name, indent),
            Self::Load(cmd) => cmd.print(name, indent),
            Self::PcrEvent(cmd) => cmd.print(name, indent),
            Self::PcrRead(cmd) => cmd.print(name, indent),
            Self::PolicyPcr(cmd) => cmd.print(name, indent),
            Self::PolicySecret(cmd) => cmd.print(name, indent),
            Self::PolicyOr(cmd) => cmd.print(name, indent),
            Self::PolicyGetDigest(cmd) => cmd.print(name, indent),
            Self::DictionaryAttackLockReset(cmd) => cmd.print(name, indent),
            Self::Create(cmd) => cmd.print(name, indent),
            Self::Unseal(cmd) => cmd.print(name, indent),
            Self::GetCapability(cmd) => cmd.print(name, indent),
            Self::StartAuthSession(cmd) => cmd.print(name, indent),
            Self::ContextLoad(cmd) => cmd.print(name, indent),
            Self::TestParms(cmd) => cmd.print(name, indent),
            Self::EccParameters(cmd) => cmd.print(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {self:?} (unimplemented pretty trace)");
            }
        }
    }
}

impl TpmPrint for TpmResponseBody {
    fn print(&self, name: &str, indent: usize) {
        match self {
            Self::GetCapability(resp) => resp.print(name, indent),
            Self::PcrRead(resp) => resp.print(name, indent),
            Self::StartAuthSession(resp) => resp.print(name, indent),
            Self::CreatePrimary(resp) => resp.print(name, indent),
            Self::ContextSave(resp) => resp.print(name, indent),
            Self::EvictControl(resp) => resp.print(name, indent),
            Self::FlushContext(resp) => resp.print(name, indent),
            Self::ReadPublic(resp) => resp.print(name, indent),
            Self::Import(resp) => resp.print(name, indent),
            Self::Load(resp) => resp.print(name, indent),
            Self::PcrEvent(resp) => resp.print(name, indent),
            Self::PolicyGetDigest(resp) => resp.print(name, indent),
            Self::DictionaryAttackLockReset(resp) => resp.print(name, indent),
            Self::Create(resp) => resp.print(name, indent),
            Self::Unseal(resp) => resp.print(name, indent),
            Self::ContextLoad(resp) => resp.print(name, indent),
            _ => {
                let prefix = " ".repeat(indent * INDENT);
                trace!(target: "cli::device", "{prefix}{name}: {self:?} (unimplemented pretty trace)");
            }
        }
    }
}
