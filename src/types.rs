//! Types for this application.
//!
//! The types are expressive, some of them just wrappers around string. This is to avoid
//! accidentaly using the wrong type in security critical cases.

pub use std::process::exit;

pub use prelude::*;

pub const ENCRYPT_LEN: usize = 128;
pub const CHECK_HASH_LEN: usize = 16;
pub const SECRET_LEN: usize = 256;
pub static CHECK_HASH: &str = "__checkhash__";

const INVALID_LEN: &str = "Master password length must be greather than 10 and less than or \
                           equal to 32 bytes. It is better to make a long password that you can \
                           remember than a short one with lots of symbols. \"battery horse loves \
                           staple\" has high entropy but is reasonably easy to remember.\n\
                           Found length: ";
pub static SITE_HEADER: &str = "NAME\tNOTES";
pub const INSECURE_MSG: &str = "!!! NOTICE: You are about to perform an insecure operation, be sur\
                                e you know what you are doing before typing in your password !!!";


error_chain!{
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error) #[cfg(unix)];
        StrFmt(::strfmt::FmtError);
        Toml(::toml::de::Error);
        Argon(::argon2rs::ParamErr);
    }

    errors {
        SecretFileExists(path: PathBuf) {
            description("Secret file already exists")
            display("Secret file {} already exists", path.display())
        }

        InvalidLength(len: usize) {
            description("master password must be between 10 and 32 characters")
            display("{}{}", INVALID_LEN, len)
        }

        InvalidSiteName {
            description("site name length is too short")
            display("site name must be at least 1 character long")

        }

        InvalidFmt(fmt: String) {
            description("Invalid fmt")
            display("{} is an invalid string fmt\nHelp: must have `{{p}}` and use at least 4 \
                    characters of the password", fmt)
        }

        SiteExists(name: String) {
            description("Site name exists")
            display("Site '{}' already exists.\nHelp: use -o/--overwrite to overwrite it.", name)
        }

        CheckFailed(result: String, expected: String) {
            description("master passwords do not match")
            display("Incorrect password, the original hash does not match: {:?} != {:?}",
                    result, expected)
        }

        NotFound(name: String) {
            description("Site not found")
            display("Site {} not found \nHelp: use `list` to list sites", name)
        }

        InvalidCmd(msg: String) {
            description("user specified an invalid combination of options")
            display("{}", msg)
        }
    }
}


/// "Site Password" type. This exists to avoid confusing it with another string and
/// to avoid accidentally serializing it.
///
/// The data is not as sensitive as the master password, but still should
/// be audited
pub struct SitePass {
    pub audit_this: String,
}

impl SitePass {
    pub fn new(s: &str) -> SitePass {
        SitePass {
            audit_this: s.to_string(),
        }
    }
}

/// Check Hash type. This exists for validating the master password.  This is the ONLY type that is
/// allowed to be serialized!
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckHash(pub String);

impl CheckHash {
    pub fn fake() -> CheckHash {
        CheckHash("fake-checkhash".to_string())
    }
}

/// Local secret, stored on the file system.
///
/// This is used as the "plaintext" input in the Argon2 algorithm
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Secret(pub String);

impl Secret {
    pub fn fake() -> Secret {
        Secret("fake-secret".to_string())
    }
}

/// "global" arguments from the cmdline options
pub struct OptGlobal {
    pub sites: PathBuf,
    pub secret: PathBuf,
    pub stdin: bool,
    pub stdout: bool,
}

pub type Sites = BTreeMap<String, Site>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// number of times a password is re-hashed
    pub level: u32,

    /// memory usage in MiB
    pub mem: u32,

    /// threads to use
    pub threads: u32,

    /// Associated checkhash
    pub checkhash: CheckHash,

    /// Associated secret
    pub secret: Secret,
}

impl Settings {
    pub fn fake() -> Settings {
        Settings {
            level: 1,
            mem: 16,
            threads: 1,
            checkhash: CheckHash::fake(),
            secret: Secret::fake(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The site password is the hash of the `MasterPass` + salt
pub struct Site {
    #[serde(rename = "!! fmt !!")]
    /// extra formatting for the password
    pub fmt: String,

    #[serde(rename = "!! pin !!")]
    /// force the password to be a pin (all digits 0-9)
    pub pin: bool,

    #[serde(rename = "!! salt !!")]
    /// salt, generated from the name
    pub salt: String,

    /// extra notes for the password, does not affect password
    pub notes: String,
}

impl Site {
    pub fn line_str(&self, name: &str) -> String {
        format!(
            "{}\t{}\t{}",
            name,
            self.fmt,
            self.notes.replace('\t', "▶ "),
        )
    }
}
