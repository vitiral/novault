//! Types for this application.
//!
//! The types are expressive, some of them just wrappers around string. This is to avoid
//! accidentaly using the wrong type in security critical cases.

pub use std::process::exit;

pub use prelude::*;

pub static ENCRYPT_LEN: usize = 128;
pub static CHECK_HASH: &str = "__checkhash__";

const INVALID_LEN: &str = "Master password length must be greather than 10 and less than or \
                           equal to 32 bytes. It is better to make a long password that you can \
                           remember than a short one with lots of symbols. \"battery horse loves \
                           staple\" has high entropy but is reasonably easy to remember.\n\
                           Found length: ";
pub static SITE_HEADER: &str = "NAME\tNOTES";


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
        ConfigFileExists(path: PathBuf) {
            description("Config file already exists")
            display("Config file {} already exists", path.display())
        }

        SecretFileExists(path: PathBuf) {
            description("Secret file already exists")
            display("Secret file {} already exists", path.display())
        }

        SecretFileDoesNotExists(path: PathBuf) {
            description("Secret file doesn't exists")
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

/// Local secret, stored on the file system.
///
/// This is used as the "salt secret" in the Argon2 algorithm. This
/// value is 512 characters of random ascii generated from `init`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Secret(pub String);

impl Secret {
    pub fn load(path: &Path) -> Result<Secret> {
        let mut f = File::open(path).chain_err(|| format!("Could not open: {}", path.display()))?;
        let mut out = String::new();
        f.read_to_string(&mut out)
            .chain_err(|| format!("Failed to read: {}", path.display()))?;
        Ok(Secret(out))
    }

    pub fn dump(&self, file: &mut File) -> Result<()> {
        file.write_all(self.0.as_ref())?;
        Ok(())
    }

    pub fn fake() -> Secret {
        Secret("fake-secret".to_string())
    }
}

/// "global" arguments from the cmdline options
pub struct OptGlobal {
    pub config: PathBuf,
    pub secret: PathBuf,
    pub stdin: bool,
    pub stdout: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "!! INITIAL SETTINGS -- DO NOT CHANGE !!")] pub settings: Settings,
    pub sites: BTreeMap<String, Site>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let mut f = File::open(path).chain_err(|| format!("Could not open: {}", path.display()))?;
        let mut out = String::new();
        f.read_to_string(&mut out)
            .chain_err(|| format!("Failed to read: {}", path.display()))?;
        ::toml::from_str(&out).chain_err(|| {
            format!("Config file format is invalid: {}", path.display())
        })
    }

    pub fn dump(&self, file: &mut File) -> Result<()> {
        file.write_all(::toml::to_string(self).unwrap().as_ref())?;
        Ok(())
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// hash of `CHECK_HASH`
    pub checkhash: CheckHash,

    /// number of times a password is re-hashed
    pub level: u32,

    /// memory usage in MiB
    pub mem: u32,

    /// threads to use
    pub threads: u32,
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
