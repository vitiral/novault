pub use std::process::exit;

pub use prelude::*;

pub static CHECK_HASH: &str = "__checkhash__";

static INVALID_LEN: &str = "\
    Master password length must be > 10. It is better to make \
    a long password that you can remember than a short one with \
    lots of symbols. \"battery horse loves staple\" has high \
    entropy but is reasonably easy to remember.";

error_chain!{
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    foreign_links {
        Fmt(::std::fmt::Error);
        Io(::std::io::Error) #[cfg(unix)];
        StrFmt(::strfmt::FmtError);
        Toml(::toml::de::Error);
    }

    errors {
        ConfigFileExists(path: PathBuf) {
            description("Config file already exists")
            display("Config file {} already exists", path.display())
        }

        InvalidLength {
            description("master password length too short")
            display("{}", INVALID_LEN)
        }

        InvalidFmt(fmt: String) {
            description("Invalid fmt")
            display("{} is an invalid string fmt\nHelp: must have `{{p}}` and use at least 4 \
                    characters of the password", fmt)
        }

        InvalidName(name: String) {
            description("Invalid name")
            display("Name '{}' cannot be used", name)
        }

        SiteExists(name: String) {
            description("Site name exists")
            display("Site '{}' already exists.\nHelp: use -o/--overwrite to overwrite it.", name)
        }

        CheckFailed {
            description("master passwords do not match")
            display("Incorrect password, the original hash does not match")
        }

        NotFound(name: String) {
            description("Site not found")
            display("Site {} not found \nHelp: use `list` to list sites", name)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
	pub settings: Settings,
	pub sites: BTreeMap<String, Site>,
}

impl Config {
	pub fn load(path: &Path) -> Result<Config> {
		let mut f = File::open(path)
            .chain_err(|| format!("Could not open: {}", path.display()))?;
		let mut out = String::new();
		f.read_to_string(&mut out)
            .chain_err(|| format!("Failed to read: {}", path.display()))?;
		::toml::from_str(&out)
            .chain_err(|| format!("Config file format is invalid: {}", path.display()))
	}

	pub fn dump(&self, file: &mut File) -> Result<()> {
		file.write_all(::toml::to_string_pretty(self).unwrap().as_ref())?;
        Ok(())
	}
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
	/// hash of `CHECK_HASH`
	pub checkhash: String,

	/// number of times a password is re-hashed
	pub level: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Site {
	pub fmt: String,
	pub pin: bool,
	pub rev: u64,
    pub notes: String,
}
