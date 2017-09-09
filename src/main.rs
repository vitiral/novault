//! novault: programatic vaultless password management

// handle signals:
// https://github.com/BurntSushi/chan-signal

extern crate base64;
extern crate ctrlc;
extern crate dialoguer;
extern crate prelude;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate openssl;
extern crate toml;

use prelude::*;
use structopt::StructOpt;

use std::process::exit;

// ##################################################
// # TYPES

static CHECK_HASH: &str = "__checkhash__";

#[derive(Debug, StructOpt)]
#[structopt(name = "novault")]
/// programatic vaultless password management
struct Opt {
	#[structopt(short = "c", long = "config", default_value = "~/.config/novault.toml")]
	/// Specify an alternate config file to use
    config: String,

	#[structopt(subcommand)]
	cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
	#[structopt(name = "init")]
	/// Initialize the config file
	Init,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
	settings: Settings,
	sites: BTreeMap<String, Site>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Settings {
	/// hash of `CHECK_HASH`
	checkhash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Site {
	user: String,
	url: String,
	revision: u64,
}

impl Config {
	fn load(path: &Path) -> Config {
		let mut f = File::open(path).expect("could not open CONFIG");
		let mut out = String::new();
		f.read_to_string(&mut out).expect("failed to read CONFIG");
		toml::from_str(&out).unwrap()
	}

	fn dump(&self, file: &mut File) {
		file.write_all(toml::to_string(self).unwrap().as_ref())
			.expect("could not write to CONFIG");
	}
}

// ##################################################
// # FUNCTIONS

fn hash(name: &str, password: &str, version: u64) -> String {
	let base = format!("{}{}{}", version, name, password);
	let hashed = openssl::sha::sha512(base.as_ref());
	base64::encode_config(hashed.as_ref(), base64::URL_SAFE_NO_PAD)
}

// ##################################################
// # COMMANDS

/// Initialize the config file
fn init(path: &Path) {
	if path.exists() {
		eprintln!("ERROR: {} already exists", path.display());
		exit(1);
	}
	let password = dialoguer::PasswordInput::new("Enter your master password")
		.interact().unwrap();

	let hashed = hash(&CHECK_HASH, &password, 0).split_at(32).0.to_string();
	let config = Config {
		settings: Settings { checkhash: hashed },
		sites: BTreeMap::new(),
	};
	let mut f = File::create(path).expect("could not create CONFIG");
	config.dump(&mut f);
	exit(0);
}

fn new(path: &Path, opt: &Opt) {
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);

    let path = PathBuf::from(opt.config);

	match opt.cmd {
		Command::Init => {
			init(&path);
		}
	}
}
