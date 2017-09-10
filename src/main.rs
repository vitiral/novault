//! NoVault: ultra simple and secure password management

// handle signals:
// https://github.com/BurntSushi/chan-signal

extern crate ansi_term;
extern crate base64;
extern crate dialoguer;
#[macro_use]
extern crate error_chain;
extern crate prelude;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate strfmt;
extern crate openssl;
extern crate toml;

use structopt::StructOpt;

mod types;
mod cmds;
mod utils;

use types::*;

// ##################################################
// # Opt

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
	Init {
		#[structopt(long = "level", default_value = "20")]
		/// The password is re-hashed 2 to the power of level (`2^level`) times.
		///
		/// Increasing this number will increase the security of your
		/// passwords, but also take more time to get a password. The default
		/// of 20, (about a million times) takes about 1 second to compute on
		/// my 2 core 800MHz laptop.
		///
		/// It is recommended that this number NEVER be increased above about 50,
		/// unless you are storing your passwords on a GPU super computer.
		///
		/// Do NOT change this paramter once initialized, as it will invalidate
		/// all of your passwords.
		level: u32,
	},

	#[structopt(name = "set")]
	/// Set a site's metadata
    Set {
        #[structopt(name = "name")]
        /// name for the site. Recommended: <username>@<site-url>
        name: String,

        #[structopt(short = "o", long = "overwrite")]
        /// Overwrite even if the site name already exists
        overwrite: bool,

        #[structopt(long = "fmt", default_value = "{p}")]
        /// Format to use for the string. This can be used to reduce
		/// the length of the string and also to add any "special"
		/// characters that might be needed. Must have at least one
		/// field with "{p}" in it. For example, to have a password that
		/// is 10 characters plus "!@" (so 12 characters total) use:
		///
		///     --fmt "{p:.10}!@"
		///
		/// Note: the first 4 characters of the generated password must
		/// appear.
        fmt: String,

        #[structopt(long = "pin")]
		/// Make the password suitable for pins by only the digits 0-9.
		///
		/// This only replaces the hash, you can still control the length,
		/// or add any characters you like with --fmt
        pin: bool,

        #[structopt(short = "r", long = "rev", default_value = "0")]
        /// revision number of password, useful for sites that require passwords to change
        rev: u64,

        #[structopt(short = "n", long = "notes", default_value = "")]
        /// NOT SECURE: do not store any secrets here. The notes are
		/// displayed every time a site is accessed.
		///
		/// This is good for displaying username, etc
        notes: String,
    },

	#[structopt(name = "list")]
	/// List stored sites
	List {},

	#[structopt(name = "get")]
	/// Get a site's password
	Get {
        #[structopt(name = "name")]
        /// name for the site to get
        name: String,

        #[structopt(long = "stdout")]
        /// !!UNSECURE!! print password to stdout
        stdout: bool,
	},
}

fn main() {
    let opt = Opt::from_args();
    let path = PathBuf::from(opt.config);
	// FIXME: do not allow any running instances to exist except when
	// triggering.

	let result = match opt.cmd {
		Command::Init { level } => {
			cmds::init(&path, level)
		}
        Command::Set { name, overwrite, pin, rev, fmt, notes } => {
            cmds::set(&path, &name, overwrite, pin, rev, &fmt, &notes)
        }
        Command::List {} => {
            cmds::list(&path)
        }
        Command::Get { name, stdout } => {
            cmds::get(&path, &name, stdout)
        }
	};

	match result {
		Ok(_) => exit(0),
		Err(e) => {
			let msg = format!("Error\n{}", e);
			eprintln!("{}", ansi_term::Colour::Red.bold().paint(msg));
			exit(1);
		}
	}
}
