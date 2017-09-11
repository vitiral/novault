//! NoVault: ultra simple and secure password management

// handle signals:
// https://github.com/BurntSushi/chan-signal

extern crate ansi_term;
extern crate base64;
extern crate chan_signal;
extern crate dialoguer;
extern crate enigo;
#[macro_use]
extern crate error_chain;
extern crate file_lock;
extern crate openssl;
extern crate prelude;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate shellexpand;
extern crate strfmt;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate toml;

use structopt::StructOpt;
use file_lock::{AccessMode, Lock, LockKind};
use std::os::unix::io::AsRawFd;

mod types;
mod cmds;
mod utils;

use types::*;

// FIXME: need to add color and some other stuff
// FIXME: need to preserve order
// TODO: add shell completions
#[derive(Debug, StructOpt)]
#[structopt(name = "novault")]
/// ultra simple and secure vaultless password management
struct Opt {
    #[structopt(short = "c", long = "config", default_value = "~/.config/novault.toml")]
    /// Specify an alternate config file to use
    config: String,

    #[structopt(short = "l", long = "lock", default_value = "~/.local/novault.lock")]
    /// Specify an alternate lock file to use
    lock: String,

    #[structopt(long = "stdin")]
    /// Get password through stdin instead of a password prompt.
    stdin: bool,

    #[structopt(long = "stdout")]
    /// !! NOT SECURE !! print password directly to stdout
    stdout: bool,

    #[structopt(subcommand)] cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(name = "init")]
    /// Initialize the config file
    Init {
        #[structopt(long = "level", default_value = "20",
                    help = "\
The password is re-hashed 2 to the power of level (`2^level`) times.

Increasing this number will increase the security of your
passwords, but also take more time to get a password. The default
of 20, (about a million times) takes about 1 second to compute on
my 2 core 800MHz laptop.

It is recommended that this number NEVER be increased above about 50,
unless you are storing your passwords on a GPU super computer.

Do NOT change this paramter once initialized, as it will invalidate
all of your passwords.")]
        level: u32,
    },

    #[structopt(name = "set")]
    /// Create or change a site's settings
    Set {
        #[structopt(name = "name",
                    help = "\
Name for the site. Recommended: <username>@<site-url>")]
        name: String,

        #[structopt(short = "o", long = "overwrite",
                    help = "\
Overwrite even if the site name already exists. Useful when
you need to change something like the rev because your site
requires multiple versions of passwords.
")]
        overwrite: bool,

        #[structopt(long = "fmt", default_value = "{p:.20}",
                    help = "\
Format to use for the string. This can be used to reduce
the length of the string and also to add any special
characters that might be needed. Must have at least one
field with '{p}' in it. For example, to have a password that
is 10 characters plus '!@' (so 12 characters total) use:

    --fmt '{p:.10}!@'

Note: the first 4 characters of the generated password must
appear.")]
        fmt: String,

        #[structopt(long = "pin",
                    help = "\
Make the password suitable for pins by only outputting the digits 0-9. This
only replaces the password, you can still control the length, or add any
characters you like with --fmt")]
        pin: bool,

        #[structopt(short = "r", long = "rev", default_value = "0",
                    help = "
Revision number of password, useful for sites that require passwords to change")]
        rev: u64,

        #[structopt(short = "n", long = "notes", default_value = "",
                    help = "\
NOT SECURE: do not store any secrets here. The notes are
displayed every time a site is accessed.
This is good for displaying username, etc")]
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
    },
}

fn main() {
    let opt = Opt::from_args();
    let config = PathBuf::from(shellexpand::tilde(&opt.config).to_string());
    let lock_path = PathBuf::from(shellexpand::tilde(&opt.lock).to_string());

    let global = OptGlobal {
        config: config,
        stdin: opt.stdin,
        stdout: opt.stdout,
    };

    if !lock_path.exists() {
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .expect(&format!(
                "could not create lock file: {}",
                lock_path.display()
            ));
    }
    let lock_file = OpenOptions::new()
        .write(true)
        .open(&lock_path)
        .expect(&format!(
            "could not open lock file: {}",
            lock_path.display()
        ));

    let lock = Lock::new(lock_file.as_raw_fd());

    if let Err(_) = lock.lock(LockKind::NonBlocking, AccessMode::Write) {
        let msg = format!(
            "Could not obtain lock for {}.\nHelp: is there another NoVault running?",
            lock_path.display()
        );
        exit_with_err(&msg);
    }

    let result = match opt.cmd {
        Command::Init { level } => cmds::init(&global, level),
        Command::Set {
            name,
            overwrite,
            pin,
            rev,
            fmt,
            notes,
        } => cmds::set(&global, &name, overwrite, pin, rev, &fmt, &notes),
        Command::List {} => cmds::list(&global),
        Command::Get { name } => cmds::get(&global, &name),
    };

    match result {
        Ok(_) => exit(0),
        Err(e) => {
            exit_with_err(&e.to_string());
        }
    }

    drop(lock);
}

fn exit_with_err(msg: &str) {
    eprintln!("Error\n{}", ansi_term::Colour::Red.bold().paint(msg));
    exit(1);
}
