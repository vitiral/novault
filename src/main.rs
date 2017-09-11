//! NoVault: ultra simple and secure password management

#![recursion_limit = "128"]

// handle signals:
// https://github.com/BurntSushi/chan-signal

extern crate ansi_term;
extern crate argon2rs;
extern crate base64;
extern crate chan_signal;
extern crate dialoguer;
extern crate enigo;
#[macro_use]
extern crate error_chain;
extern crate file_lock;
extern crate prelude;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate shellexpand;
extern crate strfmt;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tabwriter;
extern crate toml;

use structopt::StructOpt;
use file_lock::{AccessMode, Lock, LockKind};
use std::os::unix::io::AsRawFd;

mod types;
mod cmds;
mod secure;

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
        #[structopt(long = "level", default_value = "7",
                    help = "\
The level of security to use.

Increasing this number will increase the security of your passwords, but also take more time to get
a password.

Implementation details:
- For argon2 (default) this is the 'passes' and takes about a second to compute on my
  laptop.
")]
        level: u32,

        #[structopt(long = "mem", default_value = "7",
                    help = "\
Amount of memory to use in mebibytes (MiB).

Typically you should set this to about about 1/20 of your smallest computer's memory. So if your
laptop has 8GiB of memory, set it to `8 * 1024 / 20 ~= 400`.
")]
        mem: u32,

        #[structopt(long = "threads", default_value = "1",
                    help = "\
Number of threads to use.

This should be set to the MINIMUM number of physical CPUS on the computers you use. Typically \"2\"
is a fairly safe value for modern computers.
")]
        threads: u32,
    },

    #[structopt(name = "set")]
    /// Create or change a site's settings
    Set {
        #[structopt(name = "name",
                    help = "\
Name for the site. Recommended: username@site-url.com")]
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
Notes about the site -- !! NOT SECURE !!

Do not store any secrets here. The notes are stored in PLAIN TEXT and are  displayed every time a
site is accessed. I like to use this to remind me what a site is for")]
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
        Command::Init {
            level,
            mem,
            threads,
        } => cmds::init(&global, level, mem, threads),
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
