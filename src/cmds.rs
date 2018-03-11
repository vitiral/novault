/* Copyright (c) 2018 Garrett Berg, vitiral@gmail.com
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */
//! Functions which implement the command line commands.
use ansi_term::Colour::{Green, Red};
use enigo::{self, KeyboardControllable};
use dialoguer;
use rustyline;
use shlex;
use super::LoopOpt;
use structopt::StructOpt;

use types::*;
use secure;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// validate that settings.checkhash is correct
fn validate_master(settings: &Settings, master: &secure::MasterPass) -> Result<()> {
    let calc_check = secure::get_checkhash(settings, master);
    if calc_check != settings.checkhash {
        bail!(ErrorKind::CheckFailed(
            calc_check.0.clone(),
            settings.checkhash.0.clone()
        ));
    }
    Ok(())
}

/// Initialize the sites file
pub fn init(global: &mut OptGlobal, level: u32, mem: u32, threads: u32) -> Result<()> {
    if global.secret.exists() {
        bail!(ErrorKind::SecretFileExists(global.secret.to_path_buf()));
    }
    let secret = secure::generate_secret();
    let master = secure::get_master(global)?;
    let mut settings = Settings {
        level,
        mem,
        threads,
        checkhash: CheckHash(String::new()),
        secret,
    };
    settings.checkhash = secure::get_checkhash(&settings, &master);
    // create them both before dumping any
    let mut settings_file = File::create(&global.secret)
        .chain_err(|| format!("Could not create: {}", global.secret.display()))?;
    dump(&settings, &mut settings_file)?;
    Ok(())
}

/// set a site's metadata
pub fn set(
    global: &mut OptGlobal,
    name: &str,
    overwrite: bool,
    pin: bool,
    rev: u64,
    fmt: &str,
    notes: &str,
) -> Result<()> {
    touch(&global.sites)?;
    let mut sites: Sites = load(&global.sites)?;
    if !overwrite && sites.contains_key(name) {
        bail!(ErrorKind::SiteExists(name.to_string()));
    }

    if name.is_empty() {
        bail!(ErrorKind::InvalidSiteName);
    }

    let site = Site {
        fmt: fmt.to_string(),
        pin,
        salt: format!("{}{}", name, rev),
        notes: notes.to_string(),
    };

    // just make sure it doesn't fail fmt
    secure::site_pass(&Settings::fake(), &secure::MasterPass::fake(), &site)?;

    sites.insert(name.to_string(), site);

    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&global.sites)
        .chain_err(|| format!("Could not open {} for writing", global.sites.display()))?;

    let out = dump(&sites, &mut f);
    if out.is_ok() {
        let green = Green.bold();
        eprintln!(
            "Set name={} with settings:\nfmt={} rev={} pin={}",
            green.paint(name),
            green.paint(fmt),
            green.paint(rev.to_string()),
            green.paint((pin as u8).to_string()),
        );
        if !notes.is_empty() {
            eprintln!("notes={}", green.paint(notes));
        }
    }
    out
}

/// list the available sites
pub fn list(global: &OptGlobal) -> Result<()> {
    let sites: Sites = load(&global.sites)?;
    let mut tw = ::tabwriter::TabWriter::new(Vec::new());
    write!(&mut tw, "{}", SITE_HEADER)?;
    for (name, site) in &sites {
        write!(&mut tw, "\n{}", site.line_str(name))?;
    }
    let tabbed = String::from_utf8(tw.into_inner().unwrap()).unwrap();
    eprintln!("{}", tabbed);
    Ok(())
}

/// get a password and write it using keyboard after -SIGUSR1
pub fn get(global: &mut OptGlobal, name: &str) -> Result<()> {
    let settings: Settings = load(&global.secret)?;
    let sites: Sites = load(&global.sites)?;
    let site = match sites.get(name) {
        Some(s) => s,
        None => bail!(ErrorKind::NotFound(name.to_string())),
    };
    let master = secure::get_master(global)?;
    validate_master(&settings, &master)?;

    let password = secure::site_pass(&settings, &master, site)?;
    eprintln!("Getting password for {}", Green.bold().paint(name));
    if !site.notes.is_empty() {
        eprintln!("Notes: {}", Green.paint(site.notes.clone()));
    }
    if global.stdout {
        println!("{}", password.audit_this);
        return Ok(());
    }

    eprintln!(
        "Password ready. Keybind this command to use the password:\n\n    \
         echo \"ok\" >> {:?}\n\n\
         Make SURE you release any keys after running!",
        global.lock_path
    );

    while global.lock_file.metadata()?.len() == 0 {
        sleep(Duration::from_millis(100));
    }

    eprintln!("Typing password via keyboard in exactly 1 second...");
    sleep(Duration::from_millis(1000));

    let mut enigo = enigo::Enigo::new();
    enigo.key_sequence(&password.audit_this);
    eprintln!(
        "Password for {} has been typed via keyboard.",
        Green.bold().paint(name)
    );
    Ok(())
}

/// Do insecure operations
pub fn insecure(global: &mut OptGlobal, export: bool) -> Result<()> {
    if !export {
        bail!(ErrorKind::InvalidCmd(
            "Only --export is currently supported".to_string()
        ));
    }
    let settings: Settings = load(&global.secret)?;
    let sites: Sites = load(&global.sites)?;

    eprintln!("{}", Red.bold().paint(INSECURE_MSG));
    let master = secure::get_master(global)?;
    validate_master(&settings, &master)?;

    let mut passwords: BTreeMap<String, String> = BTreeMap::new();
    for (name, site) in &sites {
        let p = secure::site_pass(&settings, &master, site)?;
        passwords.insert(name.clone(), p.audit_this);
    }

    print!("{}", ::toml::to_string(&passwords).expect("toml failed"));
    Ok(())
}

pub fn loop_(global: &mut OptGlobal) -> Result<()> {
    eprintln!("Starting NoVault loop.");
    // cache the master password
    let settings: Settings = load(&global.secret)
        .chain_err(|| "Not initialized. Use `novault init` to initialize passwords.")?;

    {
        let master = secure::get_master(global)?; // note: stores in cache
        validate_master(&settings, &master)?;
    }

    let prompt = "Enter the session password. This can be less secure than the master password:";
    global.session = match dialoguer::PasswordInput::new(prompt).interact() {
        Ok(s) => Some(s),
        Err(_) => {
            eprintln!("OS Error: getting password failed");
            exit(1);
        }
    };

    let mut rl = rustyline::Editor::<()>::new();
    loop {
        eprintln!("\nType \"help\" for help and \"exit\" to exit.");
        let readline = match rl.readline(">> ") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Got {}", e);
                exit(0);
            }
        };
        let line = readline.trim();
        if line.to_ascii_uppercase() == "EXIT" {
            exit(0);
        }
        let mut args = match shlex::split(&readline) {
            Some(a) => a,
            None => {
                eprintln!("Invalid shell syntax");
                continue;
            }
        };
        args.insert(0, "novault".into());

        let matches = match super::LoopOpt::clap().get_matches_from_safe(args) {
            Ok(m) => m,
            Err(err) => {
                eprintln!("{}", err);
                continue;
            }
        };

        if let Err(err) = super::run_cmd_single(global, &LoopOpt::from_clap(matches).cmd) {
            eprintln!("{}", err);
        }
    }
}

// HELPERS

/// Deserialize the path as a toml file
pub fn load<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut f = File::open(path).chain_err(|| format!("Could not open: {}", path.display()))?;
    let mut out = String::new();
    f.read_to_string(&mut out)
        .chain_err(|| format!("Failed to read: {}", path.display()))?;
    ::toml::from_str(&out).chain_err(|| format!("File format is invalid: {}", path.display()))
}

/// Serialize the
pub fn dump<T: Serialize>(value: &T, file: &mut File) -> Result<()> {
    file.write_all(::toml::to_string(value).unwrap().as_ref())?;
    Ok(())
}

/// Ensure the file exists
fn touch(path: &Path) -> Result<()> {
    match OpenOptions::new().create(true).write(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) => bail!(e),
    }
}
