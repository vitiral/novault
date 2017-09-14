use ansi_term::Colour::Green;
use enigo::{self, KeyboardControllable};

use types::*;
use secure;
use chan_signal::{self, Signal};

/// validate that settings.checkhash is correct
fn validate_master(
    settings: &Settings,
    master: &secure::MasterPass,
    secret: &Secret,
) -> Result<()> {
    let check = secure::check_hash(settings, master, secret);
    if check != settings.checkhash {
        bail!(ErrorKind::CheckFailed(
            check.0.clone(),
            settings.checkhash.0.clone()
        ));
    }
    Ok(())
}

/// Parse all possible errors for loading/creating the secret file
fn init_secret(global: &OptGlobal, use_secret: bool) -> Result<(Secret, bool)> {
    let mut dump_secret = false;
    let out = match (global.secret.exists(), use_secret) {
        (true, true) => {
            // secret exists and we should use it
            Secret::load(&global.secret)?
        }
        (false, false) => {
            // secret doesn't exist and we should create it
            dump_secret = true;
            secure::generate_secret()
        }
        (true, false) => {
            // secret exists but we shouln't use it
            bail!(ErrorKind::SecretFileExists(global.secret.clone()));
        }
        (false, true) => {
            // secret doesn't exist, but we are supposed to use it
            bail!(ErrorKind::SecretFileDoesNotExists(
                global.secret.to_path_buf()
            ));
        }
    };
    Ok((out, dump_secret))
}

/// Initialize the config file
pub fn init(
    global: &OptGlobal,
    level: u32,
    mem: u32,
    threads: u32,
    use_secret: bool,
) -> Result<()> {
    if global.config.exists() {
        bail!(ErrorKind::ConfigFileExists(global.config.to_path_buf()));
    }
    let (secret, dump_secret) = init_secret(global, use_secret)?;
    let master = secure::get_master(global.stdin)?;
    let mut settings = Settings {
        checkhash: CheckHash(String::new()),
        level: level,
        mem: mem,
        threads: threads,
    };
    settings.checkhash = secure::check_hash(&settings, &master, &secret);
    let config = Config {
        settings: settings,
        sites: BTreeMap::new(),
    };
    // create them both before dumping any
    let mut f = File::create(&global.config)
        .chain_err(|| format!("Could not create: {}", global.config.display()))?;
    if dump_secret {
        let mut f = File::create(&global.secret)
            .chain_err(|| format!("Could not create: {}", global.secret.display()))?;
        secret.dump(&mut f)?;
    }
    config.dump(&mut f)?;
    Ok(())
}

/// set a site's metadata
pub fn set(
    global: &OptGlobal,
    name: &str,
    overwrite: bool,
    pin: bool,
    rev: u64,
    fmt: &str,
    notes: &str,
) -> Result<()> {
    let mut config = Config::load(&global.config)?;
    if !overwrite && config.sites.contains_key(name) {
        bail!(ErrorKind::SiteExists(name.to_string()));
    }

    if name.is_empty() {
        bail!(ErrorKind::InvalidSiteName);
    }

    let site = Site {
        fmt: fmt.to_string(),
        pin: pin,
        salt: format!("{}{}", name, rev),
        notes: notes.to_string(),
    };

    // just make sure it doesn't fail fmt
    secure::site_pass(
        &config.settings,
        &secure::MasterPass::fake(),
        &Secret::fake(),
        &site,
    )?;

    config.sites.insert(name.to_string(), site);

    let mut f = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&global.config)
        .chain_err(|| {
            format!("Could not open {} for writing", global.config.display())
        })?;

    let out = config.dump(&mut f);
    if out.is_ok() {
        let dnotes = if notes.is_empty() {
            String::new()
        } else {
            format!("\nnotes={}", notes)
        };
        let green = Green.bold();
        eprintln!(
            "Set name={} with settings:\nfmt={} rev={} pin={}{}",
            green.paint(name),
            green.paint(fmt),
            green.paint(rev.to_string()),
            green.paint((pin as u8).to_string()),
            green.paint(dnotes)
        );
    }
    out
}

/// list the available sites
pub fn list(global: &OptGlobal) -> Result<()> {
    let config = Config::load(&global.config)?;
    let mut tw = ::tabwriter::TabWriter::new(Vec::new());
    write!(&mut tw, "{}", SITE_HEADER)?;
    for (name, site) in &config.sites {
        write!(&mut tw, "\n{}", site.line_str(name))?;
    }
    let tabbed = String::from_utf8(tw.into_inner().unwrap()).unwrap();
    eprintln!("{}", tabbed);
    Ok(())
}

/// get a password and write it using keyboard after -SIGUSR1
pub fn get(global: &OptGlobal, name: &str) -> Result<()> {
    let secret = Secret::load(&global.secret)?;
    let config = Config::load(&global.config)?;
    let settings = &config.settings;
    let site = match config.sites.get(name) {
        Some(s) => s,
        None => bail!(ErrorKind::NotFound(name.to_string())),
    };
    let master = secure::get_master(global.stdin)?;
    validate_master(settings, &master, &secret)?;

    let password = secure::site_pass(settings, &master, &secret, site)?;
    if global.stdout {
        println!("{}", password.audit_this);
        return Ok(());
    }

    eprintln!(
        "Keybind this command to enter password:\n\n    \
         killall -SIGUSR1 -u $USER novault"
    );

    chan_signal::notify(&[Signal::USR1])
        .recv()
        .expect("unwrap ok in single thread");

    sleep(Duration::from_millis(1000));
    let mut enigo = enigo::Enigo::new();
    for c in password.audit_this.chars() {
        if is_uppercase(c) {
            enigo.key_down(enigo::Key::Shift);
        }
        enigo.key_down(enigo::Key::Layout(c.to_string()));
        enigo.key_up(enigo::Key::Layout(c.to_string()));
        if is_uppercase(c) {
            enigo.key_up(enigo::Key::Shift);
        }
    }
    // enigo.key_sequence(&password.audit_this);
    Ok(())
}

// HELPERS

fn is_uppercase(c: char) -> bool {
    match c {
        'A'...'Z' => true,
        _ => false,
    }
}

#[test]
fn test_uppercase() {
    assert!(is_uppercase('A'));
    assert!(is_uppercase('Z'));
    assert!(!is_uppercase('a'));
    assert!(!is_uppercase('z'));
}
