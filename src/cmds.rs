use ansi_term::Colour::Green;
use enigo::{self, KeyboardControllable};

use types::*;
use secure;
use chan_signal::{self, Signal};

/// ensure that a name is valid
fn validate_name(name: &str) -> Result<()> {
    if name == CHECK_HASH {
        bail!(ErrorKind::InvalidName(name.to_string()));
    } else {
        Ok(())
    }
}

/// validate that settings.checkhash is correct
fn validate_master(settings: &Settings, master: &secure::MasterPass) -> Result<()> {
    let check = secure::check_hash(settings, master);
    if check != settings.checkhash {
        bail!(ErrorKind::CheckFailed(
            check.0.clone(),
            settings.checkhash.0.clone()
        ));
    }
    Ok(())
}

/// Initialize the config file
pub fn init(global: &OptGlobal, level: u32, mem: u32, threads: u32) -> Result<()> {
    if global.config.exists() {
        bail!(ErrorKind::ConfigFileExists(global.config.to_path_buf()));
    }
    let master = secure::get_master(global.stdin)?;

    let mut settings = Settings {
        checkhash: CheckHash(String::new()),
        level: level,
        mem: mem,
        threads: threads,
    };

    settings.checkhash = secure::check_hash(&settings, &master);
    let config = Config {
        settings: settings,
        sites: BTreeMap::new(),
    };
    let mut f = File::create(&global.config)
        .chain_err(|| format!("Could not create: {}", global.config.display()))?;
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
    validate_name(name)?;
    let mut config = Config::load(&global.config)?;
    if !overwrite && config.sites.contains_key(name) {
        bail!(ErrorKind::SiteExists(name.to_string()));
    }

    // requres the salt to be > 8 characters, so just repeat 4 times
    if name.is_empty() {
        bail!(ErrorKind::InvalidSiteName);
    }
    let salt = format!("{}{}", name, rev).repeat(4);

    let site = Site {
        fmt: fmt.to_string(),
        pin: pin,
        rev: rev,
        salt: salt,
        notes: notes.to_string(),
    };

    // just make sure it doesn't fail fmt
    secure::site_pass(&config.settings, &secure::MasterPass::fake(), &site)?;

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
    // FIXME: use tabwriter
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
    validate_name(name)?;
    let config = Config::load(&global.config)?;
    let settings = &config.settings;
    let site = match config.sites.get(name) {
        Some(s) => s,
        None => bail!(ErrorKind::NotFound(name.to_string())),
    };
    let master = secure::get_master(global.stdin)?;
    validate_master(settings, &master)?;

    let password = secure::site_pass(settings, &master, site)?;
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

    let mut enigo = enigo::Enigo::new();
    enigo.key_sequence(&password.audit_this);
    Ok(())
}
