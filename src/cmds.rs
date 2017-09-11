use ansi_term::Colour::Green;
use enigo::{self, KeyboardControllable};

use types::*;
use utils;
use chan_signal::{self, Signal};

/// ensure that a name is valid
fn validate_name(name: &str) -> Result<()> {
    if name == CHECK_HASH {
        bail!(ErrorKind::InvalidName(name.to_string()));
    } else {
        Ok(())
    }
}

fn validate_master(config: &Config, master: &str) -> Result<()> {
    let settings = &config.settings;
    let check = utils::check_hash(settings.level, &master);
    if check != settings.checkhash {
        bail!(ErrorKind::CheckFailed);
    }
    Ok(())
}

/// Initialize the config file
pub fn init(global: &OptGlobal, level: u32) -> Result<()> {
    if global.config.exists() {
        bail!(ErrorKind::ConfigFileExists(global.config.to_path_buf()));
    }
    let master = utils::get_master(global.stdin)?;
    if master.len() < 10 {
        bail!(ErrorKind::InvalidLength);
    };
    let check = utils::check_hash(level, &master);
    let config = Config {
        settings: Settings {
            checkhash: check.to_string(),
            level: level,
        },
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

    // just make sure it doesn't fail fmt
    utils::fmt_hash(fmt, 0, name, "fake-master", rev, pin)?;

    let site = Site {
        fmt: fmt.to_string(),
        pin: pin,
        rev: rev,
        notes: notes.to_string(),
    };

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
        let dnotes = if notes.len() == 0 {
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
    let mut out = String::from(SITE_HEADER);
    for (name, site) in config.sites.iter() {
        write!(&mut out, "\n{}", site.line_str(name))?;
    }
    eprintln!("{}", out);
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
    let master = utils::get_master(global.stdin)?;
    validate_master(&config, &master)?;

    let password = utils::fmt_hash(&site.fmt, settings.level, name, &master, site.rev, site.pin)?;
    if global.stdout {
        println!("{}", password);
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
    enigo.key_sequence(&password);
    Ok(())
}
