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
pub fn init(path: &Path, level: u32) -> Result<()> {
	if path.exists() {
        bail!(ErrorKind::ConfigFileExists(path.to_path_buf()));
	}
    let master = utils::get_master()?;
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
	let mut f = File::create(path)
        .chain_err(|| format!("Could not create: {}", path.display()))?;
	config.dump(&mut f)?;
    Ok(())
}

/// set a site's metadata
pub fn set(path: &Path, name: &str, overwrite: bool, pin: bool, rev: u64, fmt: &str, notes: &str)
        -> Result<()> {
    validate_name(name)?;
    let mut config = Config::load(path)?;
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
        .open(path)
        .chain_err(|| format!("Could not open {} for writing", path.display()))?;

    config.dump(&mut f)
}

/// list the available sites
pub fn list(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    let mut out = String::new();
    out.write_str("NAME\tREV")?;
    for (name, site) in config.sites.iter() {
        write!(&mut out, "\n{}\t{}", name, site.rev)?;
    }
    // FIXME: use tabwriter here
    eprintln!("{}", out);
    Ok(())
}

/// list the available sites
pub fn get(path: &Path, name: &str, stdout: bool) -> Result<()> {
    validate_name(name)?;
    let config = Config::load(path)?;
    let settings = &config.settings;
    let site = match config.sites.get(name) {
        Some(s) => s,
        None => bail!(ErrorKind::NotFound(name.to_string())),
    };
    let master = utils::get_master()?;
    validate_master(&config, &master)?;

	let password = utils::fmt_hash(&site.fmt, settings.level, name, &master, site.rev, site.pin)?;
    if stdout {
        println!("{}", password);
        return Ok(());
    }
    eprintln!("Continue with: killall -SIGUSR1 -u $USER novault");
    chan_signal::notify(&[Signal::USR1])
        .recv()
        .expect("unwrap ok in single thread");

    let mut enigo = enigo::Enigo::new();
    enigo.key_sequence(&password);
    Ok(())
}
