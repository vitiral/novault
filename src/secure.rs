//! secure: this file contains the most security related functions.
//!
//! ONLY this module should be able to access the actual master password.

use argon2rs;
use strfmt;
use base64;
use dialoguer;

// Traits
use byteorder::ByteOrder;
use rand::Rng;

use types::*;

/// "Master Password" type. Only this module can access the internals
pub struct MasterPass {
    audit_this: String,
}

impl MasterPass {
    fn new(s: &str) -> MasterPass {
        MasterPass {
            audit_this: s.to_string(),
        }
    }

    /// Create a fake master password
    pub fn fake() -> MasterPass {
        MasterPass::new("fake-password")
    }

    pub fn validate(&self) -> Result<()> {
        let len = self.audit_this.len();
        if len < 10 || len > 32 {
            bail!(ErrorKind::InvalidLength(len))
        } else {
            Ok(())
        }
    }
}


/// Hash the password
fn hash(settings: &Settings, master: &MasterPass, site: &Site) -> Result<String> {
    master.validate()?;
    let ar = argon2rs::Argon2::new(
        settings.level,             // passes
        settings.threads,           // "lanes" for parallelism
        settings.mem * 1024,        // memory usage in KiB
        argon2rs::Variant::Argon2d, // don't care about sidelane atacks
    )?;
    let mut hashed = vec![0u8; ENCRYPT_LEN];
    ar.hash(
        &mut hashed,                  // output
        settings.secret.0.as_ref(),   // p: plaintext secret file
        site.salt.repeat(8).as_ref(), // s: salt, 16 bytes is recommended
        master.audit_this.as_ref(),   // k: secret key (master password)
        &[],                          // x: associated data, not useful for this app
    );

    let out = if site.pin {
        let i: u64 = ::byteorder::LittleEndian::read_u64(&hashed);
        format!("{:0<19}", i)
    } else {
        base64::encode_config(&hashed, base64::URL_SAFE_NO_PAD)
    };
    Ok(out)
}

/// Format the hash
fn fmt(fmt_str: &str, hash_str: &str) -> Result<String> {
    let mut m = HashMap::new();
    m.insert("p".to_string(), hash_str);
    let out = strfmt::strfmt(fmt_str, &m)?;
    if out.len() < 4 || !out.contains(hash_str.split_at(4).0) {
        bail!(ErrorKind::InvalidFmt(fmt_str.to_string()));
    }
    Ok(out)
}

#[test]
fn test_fmt() {
    let f = |a, b| fmt(a, b).unwrap();
    assert_eq!(f("foo-{p}", "barabado"), "foo-barabado");
    assert_eq!(f("foo-{p:.4}", "barabado"), "foo-bara");
    assert!(fmt("{p:.3}", "barabado").is_err()); // too short
    assert!(fmt("long-prefix-{p:.2}", "barabado").is_err()); // pwd too short
}

pub fn get_master(stdin: bool) -> Result<MasterPass> {
    let prompt = "Enter your master password";
    let pass = if stdin {
        eprint!("Waiting for password through stdin...");
        let mut pass = String::with_capacity(128);
        ::std::io::stdin().read_line(&mut pass)?;
        eprintln!(" got password!");
        pass
    } else {
        dialoguer::PasswordInput::new(prompt)
            .interact()
            .chain_err(|| "OS Error: getting password failed")?
    };
    let pass = MasterPass::new(&pass);
    pass.validate()?;
    Ok(pass)
}

/// Do hash and fmt in one operation
fn fmt_hash(settings: &Settings, master: &MasterPass, site: &Site) -> Result<String> {
    fmt(&site.fmt, &hash(settings, master, site)?)
}

/// Just a wrapper to make this all type safe
pub fn site_pass(settings: &Settings, master: &MasterPass, site: &Site) -> Result<SitePass> {
    Ok(SitePass::new(&fmt_hash(settings, master, site)?))
}

/// Generate the 'check hash' from the settings.
///
/// This is how novault knows that you are using the same password
/// that you input the first time.
pub fn get_checkhash(settings: &Settings, master: &MasterPass) -> CheckHash {
    let site = Site {
        fmt: format!("{{p:.{}}}", CHECK_HASH_LEN),
        pin: false,
        notes: "".to_string(),
        salt: CHECK_HASH.to_string(),
    };
    CheckHash(fmt_hash(settings, master, &site).unwrap())
}

/// Generate a secret string to be stored on the file system
pub fn generate_secret() -> Secret {
    let mut gen = ::rand::OsRng::new().expect("Failed to create random number generator");
    Secret(gen.gen_ascii_chars().take(SECRET_LEN).collect())
}

// ##################################################
// # TESTS

#[test]
/// just testing that it's the right length
fn test_generate_secret() {
    let secret = generate_secret();
    assert_eq!(secret.0.len(), SECRET_LEN, "secret={:?}", secret)
}

#[test]
fn test_hash() {
    let master = MasterPass::new("master password");
    let name = "name";
    let settings = Settings {
        level: 1,
        mem: 10,
        threads: 1,
        checkhash: CheckHash::fake(),
        secret: Secret("very secret secret".to_string()),
    };
    let site = Site {
        fmt: String::new(),
        pin: false,
        notes: String::new(),
        salt: format!("{}{}", name, 0).repeat(4),
    };
    let expect = "wk1-JSqyKyV1ker9Qt_FpnlMuY2ElDmQJmtYRV7wggMILD3Cucn4edSlucX9sAm614gj3iB0zWY0_0lv\
                  dBJVTowHyFrJvZg9FY567I4ZsOjQ87ZBcTiLfYIrnLnh5ar4JHdFhCKDPc8zGN9NpCPYCi7r_p1HGZyM\
                  X32YBNesCNU";
    assert_eq!(expect, hash(&settings, &master, &site).unwrap());

    // make sure that small changes change the output
    {
        let master = MasterPass::new("other  password");
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let settings = Settings {
            secret: Secret("other very secret secret".to_string()),
            ..settings.clone()
        };
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let settings = Settings {
            level: 2,
            ..settings.clone()
        };
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let settings = Settings {
            mem: 9,
            ..settings.clone()
        };
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let settings = Settings {
            threads: 2,
            ..settings.clone()
        };
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let site = Site {
            salt: "someothersalt".to_string(),
            ..site.clone()
        };
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
    {
        let master = MasterPass::new(&"a".repeat(33));
        assert!(hash(&settings, &master, &site).is_err());
    }
}

#[test]
/// just a really basic test to make sure pin works at all
fn test_hash_pin() {
    let master = MasterPass::new("master password");
    let name = "name";
    let settings = Settings {
        level: 1,
        mem: 10,
        threads: 1,
        checkhash: CheckHash::fake(),
        secret: Secret("very secret secret".to_string()),
    };
    let site = Site {
        fmt: String::new(),
        pin: true,
        notes: String::new(),
        salt: format!("{}{}", name, 0).repeat(4),
    };
    let expect = "2678430297489296834";
    assert_eq!(expect, hash(&settings, &master, &site).unwrap());

    // make sure that small changes change the output
    {
        let master = MasterPass::new("other  password");
        assert_ne!(expect, hash(&settings, &master, &site).unwrap());
    }
}

#[test]
fn test_checkhash() {
    let settings = Settings {
        level: 1,
        mem: 10,
        threads: 1,
        checkhash: CheckHash::fake(),
        secret: Secret("very secret secret".to_string()),
    };

    let master = MasterPass::new("check  password");
    let expect = "nxRX0JgmcocSQa6i";
    assert_eq!(expect, get_checkhash(&settings, &master).0);

    {
        let master = MasterPass::new("other check for password");
        assert_ne!(expect, get_checkhash(&settings, &master).0);
    }
    {
        let settings = Settings {
            level: 2,
            ..settings.clone()
        };
        assert_ne!(expect, get_checkhash(&settings, &master).0);
    }
    {
        let settings = Settings {
            mem: 9,
            ..settings.clone()
        };
        assert_ne!(expect, get_checkhash(&settings, &master).0);
    }
    {
        let settings = Settings {
            threads: 2,
            ..settings.clone()
        };
        assert_ne!(expect, get_checkhash(&settings, &master).0);
    }
}
