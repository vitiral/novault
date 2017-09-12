//! secure: this file contains the most security related functions.
//!
//! ONLY this module should be able to access the actual master password.

use argon2rs;
use strfmt;
use base64;
use byteorder::ByteOrder;
use dialoguer;

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
        MasterPass::new("fake-pass")
    }
}


/// Hash the password
fn hash(settings: &Settings, master: &MasterPass, site: &Site) -> Result<String> {
    let ar = argon2rs::Argon2::new(
        settings.level,             // passes
        settings.threads,           // "lanes" for parallelism
        settings.mem * 1024,        // memory usage in KiB
        argon2rs::Variant::Argon2d, // don't care about sidelane atacks
    )?;
    let mut hashed = vec![0u8; ENCRYPT_LEN];
    ar.hash(
        &mut hashed,
        master.audit_this.as_ref(),
        site.salt.as_ref(),
        &[], // (optional) secret value  (TODO: what is this?)
        &[], // (optional) data length   (TODO: what is this?)
    );

    let out = if site.pin {
        let i: u64 = ::byteorder::LittleEndian::read_u64(&hashed);
        format!("{:0<19}", i)
    } else {
        base64::encode_config(&hashed, base64::URL_SAFE_NO_PAD)
    };
    Ok(out)
}

#[test]
fn test_hash() {
    {
        let master = MasterPass::new("masterpassword");
        let name = "name";
        let settings = Settings {
            checkhash: CheckHash(String::new()),
            level: 1,
            mem: 10,
            threads: 1,
        };
        let site = Site {
            fmt: String::new(),
            pin: false,
            rev: 0,
            notes: String::new(),
            salt: format!("{}{}", name, 0).repeat(4),
        };
        let expect = "vkcuqRoFblOqF_vj82fQn7lMjyfvciuE5k-8cd_2gXAXxt9jG_C_xSRqyswc3dwn37g3qYQtqZc2\
                      mYssHMnJy9gEOXG8aZrGu16jlaia5flqrbTDmxgwj9rcBQY9IvJ1-KRCA4WVzkf-UTHVts4kO0WS\
                      6s6KPmJi0SUPYkFy3Cs";
        assert_eq!(expect, hash(&settings, &master, &site).unwrap());

        // make sure that small changes change the output
        {
            let master = MasterPass::new("otherpassword");
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
    }
}

#[test]
/// just a really basic test to make sure pin works at all
fn test_hash_pin() {
    {
        let master = MasterPass::new("masterpassword");
        let name = "name";
        let settings = Settings {
            checkhash: CheckHash(String::new()),
            level: 1,
            mem: 10,
            threads: 1,
        };
        let site = Site {
            fmt: String::new(),
            pin: true,
            rev: 0,
            notes: String::new(),
            salt: format!("{}{}", name, 0).repeat(4),
        };
        let expect = "6011748164651861950";
        assert_eq!(expect, hash(&settings, &master, &site).unwrap());

        // make sure that small changes change the output
        {
            let master = MasterPass::new("otherpassword");
            assert_ne!(expect, hash(&settings, &master, &site).unwrap());
        }
    }
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
    if pass.len() < 10 {
        bail!(ErrorKind::InvalidLength);
    };
    Ok(MasterPass::new(&pass))
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
pub fn check_hash(settings: &Settings, master: &MasterPass) -> CheckHash {
    let site = Site {
        // format to 20 characters because it's all we need for password
        // validation. This also gives the attacker LESS information.
        //
        // To get the true master password, and attacker will have to know
        // AT LEAST two passwords.
        fmt: "#- {p:.20} -#".to_string(),
        pin: false,
        rev: 0,
        notes: "".to_string(),
        salt: format!("{}{}", CHECK_HASH, 0).repeat(4),
    };
    CheckHash(fmt_hash(settings, master, &site).unwrap())
}

#[test]
fn test_check_hash() {
    let settings = Settings {
        checkhash: CheckHash(String::new()),
        level: 1,
        mem: 10,
        threads: 1,
    };

    let master = MasterPass::new("checkpassword");
    let expect = "#- IHhCf7r1yfYoics9iany -#";
    assert_eq!(expect, check_hash(&settings, &master).0);

    {
        let master = MasterPass::new("othercheck");
        assert_ne!(expect, check_hash(&settings, &master).0);
    }
    {
        let settings = Settings {
            level: 2,
            ..settings.clone()
        };
        assert_ne!(expect, check_hash(&settings, &master).0);
    }
    {
        let settings = Settings {
            mem: 9,
            ..settings.clone()
        };
        assert_ne!(expect, check_hash(&settings, &master).0);
    }
    {
        let settings = Settings {
            threads: 2,
            ..settings.clone()
        };
        assert_ne!(expect, check_hash(&settings, &master).0);
    }
}
