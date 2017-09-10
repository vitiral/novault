use strfmt;
use openssl;
use base64;
use dialoguer;

use types::*;

/// Hash the name and password with other settings
fn hash(level: u32, name: &str, password: &str, rev: u64, pin: bool) -> String {
	let base = format!("{}{}{}", rev, name, password);
    let mut hashed = openssl::sha::sha512(base.as_ref());
    for _ in 0..(2u64.pow(level)) {
        hashed = openssl::sha::sha512(hashed.as_ref());
    }
    if pin {
        let mut out = String::new();
        for d in hashed.as_ref().iter() {
            let c = ('0' as u8) + (d % 10u8);
            out.push(c as char);
        }
        out
    } else {
        base64::encode_config(hashed.as_ref(), base64::URL_SAFE_NO_PAD)
    }
}

#[test]
fn test_hash() {
    {
        let expect = "wGMMdn-sfvN-XhDhDMB7vM9nMUtV2uHjQ_YUaJSnggpoqWaaX3X1tKPSDUPvdQnbpZA1xV3lu7mN\
                      5UEINyU-SA";
        assert_eq!(expect, hash(5, "name", "password", 0, false));

        assert_ne!(expect, hash(4, "name", "password", 0, false));
        assert_ne!(expect, hash(0, "name", "password", 0, false));
        assert_ne!(expect, hash(5, "nam",  "password", 0, false));
        assert_ne!(expect, hash(5, "name", "assword",  0, false));
        assert_ne!(expect, hash(5, "name", "password", 1, false));
        assert_ne!(expect, hash(5, "name", "password", 0, true ));
    }
    {
        let expect = "5000323459560071975709151365474757802006475730741845631756435134";
        assert_eq!(expect, hash(10, "name", "password", 0, true));
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
    assert!(fmt("{p:.3}", "barabado").is_err());             // too short
    assert!(fmt("long-prefix-{p:.2}", "barabado").is_err()); // pwd too short
}

pub fn get_master() -> Result<String> {
	dialoguer::PasswordInput::new("Enter your master password")
		.interact()
        .chain_err(|| "OS Error: getting password failed")
}


/// Do hash and fmt in one operation
pub fn fmt_hash(fmt_str: &str, level: u32, name: &str, password: &str, rev: u64, pin: bool)
        -> Result<String> {
    fmt(fmt_str, &hash(level, name, password, rev, pin))
}

#[test]
fn test_fmt_hash() {

}

pub fn check_hash(level: u32, password: &str) -> String {
	fmt_hash("{p:.16}", level, CHECK_HASH, password, 0, false).unwrap()
}

#[test]
fn test_check_hash() {
    let expect = "pSR0_-BokRYQ7NfemWE9Zu9lvIXxbff3";
    assert_eq!(expect, check_hash(2, "mypass"));

    assert_ne!(expect, check_hash(1, "mypass"));
    assert_ne!(expect, check_hash(0, "mypass"));
    assert_ne!(expect, check_hash(2, "ypass"));
    assert_ne!(expect, check_hash(2, "bypass"));
}
