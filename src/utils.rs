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
            let c = ('0' as u8) + (d % 10);
            out.push(c as char);
        }
        out
    } else {
        base64::encode_config(hashed.as_ref(), base64::URL_SAFE_NO_PAD)
    }
}

/// Format the hash
fn fmt(fmt_str: &str, hash_str: &str) -> Result<String> {
    let mut m = HashMap::new();
    m.insert("p".to_string(), hash_str);
    let out = strfmt::strfmt(fmt_str, &m)?;
    if !out.contains(hash_str.split_at(4).0) {
        bail!(ErrorKind::InvalidFmt(fmt_str.to_string()));
    }
    Ok(out)
}

pub fn get_password() -> Result<String> {
	dialoguer::PasswordInput::new("Enter your master password")
		.interact()
        .chain_err(|| "getting password failed")
}


/// Do hash and fmt in one operation
pub fn fmt_hash(fmt_str: &str, level: u32, name: &str, password: &str, rev: u64, pin: bool)
        -> Result<String> {
    fmt(fmt_str, &hash(level, name, password, rev, pin))
}

pub fn check_hash(level: u32, password: &str) -> String {
	fmt_hash("{p:.32}", level, CHECK_HASH, password, 0, false).unwrap()
}
