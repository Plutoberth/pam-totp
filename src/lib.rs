use std::{error::Error, fs::File, io::Write, path::{Path, PathBuf}, time::SystemTime};

use totp_rs::TOTP;

const TOTP_PATH: &'static str = "~/.totp-pam";

pub fn get_path_for_current_user() -> PathBuf {
    let mut pb = PathBuf::new();
    pb.push(String::from(shellexpand::tilde(TOTP_PATH)));
    pb
}

pub fn read_totp_for_current_user() -> Result<TOTP, Box<dyn Error>> {
    read_totp(get_path_for_current_user())
}

pub fn read_totp<P: AsRef<Path>>(path: P) -> Result<TOTP, Box<dyn Error>> {
    let file_str = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&file_str)?)
}

pub fn write_totp_for_current_user(totp: &TOTP) -> Result<(), Box<dyn Error>> {
    write_totp(get_path_for_current_user(), totp)
}

pub fn write_totp<P: AsRef<Path>>(path: P, totp: &TOTP) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    file.write_all(serde_yaml::to_string(totp)?.as_bytes())?;

    Ok(())
}

pub fn verify_totp(totp: &TOTP, attempt: &str) -> bool {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token = totp.generate(time);
    token == attempt
}
