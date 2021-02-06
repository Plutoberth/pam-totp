use std::{error::Error, fs::File, io::Write, path::Path, time::SystemTime};
use totp_rs::TOTP;

pub fn read_totp<P: AsRef<Path>>(path: P) -> Result<TOTP, Box<dyn Error>> {
    let file_str = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&file_str)?)
}

pub fn save_totp<P: AsRef<Path>>(path: P, totp: &TOTP) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    file.write_all(serde_yaml::to_string(&totp)?.as_bytes())?;

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
