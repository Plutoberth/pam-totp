use std::{
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
};
use structopt::StructOpt;
use text_io::read;

use std::fs::File;
use totp_rs::{Algorithm, TOTP};

use totp_pam::{read_totp_for_current_user, get_path_for_current_user, write_totp, verify_totp};

use getrandom::getrandom;

const TOTP_SECRET_SIZE: usize = 20;
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;
const TOTP_ISSUER: &'static str = "TOTP-PAM";

//TODO: Create TOTP wrapper class with permission and owner checks.
//TODO: Make this less ugly.

///A helper program for the pam_totp.so PAM module
#[derive(StructOpt, Debug)]
enum TotpPamArgs {
    ///View the current TOTP config in the otpauth format
    View {},
    ///Save the TOTP config as a PNG of a QR code
    SaveQr {
        ///QR code destination
        path: String,
    },
    ///Generate a new OTP
    Generate {
        ///Don't prompt for overwrite
        #[structopt(long = "force", short = "f")]
        force: bool,

        ///Don't ask for a verification token after generating the TOTP. This is not recommended.
        #[structopt(long = "no-verify")]
        no_verify: bool,
    },
}

fn yesno(prompt: &str) -> bool {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let line: String = read!();
        if line == "y" {
            return true;
        } else if line == "n" {
            return false;
        }
    }
}

fn expand(path_str: &str) -> PathBuf {
    let mut pb = PathBuf::new();
    pb.push(String::from(shellexpand::tilde(path_str)));
    pb
}

fn get_totp_secret() -> Vec<u8> {
    let mut buf = vec![0u8; TOTP_SECRET_SIZE];
    getrandom(&mut buf).expect("Failed to obtain random data");
    buf
}

fn get_label() -> String {
    format!("{}@{}", whoami::username(), whoami::hostname())
}

fn view() {
    match read_totp_for_current_user() {
        Ok(totp) => {
            println!("{}", totp.get_url(&get_label(), TOTP_ISSUER));
        }
        Err(_) => {
            eprintln!("I didn't find a TOTP config for your user.");
        }
    }
}

fn save_qr(qr_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match read_totp_for_current_user() {
        Ok(totp) => {
            save_qr_from_totp(expand(qr_path), &totp)?;
        }
        Err(_) => {
            eprintln!("I didn't find a TOTP config for your user.");
        }
    }
    Ok(())
}

fn save_qr_from_totp<P: AsRef<Path>>(
    path: P,
    totp: &TOTP,
) -> Result<(), Box<dyn std::error::Error>> {
    let code = totp.get_qr(&get_label(), TOTP_ISSUER)?;
    let code_bytes = base64::decode(code)?;

    let mut file = File::create(path)?;
    file.write_all(&code_bytes)?;
    Ok(())
}

fn check_totp(totp: &TOTP) -> bool {
    print!("Enter a generated token from the TOTP: ");
    io::stdout().flush().unwrap();

    let user_token: String = read!();

    if verify_totp(totp, &user_token) {
        println!("Verification successful");
        true
    } else {
        println!("Verification failed");
        false
    }
}

//Generate a new TOTP.
fn generate(force: bool, no_verify: bool) -> Result<(), Box<dyn Error>> {
    let totp_path = get_path_for_current_user();
    if !force && totp_path.exists() {
        if !yesno("Would you like to overwrite the existing TOTP (y/n)? ") {
            return Ok(());
        }
    }

    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        get_totp_secret(),
    );

    let url = totp.get_url(&get_label(), TOTP_ISSUER);
    println!("TOTP URI:\n{}", url);

    if yesno("Would you like to save it as a QR code (y/n)? ") {
        let mut qr_saved = false;
        while !qr_saved {
            print!("Enter the target path: ");
            io::stdout().flush().unwrap();
            let target_path: String = read!();
            match save_qr_from_totp(&expand(&target_path), &totp) {
                Ok(_) => {
                    qr_saved = true;
                    println!("QR Code Saved successfully");
                }
                Err(e) => {
                    eprintln!("Failed to save QR Code: {}", e);
                }
            };
        }
    }

    if !no_verify {
        println!("It's required to verify the TOTP to proceed.");

        let mut totp_verified = false;
        while !totp_verified {
            totp_verified = check_totp(&totp);
        }
    }

    write_totp(&totp_path, &totp)?;

    println!("Updated TOTP config");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = TotpPamArgs::from_args();

    match cli {
        TotpPamArgs::View {} => view(),
        TotpPamArgs::SaveQr { path } => save_qr(&path)?,
        TotpPamArgs::Generate { force, no_verify } => generate(force, no_verify)?,
    }

    Ok(())
}
