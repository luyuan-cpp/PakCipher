use std::{error::Error, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use pakcipher_core::{load_private_key, load_public_key, pack_folder, unpack_packet};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Encrypt and restore folders with OpenPGP RSA keys.")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a folder into a new .pak file.
    Encrypt {
        folder: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Restore an archive into a new folder.
    Decrypt {
        archive: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Read a protected private key's passphrase from the terminal without echo.
        #[arg(long)]
        ask_passphrase: bool,
    },
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    match args.command {
        Command::Encrypt {
            folder,
            key_file,
            output,
        } => {
            pack_folder(&folder, &load_public_key(&key_file)?, &output, |_, _| {})?;
        }
        Command::Decrypt {
            archive,
            key_file,
            output,
            ask_passphrase,
        } => {
            let key = load_private_key(&key_file)?;
            let passphrase = if ask_passphrase {
                Zeroizing::new(rpassword::prompt_password("Private key passphrase: ")?)
            } else {
                Zeroizing::new(String::new())
            };
            unpack_packet(&archive, &key, &passphrase, &output, |_, _| {})?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run(Args::parse()) {
        eprintln!("PakCipher: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
