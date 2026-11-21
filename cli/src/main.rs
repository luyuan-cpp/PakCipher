use std::{error::Error, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use pakcipher_core::{
    load_private_key, load_public_key, pack_folder, pack_folder_volumes, unpack_packet, VolumeSize,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Encrypt and restore folders with OpenPGP RSA keys.")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a folder into a .pak or a directory of .pak volumes.
    Encrypt {
        folder: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Write volumes into a new output directory with this size range.
        #[arg(long, value_name = "MIN_MIB:MAX_MIB", conflicts_with_all = ["min_volume_size", "max_volume_size"])]
        volume_size: Option<VolumeSize>,
        /// Minimum volume size. Defaults to 1 MiB when only the maximum is set.
        #[arg(long, value_name = "MIB")]
        min_volume_size: Option<u64>,
        /// Maximum volume size. Defaults to twice the minimum when omitted in split mode.
        #[arg(long, value_name = "MIB")]
        max_volume_size: Option<u64>,
    },
    /// Restore an archive into a new folder.
    Decrypt {
        /// A .pak file, the first .pak volume, or a volume directory.
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
            volume_size,
            min_volume_size,
            max_volume_size,
        } => {
            let sizes = match volume_size {
                Some(sizes) => Some(sizes),
                None => VolumeSize::from_mib_bounds(min_volume_size, max_volume_size)?,
            };
            let key = load_public_key(&key_file)?;
            if let Some(sizes) = sizes {
                pack_folder_volumes(&folder, &key, &output, sizes, |_, _| {})?;
            } else {
                pack_folder(&folder, &key, &output, |_, _| {})?;
            }
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
