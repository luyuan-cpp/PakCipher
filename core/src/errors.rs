#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Directory scan failed: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("Invalid OpenPGP key: {0}")]
    Key(String),
    #[error("Session key could not be unlocked. Check the private key and its passphrase.")]
    Unlock,
    #[error("Archive authentication failed or the archive was modified.")]
    Authentication,
    #[error("Invalid or unsupported archive: {0}")]
    Format(&'static str),
    #[error("Unsupported path: {0}")]
    Path(String),
    #[error("Output must be outside the source folder.")]
    OutputInSource,
    #[error("The source file changed while being read: {0}")]
    Changed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
