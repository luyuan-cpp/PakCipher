use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::Hmac;
use pgp::{
    composed::{
        Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Signature, SignatureType},
    types::{KeyDetails, Password, PublicParams, Timestamp},
};
use rand::{rngs::OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    packet::{create_directory, create_file, output_path},
    Error, Result,
};

pub struct PublicKey(SignedPublicKey);
pub struct PrivateKey(SignedSecretKey);

pub(crate) type ArchiveMac = Hmac<Sha256>;
type Seed = Zeroizing<[u8; 32]>;

pub fn generate_key_pair(output: &Path, user_id: &str, passphrase: &str) -> Result<()> {
    let user_id = user_id.trim();
    if user_id.is_empty() || user_id.len() > 256 || user_id.chars().any(char::is_control) {
        return Err(Error::Key(
            "enter a key label of 1 to 256 UTF-8 bytes".into(),
        ));
    }
    if passphrase.trim().is_empty() {
        return Err(Error::Key("a private key passphrase is required".into()));
    }
    let output = output_path(output)?;
    create_directory(&output)?;
    let private_path = output.join("private.key");
    let public_path = output.join("public.key");
    let mut private_created = false;
    let mut public_created = false;

    let result = (|| {
        let subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Rsa(3072))
            .can_encrypt(EncryptionCaps::All)
            .passphrase(Some(passphrase.to_owned()))
            .build()
            .map_err(|error| Error::Key(error.to_string()))?;
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user_id.into())
            .passphrase(Some(passphrase.to_owned()))
            .subkeys(vec![subkey])
            .build()
            .map_err(|error| Error::Key(error.to_string()))?
            .generate(OsRng)
            .map_err(key_error)?;

        let mut private = create_file(&private_path)?;
        private_created = true;
        key.to_armored_writer(&mut private, Default::default())
            .map_err(key_error)?;
        let mut public = create_file(&public_path)?;
        public_created = true;
        key.to_public_key()
            .to_armored_writer(&mut public, Default::default())
            .map_err(key_error)?;
        Ok(())
    })();
    if result.is_err() {
        if private_created {
            let _ = fs::remove_file(private_path);
        }
        if public_created {
            let _ = fs::remove_file(public_path);
        }
        let _ = fs::remove_dir(&output);
    }
    result
}

pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    let bytes = read_key(path)?;
    let key = if bytes.starts_with(b"-----BEGIN PGP ") {
        SignedPublicKey::from_armor_single(bytes.as_slice()).map(|(key, _)| key)
    } else {
        SignedPublicKey::from_bytes(bytes.as_slice())
    }
    .map_err(key_error)?;
    key.verify_bindings().map_err(key_error)?;
    Ok(PublicKey(key))
}

pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let bytes = read_key(path)?;
    let key = if bytes.starts_with(b"-----BEGIN PGP ") {
        SignedSecretKey::from_armor_single(bytes.as_slice()).map(|(key, _)| key)
    } else {
        SignedSecretKey::from_bytes(bytes.as_slice())
    }
    .map_err(key_error)?;
    key.verify_bindings().map_err(key_error)?;
    Ok(PrivateKey(key))
}

fn read_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    const LIMIT: u64 = 1024 * 1024;
    // Allocate once so reading a secret key never reallocates its input buffer.
    let mut bytes = Zeroizing::new(vec![0; LIMIT as usize + 1]);
    let mut file = File::open(path)?;
    let mut length = 0;
    while length < bytes.len() {
        let read = file.read(&mut bytes[length..])?;
        if read == 0 {
            break;
        }
        length += read;
    }
    if length as u64 > LIMIT {
        return Err(Error::Key("key file exceeds 1 MiB".into()));
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn key_error(error: pgp::errors::Error) -> Error {
    Error::Key(error.to_string())
}

fn rsa_encryption_key(key: &impl KeyDetails) -> bool {
    matches!(
        key.algorithm(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt
    ) && matches!(key.public_params(), PublicParams::RSA(params) if params.key.n().bits() >= 2048)
}

fn allows_encryption(signature: &Signature) -> bool {
    let flags = signature.key_flags();
    flags.encrypt_comms() || flags.encrypt_storage()
}

fn key_is_current(key: &impl KeyDetails, signature: &Signature, now: u32) -> bool {
    let created = key.created_at().as_secs();
    created <= now
        && signature
            .key_expiration_time()
            .is_none_or(|duration| duration.as_secs() == 0 || now - created < duration.as_secs())
}

pub(crate) fn wrap_seed(key: &PublicKey) -> Result<(Seed, Vec<u8>)> {
    if !key.0.details.revocation_signatures.is_empty() {
        return Err(Error::Key("the recipient certificate is revoked".into()));
    }
    let mut rng = OsRng;
    let mut seed = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut seed[..])
        .map_err(|error| Error::Io(std::io::Error::other(error.to_string())))?;
    let mut builder = MessageBuilder::from_reader("", seed.as_slice())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    let now = Timestamp::now().as_secs();
    let primary_signature = key
        .0
        .details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .chain(&key.0.details.direct_signatures)
        .max_by_key(|sig| sig.created().map(Timestamp::as_secs))
        .ok_or_else(|| Error::Key("missing recipient self-signature".into()))?;
    if !key_is_current(&key.0.primary_key, primary_signature, now) {
        return Err(Error::Key(
            "the recipient certificate is expired or not yet valid".into(),
        ));
    }
    let subkey = key.0.public_subkeys.iter().find(|key| {
        rsa_encryption_key(*key)
            && !key
                .signatures
                .iter()
                .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation))
            && key
                .signatures
                .iter()
                .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
                .max_by_key(|sig| sig.created().map(Timestamp::as_secs))
                .is_some_and(|sig| allows_encryption(sig) && key_is_current(*key, sig, now))
    });
    if let Some(subkey) = subkey {
        builder
            .encrypt_to_key(&mut rng, subkey)
            .map_err(key_error)?;
    } else if rsa_encryption_key(&key.0.primary_key) && allows_encryption(primary_signature) {
        builder
            .encrypt_to_key(&mut rng, &key.0.primary_key)
            .map_err(key_error)?;
    } else {
        return Err(Error::Key(
            "an RSA encryption key of at least 2048 bits is required".into(),
        ));
    }
    let wrapped = builder.to_vec(&mut rng).map_err(key_error)?;
    Ok((seed, wrapped))
}

pub(crate) fn unwrap_seed(key: &PrivateKey, password: &str, wrapped: &[u8]) -> Result<Seed> {
    let password = Password::from(password);
    let mut message = Message::from_bytes(wrapped)
        .and_then(|message| message.decrypt(&password, &key.0))
        .map_err(|_| Error::Unlock)?;
    if !matches!(message, Message::Literal { .. }) {
        return Err(Error::Unlock);
    }
    let mut seed = Zeroizing::new([0; 32]);
    message
        .read_exact(&mut seed[..])
        .map_err(|_| Error::Unlock)?;
    if message
        .read(&mut Zeroizing::new([0; 1])[..])
        .map_err(|_| Error::Unlock)?
        != 0
    {
        return Err(Error::Unlock);
    }
    Ok(seed)
}

pub(crate) fn derive_keys(seed: &Seed) -> (Aes256Gcm, ArchiveMac) {
    use aes_gcm::KeyInit;
    use hmac::Mac;

    let derive = Hkdf::<Sha256>::new(Some(b"PakCipher v1"), &seed[..]);
    let mut key = Zeroizing::new([0; 32]);
    derive
        .expand(b"content AES-256-GCM", &mut key[..])
        .expect("fixed key size");
    let cipher = Aes256Gcm::new_from_slice(&key[..]).expect("fixed key size");
    derive
        .expand(b"archive HMAC-SHA256", &mut key[..])
        .expect("fixed key size");
    let mac = <ArchiveMac as Mac>::new_from_slice(&key[..]).expect("fixed key size");
    (cipher, mac)
}
