//! REALITY AEAD encryption / decryption.

use alloc::vec::Vec;

#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
use aws_lc_rs::aead;
#[cfg(feature = "ring")]
use ring::aead;
#[cfg(all(not(feature = "aws_lc_rs"), not(feature = "ring")))]
compile_error!("Either 'ring' or 'aws_lc_rs' feature must be enabled for AEAD support");

use crate::Error;

use super::cipher::AeadKey;

impl AeadKey {
    /// Generate a new AEAD key using the given algorithm.
    ///
    /// # Panics
    ///
    /// - key_bytes.len() != algorithm.key_len() (for AES-256-GCM and CHACHA20_POLY1305, 32 bytes)
    fn generate_key(&self, aes_gcm_preferred: bool) -> aead::LessSafeKey {
        let alg = if aes_gcm_preferred {
            &aead::AES_256_GCM
        } else {
            &aead::CHACHA20_POLY1305
        };

        aead::LessSafeKey::new(aead::UnboundKey::new(alg, self.as_ref()).unwrap())
    }

    /// Encrypts the given plaintext using the AEAD key and nonce.
    ///
    /// # Panics
    ///
    /// - key_bytes.len() != algorithm.key_len() (for AES-256-GCM and CHACHA20_POLY1305, 32 bytes)
    /// - Nonce must be length of 12 bytes or panic.
    pub(crate) fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        aes_gcm_preferred: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = plaintext.to_vec();

        self.generate_key(aes_gcm_preferred)
            .seal_in_place_append_tag(
                aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
                aead::Aad::from(aad),
                &mut buf,
            )
            .map(|_| buf)
            .map_err(|_| Error::EncryptError)
    }

    #[allow(dead_code)]
    /// Decrypts the given ciphertext using the AEAD key and nonce.
    pub(crate) fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        aes_gcm_preferred: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = ciphertext.to_vec();

        let len = self
            .generate_key(aes_gcm_preferred)
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(nonce).unwrap(),
                aead::Aad::from(aad),
                &mut buf,
            )
            .map(|l| l.len())
            .map_err(|_| Error::DecryptError)?;

        buf.truncate(len);

        Ok(buf)
    }
}
