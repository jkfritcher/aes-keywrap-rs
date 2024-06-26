// Copyright (c) 2020,2021, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

use crate::types::{Aes128Ecb, Aes192Ecb, Aes256Ecb, AES_BLOCK_LEN, BLOCK_LEN};
use block_modes::BlockMode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UnwrapKeyError {
    #[error("Key length must be 16, 24 or 32 octets")]
    KeyLengthInvalid,

    #[error("Ciphertext length must be a multiple of {0} octets")]
    CipherTextInvalidLength(usize),

    #[error("Ciphertext length can not be longer than {0} octets")]
    CipherTextLengthTooLong(u32),

    #[error("Ciphertext length must be atleast {0} octet(s)")]
    CipherTextLengthTooShort(usize),

    #[error("Failed to successfully unwrap key")]
    CipherTextValidationFailure,
}

pub fn aes_unwrap_with_nopadding(ct: &[u8], key: &[u8]) -> Result<Vec<u8>, UnwrapKeyError> {
    let ct_len = ct.len();
    if ct_len % BLOCK_LEN != 0 {
        return Err(UnwrapKeyError::CipherTextInvalidLength(BLOCK_LEN));
    }

    let n = (ct_len / BLOCK_LEN) - 1;
    if n < 2 {
        return Err(UnwrapKeyError::CipherTextLengthTooShort(24));
    }

    // Copy ct into a new vec for unwrapping in place
    let mut pt = ct.to_vec();

    // Get the AES function for the key length
    let aes_func = get_aes_func(key.len())?;

    // Unwrap the key into pt
    unwrap_core(key, n, pt.as_mut_slice(), aes_func);

    // Validate the IV
    const A: [u8; BLOCK_LEN] = [0xa6; BLOCK_LEN];
    if !constant_time_eq(&pt[0..BLOCK_LEN], &A) {
        return Err(UnwrapKeyError::CipherTextValidationFailure);
    }

    Ok(pt[BLOCK_LEN..].to_vec())
}

pub fn aes_unwrap_with_padding(ct: &[u8], key: &[u8]) -> Result<Vec<u8>, UnwrapKeyError> {
    let ct_len = ct.len();
    if ct_len % BLOCK_LEN != 0 {
        return Err(UnwrapKeyError::CipherTextInvalidLength(BLOCK_LEN));
    }

    let n = (ct_len / BLOCK_LEN) - 1;
    if n < 1 {
        return Err(UnwrapKeyError::CipherTextLengthTooShort(16));
    }

    // Copy ct into a new vec for unwrapping in place
    let mut pt = ct.to_vec();

    // Get the AES function for the key length
    let aes_func = get_aes_func(key.len())?;

    // Unwrap the key into pt
    unwrap_core(key, n, pt.as_mut_slice(), aes_func);

    // Validate the IV and MLI
    const A: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];
    if !constant_time_eq(&pt[0..4], &A) {
        // Static part of the IV is invalid
        return Err(UnwrapKeyError::CipherTextValidationFailure);
    }
    let mli = {
        let mut mli_bytes: [u8; 4] = Default::default();
        mli_bytes[..].copy_from_slice(&pt[4..8]);
        u32::from_be_bytes(mli_bytes) as usize
    };
    if !(mli > (8 * (n - 1)) && mli <= (8 * n)) {
        // MLI is an invalid value
        return Err(UnwrapKeyError::CipherTextValidationFailure);
    }
    let pad_len = ct_len - mli - BLOCK_LEN;
    let padding = &pt[(ct_len - pad_len)..];
    for pad_byte in padding {
        if *pad_byte != 0 {
            // Padding must be all zeros
            return Err(UnwrapKeyError::CipherTextValidationFailure);
        }
    }

    Ok(pt[BLOCK_LEN..(BLOCK_LEN + mli)].to_vec())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Not constant time if the lengths differ
    if a.len() != b.len() {
        return false;
    }
    let c = a.iter().zip(b.iter()).fold(0, |acc, (a, b)| acc | (a ^ b));
    c == 0
}

fn get_aes_func(key_len: usize) -> Result<fn(&[u8], &mut [u8]), UnwrapKeyError> {
    match key_len {
        16 => Ok(aes128_ecb_decrypt),
        24 => Ok(aes192_ecb_decrypt),
        32 => Ok(aes256_ecb_decrypt),
        _ => Err(UnwrapKeyError::KeyLengthInvalid),
    }
}

fn aes128_ecb_decrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes128Ecb::new_from_slices(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.decrypt(data).expect("Failed to decrypt data block");
}

fn aes192_ecb_decrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes192Ecb::new_from_slices(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.decrypt(data).expect("Failed to decrypt data block");
}

fn aes256_ecb_decrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes256Ecb::new_from_slices(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.decrypt(data).expect("Failed to decrypt data block");
}

fn unwrap_core<AesEcb>(key: &[u8], n: usize, pt: &mut [u8], aes_ecb_decrypt: AesEcb)
where
    AesEcb: Fn(&[u8], &mut [u8]),
{
    if pt.len() > AES_BLOCK_LEN {
        // Allocate buffer for operations in loop
        // tmp = A | R[i]
        let mut tmp: Vec<u8> = vec![0u8; AES_BLOCK_LEN];

        // Copy A into buffer
        tmp[0..BLOCK_LEN].copy_from_slice(&pt[0..BLOCK_LEN]);

        for j in (0..6).rev() {
            for i in (1..=n).rev() {
                let idx = i * BLOCK_LEN;
                tmp[BLOCK_LEN..].copy_from_slice(&pt[idx..idx + BLOCK_LEN]);

                // A = MSB(64, B) ^ t where t = (n*j)+i
                let t = ((n * j) + i) as u64;
                tmp[0..BLOCK_LEN]
                    .iter_mut()
                    .zip(t.to_be_bytes().iter())
                    .for_each(|(x1, x2)| *x1 ^= *x2);

                // B = AES(K, A | R[i])
                aes_ecb_decrypt(key, &mut tmp);

                // R[i] = LSB(64, B)
                pt[idx..idx + BLOCK_LEN].copy_from_slice(&tmp[BLOCK_LEN..]);
            }
        }

        // Put A into output
        pt[0..BLOCK_LEN].copy_from_slice(&tmp[0..BLOCK_LEN]);
    } else {
        aes_ecb_decrypt(key, pt);
    }
}

#[cfg(test)]
mod tests {
    use super::{aes_unwrap_with_nopadding, aes_unwrap_with_padding};

    #[test]
    fn test_unwrap_nopad_invalid_key_length() {
        let ct = hex!("000102030405060708090a0b0c0d0e0f").to_vec();
        let key = hex!("000102030405060708090a0b0c0d0e").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_err(), "Invalid key length erroneously passed");
    }

    #[test]
    fn test_wrap_pad_invalid_key_length() {
        let pt = hex!("000102030405060708090a0b0c0d0e0f").to_vec();
        let key = hex!("000102030405060708090a0b0c0d0e").to_vec();
        let ct = aes_unwrap_with_padding(&pt, &key);
        assert!(ct.is_err(), "Invalid key length erroneously passed");
    }

    //
    // RFC3394 Test Vectors
    //
    #[test]
    fn test_unwrap_nopad_16_byte_key_16_byte_data() {
        let ct = hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(pt.unwrap(), hex!("00112233445566778899AABBCCDDEEFF").to_vec());
    }

    #[test]
    fn test_unwrap_nopad_24_byte_key_16_byte_data() {
        let ct = hex!("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(pt.unwrap(), hex!("00112233445566778899AABBCCDDEEFF").to_vec());
    }

    #[test]
    fn test_unwrap_nopad_32_byte_key_16_byte_data() {
        let ct = hex!("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(pt.unwrap(), hex!("00112233445566778899AABBCCDDEEFF").to_vec());
    }

    #[test]
    fn test_unwrap_nopad_24_byte_key_24_byte_data() {
        let ct = hex!("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(
            pt.unwrap(),
            hex!("00112233445566778899AABBCCDDEEFF0001020304050607").to_vec()
        );
    }

    #[test]
    fn test_unwrap_nopad_32_byte_key_24_byte_data() {
        let ct = hex!("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(
            pt.unwrap(),
            hex!("00112233445566778899AABBCCDDEEFF0001020304050607").to_vec()
        );
    }

    #[test]
    fn test_unwrap_nopad_32_byte_key_32_byte_data() {
        let ct = hex!("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let pt = aes_unwrap_with_nopadding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(
            pt.unwrap(),
            hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F").to_vec()
        );
    }

    //
    // RFC5649 Test Vectors
    //
    #[test]
    fn test_unwrap_pad_24_byte_key_20_byte_data() {
        let ct = hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a").to_vec();
        let key = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").to_vec();
        let pt = aes_unwrap_with_padding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(
            pt.unwrap(),
            hex!("c37b7e6492584340bed12207808941155068f738").to_vec()
        );
    }

    #[test]
    fn test_unwrap_pad_24_byte_key_7_byte_data() {
        let ct = hex!("afbeb0f07dfbf5419200f2ccb50bb24f").to_vec();
        let key = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").to_vec();
        let pt = aes_unwrap_with_padding(&ct, &key);
        assert!(pt.is_ok(), "Test unexpectantly failed: {:?}", pt);
        assert_eq!(pt.unwrap(), hex!("466f7250617369").to_vec());
    }
}
