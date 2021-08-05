// Copyright (c) 2020, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

use crate::{
    error::KeyWrapError,
    types::{Aes128Ecb, Aes192Ecb, Aes256Ecb, AES_BLOCK_LEN, BLOCK_LEN},
};
use block_modes::BlockMode;

pub fn aes_wrap_with_nopadding(pt: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyWrapError> {
    #[allow(non_snake_case)]
    let A: [u8; BLOCK_LEN] = [0xa6; BLOCK_LEN];
    let mut ct: Vec<u8> = Vec::new();
    let pt_len = match pt.len() {
        pt_len if (pt_len % BLOCK_LEN) > 0 => {
            return Err("Plaintext length must be a multiple of 8 octets in length".into())
        },
        pt_len => pt_len,  // pt should be a multiple of BLOCK_LEN
    };

    let n = match pt_len / BLOCK_LEN {
        0 | 1 => { return Err("Plaintext length must be atleast 16 octets".into()) },
        n  => n,  // pt must be at least 2 blocks in size
    };

    // Check for valid key lengths and get func pointer
    let aes_func = match key.len() {
        16 => aes128_ecb_encrypt,
        24 => aes192_ecb_encrypt,
        32 => aes256_ecb_encrypt,
        _ => return Err("Key must be 16, 24 or 32 octets in length".into()),
    };

    // Allocate ct to the proper size
    ct.resize(A.len() + pt_len, 0);

    // Because we're encrypting in place, copy A and pt into ct
    ct[..BLOCK_LEN].copy_from_slice(&A);
    ct[BLOCK_LEN..].copy_from_slice(pt);

    // Wrap the key into ct
    wrap_core(key, n, ct.as_mut_slice(), aes_func);

    Ok(ct)
}

pub fn aes_wrap_with_padding(pt: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyWrapError> {
    #[allow(non_snake_case)]
    let mut A: [u8; BLOCK_LEN] = [0xa6, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
    let mut ct: Vec<u8> = Vec::new();
    let pt_len = match pt.len() {
        0 => { return Err("Plaintext length must be atleast 1 octet".into()) },
        pt_len if pt_len > u32::MAX as usize => {
            // The MLI restricts pt.len() to a u32
            return Err(format!("Plaintext length can not be larger than {}", u32::MAX).into());
        },
        pt_len => pt_len,  // Need atleast one octet of plaintext.
    };

    // Check for valid key lengths and get func pointer
    let aes_func = match key.len() {
        16 => aes128_ecb_encrypt,
        24 => aes192_ecb_encrypt,
        32 => aes256_ecb_encrypt,
        _ => return Err("Key must be 16, 24 or 32 octets in length".into()),
    };

    // Set MLI in A
    let pt_len_u32 = pt_len as u32;
    A[4..].copy_from_slice(&pt_len_u32.to_be_bytes());

    // Calculate padded length
    let padded_len = pt_len
        + match pt_len % BLOCK_LEN {
            0 => 0,
            n => BLOCK_LEN - n,
        };
    let n = padded_len / BLOCK_LEN;

    // Allocate ct to the required size
    ct.resize(A.len() + padded_len, 0);

    // Because we're encrypting in place, copy A and pt into ct
    // Padding happens automatically if pt isn't a block length
    ct[..BLOCK_LEN].copy_from_slice(&A);
    ct[BLOCK_LEN..BLOCK_LEN + pt_len].copy_from_slice(pt);

    // Wrap the key into ct
    wrap_core(key, n, ct.as_mut_slice(), aes_func);

    Ok(ct)
}

fn aes128_ecb_encrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes128Ecb::new_var(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.encrypt(data, AES_BLOCK_LEN).expect("Failed to encrypt data block");
}

fn aes192_ecb_encrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes192Ecb::new_var(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.encrypt(data, AES_BLOCK_LEN).expect("Failed to encrypt data block");
}

fn aes256_ecb_encrypt(key: &[u8], data: &mut [u8]) {
    let cipher = Aes256Ecb::new_var(key, Default::default()).expect("Failed to create AES context");
    // Modifies data in place
    cipher.encrypt(data, AES_BLOCK_LEN).expect("Failed to encrypt data block");
}

fn wrap_core<AesEcb>(key: &[u8], n: usize, ct: &mut [u8], aes_ecb_encrypt: AesEcb)
where
    AesEcb: Fn(&[u8], &mut [u8]),
{
    if ct.len() > AES_BLOCK_LEN {
        // Allocate buffer for operations in loop
        // tmp = A | R[i]
        let mut tmp: Vec<u8> = vec![0u8; AES_BLOCK_LEN];

        // Copy A into buffer
        tmp[0..BLOCK_LEN].copy_from_slice(&ct[0..BLOCK_LEN]);

        for j in 0..6 {
            for i in 1..=n {
                let idx = i * BLOCK_LEN;
                tmp[BLOCK_LEN..].copy_from_slice(&ct[idx..idx + BLOCK_LEN]);

                // B = AES(K, A | R[i])
                aes_ecb_encrypt(key, &mut tmp);

                // A = MSB(64, B) ^ t where t = (n*j)+i
                let t = ((n * j) + i) as u64;
                tmp[0..BLOCK_LEN]
                    .iter_mut()
                    .zip(t.to_be_bytes().iter())
                    .for_each(|(x1, x2)| *x1 ^= *x2);

                // R[i] = LSB(64, B)
                ct[idx..idx + BLOCK_LEN].copy_from_slice(&tmp[BLOCK_LEN..]);
            }

            // Put A into output
            ct[0..BLOCK_LEN].copy_from_slice(&tmp[0..BLOCK_LEN]);
        }
    } else {
        aes_ecb_encrypt(key, ct);
    }
}

#[cfg(test)]
mod tests {
    use super::{aes_wrap_with_nopadding, aes_wrap_with_padding};

    #[test]
    fn test_wrap_nopad_invalid_key_length() {
        let pt = hex!("000102030405060708090a0b0c0d0e0f").to_vec();
        let key = hex!("000102030405060708090a0b0c0d0e").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_err(), "Invalid key length erroneously passed");
    }

    #[test]
    fn test_wrap_pad_invalid_key_length() {
        let pt = hex!("000102030405060708090a0b0c0d0e0f").to_vec();
        let key = hex!("000102030405060708090a0b0c0d0e").to_vec();
        let ct = aes_wrap_with_padding(&pt, &key);
        assert!(ct.is_err(), "Invalid key length erroneously passed");
    }

    //
    // RFC3394 Test Vectors
    //
    #[test]
    fn test_wrap_nopad_16_byte_key_16_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").to_vec()
        );
    }

    #[test]
    fn test_wrap_nopad_24_byte_key_16_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").to_vec()
        );
    }

    #[test]
    fn test_wrap_nopad_32_byte_key_16_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").to_vec()
        );
    }

    #[test]
    fn test_wrap_nopad_24_byte_key_24_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF0001020304050607").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2").to_vec()
        );
    }

    #[test]
    fn test_wrap_nopad_32_byte_key_24_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF0001020304050607").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1").to_vec()
        );
    }

    #[test]
    fn test_wrap_nopad_32_byte_key_32_byte_data() {
        let pt = hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F").to_vec();
        let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec();
        let ct = aes_wrap_with_nopadding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21").to_vec()
        );
    }

    //
    // RFC5649 Test Vectors
    //
    #[test]
    fn test_wrap_pad_24_byte_key_20_byte_data() {
        let pt = hex!("c37b7e6492584340bed12207808941155068f738").to_vec();
        let key = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").to_vec();
        let ct = aes_wrap_with_padding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a").to_vec()
        );
    }

    #[test]
    fn test_wrap_pad_24_byte_key_7_byte_data() {
        let pt = hex!("466f7250617369").to_vec();
        let key = hex!("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").to_vec();
        let ct = aes_wrap_with_padding(&pt, &key);
        assert!(ct.is_ok(), "Test unexpectantly failed: {:?}", ct);
        assert_eq!(
            ct.unwrap(),
            hex!("afbeb0f07dfbf5419200f2ccb50bb24f").to_vec()
        );
    }
}
