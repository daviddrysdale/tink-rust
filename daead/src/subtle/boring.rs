// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Provides a Boring-SSL backed AES-256 cipher in a form suitable for
//! use with RustCrypto traits.

use generic_array::{
    typenum::{U16, U32, U8},
    GenericArray,
};
use std::convert::TryInto;

/// AES-256 block cipher
#[derive(Clone)]
pub struct Aes256 {
    key: [u8; 32],
}

impl cipher::NewBlockCipher for Aes256 {
    type KeySize = U32;

    #[inline]
    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self {
            key: key.as_slice().try_into().unwrap(/* safe: array size checked */),
        }
    }
}

impl cipher::BlockCipher for Aes256 {
    type BlockSize = U16;
    type ParBlocks = U8;

    #[inline]
    fn encrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        // To encrypt a single block, use electronic code book mode (ECB).
        let cipher = boring::symm::Cipher::aes_256_ecb();
        // TODO: investigate whether `boring` has an in-place encrypt operation.
        let ciphertext = boring::symm::encrypt(cipher, &self.key[..], None, block).unwrap();
        block[..16].copy_from_slice(&ciphertext)
    }

    #[inline]
    fn decrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        // To decrypt a single block, use electronic code book mode (ECB).
        let cipher = boring::symm::Cipher::aes_256_ecb();
        // TODO: investigate whether `boring` has an in-place decrypt operation.
        let plaintext = boring::symm::decrypt(cipher, &self.key[..], None, block).unwrap();
        block[..16].copy_from_slice(&plaintext)
    }
}
