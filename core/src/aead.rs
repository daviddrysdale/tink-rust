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

//! Authenticated encryption with associated authenticated data.

/// `Aead` is the interface for authenticated encryption with associated data.
///
/// Implementations of this trait are secure against adaptive chosen ciphertext attacks.
/// Encryption with associated data ensures authenticity and integrity of that data, but not
/// its secrecy (see [RFC 5116](https://tools.ietf.org/html/rfc5116)).
pub trait Aead: AeadBoxClone {
    /// Encrypt plaintext with `associated_data` as associated data.
    /// The resulting ciphertext allows for checking
    /// authenticity and integrity of associated data `associated_data`,
    /// but there are no guarantees wrt. secrecy of that data.
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, crate::TinkError>;

    /// Decrypt ciphertext with `associated_data` as associated data.
    /// The decryption verifies the authenticity and integrity
    /// of the associated data, but there are no guarantees wrt. secrecy of that data.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, crate::TinkError>;
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait AeadBoxClone {
    fn box_clone(&self) -> Box<dyn Aead>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> AeadBoxClone for T
where
    T: 'static + Aead + Clone,
{
    fn box_clone(&self) -> Box<dyn Aead> {
        Box::new(self.clone())
    }
}
