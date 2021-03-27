// Copyright 2021 Google LLC
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

use rsa::BigUint;
use std::convert::TryInto;
use tink_core::{utils::wrap_err, TinkError};

/// Generate an RSA key with the given modulus size and public exponent.
pub fn generate_rsa_key(
    modulus_size: u64,
    public_exponent: u64,
) -> Result<::rsa::RSAPrivateKey, TinkError> {
    let modulus_size = valid_modulus_size(modulus_size)?;
    let public_exponent = valid_public_exponent(public_exponent)?;
    // TODO: is there a version of rand_core re-exported from ::rsa that could be used
    // here to guarantee correct version?
    let mut csprng = signature::rand_core::OsRng {};
    ::rsa::RSAPrivateKey::new_with_exp(&mut csprng, modulus_size, &public_exponent)
        .map_err(|e| wrap_err("failed to generate RSA private key", e))
}

/// RSA public key as raw data.
///
/// This facilitates creating instances of [`::rsa::RSAPublicKey`] from serialized
/// key material.
#[derive(Clone)]
pub struct RsaPublicKeyData {
    pub e: u64,
    pub n: BigUint,
}

impl RsaPublicKeyData {
    /// Verify that the parameters contain valid values.
    pub fn validate(&self) -> Result<(), TinkError> {
        valid_modulus(self.n.clone()).map_err(|e| wrap_err("invalid RSA public key data", e))?;
        valid_public_exponent(self.e).map_err(|e| wrap_err("invalid RSA public key data", e))?;
        Ok(())
    }

    /// Create an [`::rsa::RSAPublicKey`] from the parameters.
    // TODO: should this consume self instead?
    pub fn create_key(&self) -> Result<::rsa::RSAPublicKey, TinkError> {
        self.validate()?;
        ::rsa::RSAPublicKey::new(self.n.clone(), self.e.into())
            .map_err(|e| wrap_err("failed to convert public key data", e))
    }
}

/// RSA private key as raw data.
///
/// This facilitates creating instances of [`::rsa::RSAPrivateKey`] from serialized
/// key material.
#[derive(Clone)]
pub struct RsaPrivateKeyData {
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub public_key_data: RsaPublicKeyData,
}

impl RsaPrivateKeyData {
    /// Verify that the populated data is valid.
    pub fn validate(&self) -> Result<(), TinkError> {
        let _ = self.create_key()?;
        Ok(())
    }

    /// Create an [`::rsa::RSAPrivateKey`].
    // TODO: should this consume self instead?
    pub fn create_key(&self) -> Result<::rsa::RSAPrivateKey, TinkError> {
        self.public_key_data
            .validate()
            .map_err(|e| wrap_err("invalid RSA private key data", e))?;
        let mut priv_key = ::rsa::RSAPrivateKey::from_components(
            self.public_key_data.n.clone(),
            self.public_key_data.e.into(),
            self.d.clone(),
            vec![self.p.clone(), self.q.clone()],
        );
        priv_key
            .precompute()
            .map_err(|e| wrap_err("invalid RSA private key data", e))?;
        priv_key
            .validate()
            .map_err(|e| wrap_err("invalid RSA private key data", e))?;
        Ok(priv_key)
    }
}

fn valid_modulus_size(m: u64) -> Result<usize, TinkError> {
    if m < 2048 {
        Err("modulus size too small, must be >= 2048".into())
    } else {
        m.try_into()
            .map_err(|e| wrap_err("modulus size invalid", e))
    }
}

fn valid_modulus(m: BigUint) -> Result<(), TinkError> {
    let bit_len: u64 = m
        .bits()
        .try_into()
        .map_err(|e| wrap_err("invalid modulus", e))?;
    valid_modulus_size(bit_len)?;
    Ok(())
}

fn valid_public_exponent(e: u64) -> Result<BigUint, TinkError> {
    // Only support 0x10001 modulus at the moment.
    if e != 65537 {
        Err("invalid public exponent".into())
    } else {
        Ok(e.into())
    }
}
