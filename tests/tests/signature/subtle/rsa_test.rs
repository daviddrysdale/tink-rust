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

use ::rsa::PublicKeyParts;
use tink_core::TinkError;
use tink_signature::subtle;

#[test]
fn test_generate_rsa_key() {
    let modulus_size = 2048;
    let public_exponent = 65537;
    let _ = subtle::generate_rsa_key(modulus_size, public_exponent).unwrap();
}

#[test]
fn test_generate_rsa_key_invalid() {
    struct TestCase {
        name: &'static str,
        modulus_size: u64,
        public_exponent: u64,
    }
    let test_cases = vec![
        TestCase {
            name: "InvalidModulusSize",
            modulus_size: 1024,
            public_exponent: 65537,
        },
        TestCase {
            name: "InvalidPublicExponent",
            modulus_size: 2048,
            public_exponent: 3,
        },
    ];
    for tc in test_cases {
        let result = subtle::generate_rsa_key(tc.modulus_size, tc.public_exponent);
        assert!(
            result.is_err(),
            "GenerateRSAKey() succeeded with invalid input for {}, want error",
            tc.name
        );
    }
}

#[test]
fn test_rsa_public_key_data_validate_create_key() {
    let key_data = create_rsa_private_key_data().unwrap();
    key_data.public_key_data.validate().unwrap();
    let _ = key_data.public_key_data.create_key().unwrap();
}

#[test]
fn test_rsa_public_key_data_validate_create_key_invalid() {
    let valid_key_data = create_rsa_private_key_data().unwrap();
    struct TestCase {
        name: &'static str,
        key_data: subtle::RsaPublicKeyData,
    }
    let test_cases = vec![
        TestCase {
            name: "InvalidPublicExponent",
            key_data: subtle::RsaPublicKeyData {
                e: 3,
                n: valid_key_data.public_key_data.n,
            },
        },
        TestCase {
            name: "InvalidModulus",
            key_data: subtle::RsaPublicKeyData {
                e: valid_key_data.public_key_data.e,
                n: 0u64.into(),
            },
        },
    ];
    for tc in test_cases {
        assert!(
            tc.key_data.validate().is_err(),
            "validate() succeeded with an invalid input {}, want error",
            tc.name
        );
        assert!(
            tc.key_data.create_key().is_err(),
            "create_key() succeeded with an invalid input {}, want error",
            tc.name
        );
    }
}

#[test]
fn test_rsa_private_key_data_validate_create_key() {
    let key_data = create_rsa_private_key_data().unwrap();
    key_data.validate().unwrap();
    let _ = key_data.create_key().unwrap();
}

#[test]
fn test_rsa_private_key_data_validate_create_key_invalid() {
    let valid_key_data = create_rsa_private_key_data().unwrap();
    struct TestCase {
        name: &'static str,
        key_data: subtle::RsaPrivateKeyData,
    }
    let test_cases = vec![
        TestCase {
            name: "InvalidPublicExponent",
            key_data: subtle::RsaPrivateKeyData {
                d: valid_key_data.d.clone(),
                p: valid_key_data.p.clone(),
                q: valid_key_data.q.clone(),
                public_key_data: subtle::RsaPublicKeyData {
                    e: 3,
                    n: valid_key_data.public_key_data.n.clone(),
                },
            },
        },
        TestCase {
            name: "InvalidModulus",
            key_data: subtle::RsaPrivateKeyData {
                d: valid_key_data.d.clone(),
                p: valid_key_data.p.clone(),
                q: valid_key_data.q.clone(),
                public_key_data: subtle::RsaPublicKeyData {
                    e: valid_key_data.public_key_data.e,
                    n: 0u64.into(),
                },
            },
        },
        TestCase {
            name: "ZeroValue",
            key_data: subtle::RsaPrivateKeyData {
                d: 0u64.into(),
                p: 0u64.into(),
                q: 0u64.into(),
                public_key_data: subtle::RsaPublicKeyData {
                    e: 0u64,
                    n: 0u64.into(),
                },
            },
        },
        TestCase {
            name: "InvalidValue",
            key_data: subtle::RsaPrivateKeyData {
                d: 2u64.into(),
                p: valid_key_data.p.clone(),
                q: valid_key_data.q.clone(),
                public_key_data: valid_key_data.public_key_data,
            },
        },
    ];
    for tc in test_cases {
        assert!(
            tc.key_data.validate().is_err(),
            "validate() succeeded with an invalid input {}, want error",
            tc.name
        );
        assert!(
            tc.key_data.create_key().is_err(),
            "create_key() succeeded with an invalid input {}, want error",
            tc.name
        );
    }
}

fn create_rsa_private_key_data() -> Result<subtle::RsaPrivateKeyData, TinkError> {
    let priv_key = subtle::generate_rsa_key(2048, 65537)?;
    let primes = priv_key.primes();
    let pub_key = priv_key.to_public_key();
    Ok(subtle::RsaPrivateKeyData {
        d: priv_key.d().clone(),
        p: primes[0].clone(),
        q: primes[1].clone(),
        public_key_data: subtle::RsaPublicKeyData {
            e: 0x10001u64, // TODO: pub_key.e(),
            n: pub_key.n().clone(),
        },
    })
}
