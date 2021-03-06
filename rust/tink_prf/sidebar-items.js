initSidebarItems({"constant":[["AES_CMAC_PRF_KEY_VERSION","Maximal version of AES-CMAC PRF keys."],["AES_CMAC_PRF_TYPE_URL","Type URL of AES-CMAC PRF keys that Tink supports."],["HKDF_PRF_KEY_VERSION","Maximal version of HKDF PRF keys."],["HKDF_PRF_TYPE_URL","Type URL of HKDF PRF keys that Tink supports."],["HMAC_PRF_KEY_VERSION","Maximal version of HMAC PRF keys."],["HMAC_PRF_TYPE_URL","Type URL of HMAC PRF keys that Tink supports."],["UPSTREAM_VERSION","The upstream Tink version that this Rust port is based on."]],"fn":[["aes_cmac_prf_key_template","Return a [`KeyTemplate`] that generates an AES-CMAC key with the following parameters:"],["hkdf_sha256_prf_key_template","Return a [`KeyTemplate`] that generates an HKDF key with the following parameters:"],["hmac_sha256_prf_key_template","Return a [`KeyTemplate`] that generates an HMAC key with the following parameters:"],["hmac_sha512_prf_key_template","Return a [`KeyTemplate`] that generates an HMAC key with the following parameters:"],["init","Initialize the `tink-prf` crate, registering its primitives so they are available via Tink."]],"mod":[["subtle","Provides subtle implementations of the `tink_core::Prf` primitive."]],"struct":[["Set","`Set` is a set of PRFs. A `Keyset` can be converted into a set of PRFs using this primitive. Every key in the keyset corresponds to a PRF in the prf.Set. Every PRF in the set is given an ID, which is the same ID as the key id in the `Keyset`."]]});