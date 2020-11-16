initSidebarItems({"constant":[["AES_CTR_HMAC_AEAD_KEY_VERSION","Maximal version of AES-CTR-HMAC keys."],["AES_CTR_HMAC_AEAD_TYPE_URL","Type URL of AES-CTR-HMAC keys that Tink supports."],["AES_GCM_KEY_VERSION","Maximal version of AES-GCM keys."],["AES_GCM_TYPE_URL","Type URL of AES-GCM keys that Tink supports."],["CHA_CHA20_POLY1305_KEY_VERSION","Maximal version of ChaCha20Poly1305 keys."],["CHA_CHA20_POLY1305_TYPE_URL","Type URL of ChaCha20Poly1305 keys that Tink supports."],["KMS_ENVELOPE_AEAD_KEY_VERSION","Maximal version of KMS-wrapped keys."],["KMS_ENVELOPE_AEAD_TYPE_URL","Type URL of KMS-wrapped keys that Tink supports."],["X_CHA_CHA20_POLY1305_KEY_VERSION","Maximal version of XChaCha20Poly1305 keys."],["X_CHA_CHA20_POLY1305_TYPE_URL","Type URL of XChaCha20Poly1305 keys that Tink supports."]],"fn":[["aes128_ctr_hmac_sha256_key_template","Return a [`KeyTemplate`] that generates an AES-CTR-HMAC-AEAD key with the following parameters:"],["aes128_gcm_key_template","Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:"],["aes256_ctr_hmac_sha256_key_template","Return a [`KeyTemplate`] that generates an AES-CTR-HMAC-AEAD key with the following parameters:"],["aes256_gcm_key_template","Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:"],["aes256_gcm_no_prefix_key_template","Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:"],["cha_cha20_poly1305_key_template","Return a [`KeyTemplate`] that generates a CHACHA20_POLY1305 key."],["init","Initialize the `tink-aead` crate, registering its primitives so they are available via tink."],["kms_envelope_aead_key_template","Return a [`KeyTemplate`] that generates a KmsEnvelopeAead key for a given KEK in remote KMS"],["new","Returns a [`tink::Aead`] primitive from the given keyset handle."],["new_with_key_manager","Return a [`tink::Aead`] primitive from the given keyset handle and custom key manager."],["x_cha_cha20_poly1305_key_template","Return a [`KeyTemplate`] that generates a XCHACHA20_POLY1305 key."]],"mod":[["subtle","Provides subtle implementations of the `tink::Aead` primitive."]],"struct":[["KmsEnvelopeAead","`KmsEnvelopeAead` represents an instance of Envelope AEAD."]]});