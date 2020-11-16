initSidebarItems({"enum":[["EcPointFormat",""],["EcdsaSignatureEncoding",""],["EllipticCurveType",""],["HashType",""],["KeyStatusType",""],["OutputPrefixType","Tink produces and accepts ciphertexts or signatures that consist of a prefix and a payload. The payload and its format is determined entirely by the primitive, but the prefix has to be one of the following 4 types:"]],"mod":[["key_data",""],["keyset",""],["keyset_info",""]],"struct":[["AesCmacKey","key_type: type.googleapis.com/google.crypto.tink.AesCmacKey"],["AesCmacKeyFormat",""],["AesCmacParams",""],["AesCmacPrfKey","key_type: type.googleapis.com/google.crypto.tink.AesCmacPrfKey"],["AesCmacPrfKeyFormat",""],["AesCtrHmacAeadKey","key_type: type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"],["AesCtrHmacAeadKeyFormat",""],["AesCtrHmacStreamingKey","key_type: type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"],["AesCtrHmacStreamingKeyFormat",""],["AesCtrHmacStreamingParams",""],["AesCtrKey","key_type: type.googleapis.com/google.crypto.tink.AesCtrKey"],["AesCtrKeyFormat",""],["AesCtrParams",""],["AesEaxKey","key_type: type.googleapis.com/google.crypto.tink.AesEaxKey"],["AesEaxKeyFormat",""],["AesEaxParams","only allowing tag size in bytes = 16"],["AesGcmHkdfStreamingKey","key_type: type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"],["AesGcmHkdfStreamingKeyFormat",""],["AesGcmHkdfStreamingParams",""],["AesGcmKey","key_type: type.googleapis.com/google.crypto.tink.AesGcmKey"],["AesGcmKeyFormat","only allowing IV size in bytes = 12 and tag size in bytes = 16 Thus, accept no params."],["AesGcmSivKey","key_type: type.googleapis.com/google.crypto.tink.AesGcmSivKey"],["AesGcmSivKeyFormat","The only allowed IV size is 12 bytes and tag size is 16 bytes. Thus, accept no params."],["AesSivKey","key_type: type.googleapis.com/google.crypto.tink.AesSivKey"],["AesSivKeyFormat",""],["ChaCha20Poly1305Key","key_type: type.googleapis.com/google.crypto.tink.ChaCha20Poly1305. This key type actually implements ChaCha20Poly1305 as described at https://tools.ietf.org/html/rfc7539#section-2.8."],["ChaCha20Poly1305KeyFormat",""],["EcdsaKeyFormat",""],["EcdsaParams","Protos for Ecdsa."],["EcdsaPrivateKey","key_type: type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"],["EcdsaPublicKey","key_type: type.googleapis.com/google.crypto.tink.EcdsaPublicKey"],["EciesAeadDemParams","Parameters of AEAD DEM (Data Encapsulation Mechanism)."],["EciesAeadHkdfKeyFormat",""],["EciesAeadHkdfParams",""],["EciesAeadHkdfPrivateKey","EciesKdfAeadPrivateKey represents HybridDecryption primitive. key_type: type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"],["EciesAeadHkdfPublicKey","EciesAeadHkdfPublicKey represents HybridEncryption primitive. key_type: type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"],["EciesHkdfKemParams","Parameters of KEM (Key Encapsulation Mechanism)"],["Ed25519KeyFormat",""],["Ed25519PrivateKey","key_type: type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"],["Ed25519PublicKey","key_type: type.googleapis.com/google.crypto.tink.Ed25519PublicKey"],["Empty",""],["EncryptedKeyset","Represents a keyset that is encrypted with a master key."],["HkdfPrfKey",""],["HkdfPrfKeyFormat",""],["HkdfPrfParams",""],["HmacKey","key_type: type.googleapis.com/google.crypto.tink.HmacKey"],["HmacKeyFormat",""],["HmacParams",""],["HmacPrfKey","key_type: type.googleapis.com/google.crypto.tink.HmacPrfKey"],["HmacPrfKeyFormat",""],["HmacPrfParams",""],["JwtHmacKey","key_type: type.googleapis.com/google.crypto.tink.JwtHmacKey"],["JwtHmacKeyFormat",""],["KeyData","The actual *Key-proto is wrapped in a KeyData message, which in addition to this serialized proto contains also type_url identifying the definition of *Key-proto (as in KeyFormat-message), and some extra metadata about the type key material."],["KeyTemplate",""],["KeyTypeEntry","An entry that describes a key type to be used with Tink library, specifying the corresponding primitive, key manager, and deprecation status. All fields are required."],["Keyset","A Tink user works usually not with single keys, but with keysets, to enable key rotation.  The keys in a keyset can belong to different implementations/key types, but must all implement the same primitive. Any given keyset (and any given key) can be used for one primitive only."],["KeysetInfo","Represents a \"safe\" Keyset that doesn't contain any actual key material, thus can be used for logging or monitoring. Most fields are copied from Keyset."],["KmsAeadKey","There is no actual key material in the key."],["KmsAeadKeyFormat",""],["KmsEnvelopeAeadKey","There is no actual key material in the key."],["KmsEnvelopeAeadKeyFormat",""],["PrfBasedDeriverKey","key_type: type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"],["PrfBasedDeriverKeyFormat",""],["PrfBasedDeriverParams",""],["RegistryConfig","A complete configuration of Tink library: a list of key types to be available via the Registry after initialization. All fields are required."],["RsaSsaPkcs1KeyFormat",""],["RsaSsaPkcs1Params",""],["RsaSsaPkcs1PrivateKey","key_type: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"],["RsaSsaPkcs1PublicKey","key_type: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"],["RsaSsaPssKeyFormat",""],["RsaSsaPssParams",""],["RsaSsaPssPrivateKey","key_type: type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"],["RsaSsaPssPublicKey","key_type: type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey"],["XChaCha20Poly1305Key","key_type: type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"],["XChaCha20Poly1305KeyFormat",""]]});