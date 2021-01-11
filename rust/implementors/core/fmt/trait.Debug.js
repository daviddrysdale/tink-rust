(function() {var implementors = {};
implementors["tink"] = [{"text":"impl Debug for Handle","synthetic":false,"types":[]},{"text":"impl Debug for AesCmacParams","synthetic":false,"types":[]},{"text":"impl Debug for AesCmacKey","synthetic":false,"types":[]},{"text":"impl Debug for AesCmacKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCmacPrfKey","synthetic":false,"types":[]},{"text":"impl Debug for AesCmacPrfKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrParams","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrKey","synthetic":false,"types":[]},{"text":"impl Debug for EllipticCurveType","synthetic":false,"types":[]},{"text":"impl Debug for EcPointFormat","synthetic":false,"types":[]},{"text":"impl Debug for HashType","synthetic":false,"types":[]},{"text":"impl Debug for HmacParams","synthetic":false,"types":[]},{"text":"impl Debug for HmacKey","synthetic":false,"types":[]},{"text":"impl Debug for HmacKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrHmacAeadKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrHmacAeadKey","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrHmacStreamingParams","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrHmacStreamingKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesCtrHmacStreamingKey","synthetic":false,"types":[]},{"text":"impl Debug for AesEaxParams","synthetic":false,"types":[]},{"text":"impl Debug for AesEaxKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesEaxKey","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmKey","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmHkdfStreamingParams","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmHkdfStreamingKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmHkdfStreamingKey","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmSivKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesGcmSivKey","synthetic":false,"types":[]},{"text":"impl Debug for AesSivKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for AesSivKey","synthetic":false,"types":[]},{"text":"impl Debug for ChaCha20Poly1305KeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for ChaCha20Poly1305Key","synthetic":false,"types":[]},{"text":"impl Debug for KeyTypeEntry","synthetic":false,"types":[]},{"text":"impl Debug for RegistryConfig","synthetic":false,"types":[]},{"text":"impl Debug for EcdsaParams","synthetic":false,"types":[]},{"text":"impl Debug for EcdsaPublicKey","synthetic":false,"types":[]},{"text":"impl Debug for EcdsaPrivateKey","synthetic":false,"types":[]},{"text":"impl Debug for EcdsaKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for EcdsaSignatureEncoding","synthetic":false,"types":[]},{"text":"impl Debug for KeyTemplate","synthetic":false,"types":[]},{"text":"impl Debug for KeyData","synthetic":false,"types":[]},{"text":"impl Debug for KeyMaterialType","synthetic":false,"types":[]},{"text":"impl Debug for Keyset","synthetic":false,"types":[]},{"text":"impl Debug for Key","synthetic":false,"types":[]},{"text":"impl Debug for KeysetInfo","synthetic":false,"types":[]},{"text":"impl Debug for KeyInfo","synthetic":false,"types":[]},{"text":"impl Debug for EncryptedKeyset","synthetic":false,"types":[]},{"text":"impl Debug for KeyStatusType","synthetic":false,"types":[]},{"text":"impl Debug for OutputPrefixType","synthetic":false,"types":[]},{"text":"impl Debug for EciesHkdfKemParams","synthetic":false,"types":[]},{"text":"impl Debug for EciesAeadDemParams","synthetic":false,"types":[]},{"text":"impl Debug for EciesAeadHkdfParams","synthetic":false,"types":[]},{"text":"impl Debug for EciesAeadHkdfPublicKey","synthetic":false,"types":[]},{"text":"impl Debug for EciesAeadHkdfPrivateKey","synthetic":false,"types":[]},{"text":"impl Debug for EciesAeadHkdfKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for Ed25519KeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for Ed25519PublicKey","synthetic":false,"types":[]},{"text":"impl Debug for Ed25519PrivateKey","synthetic":false,"types":[]},{"text":"impl Debug for Empty","synthetic":false,"types":[]},{"text":"impl Debug for HkdfPrfParams","synthetic":false,"types":[]},{"text":"impl Debug for HkdfPrfKey","synthetic":false,"types":[]},{"text":"impl Debug for HkdfPrfKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for HmacPrfParams","synthetic":false,"types":[]},{"text":"impl Debug for HmacPrfKey","synthetic":false,"types":[]},{"text":"impl Debug for HmacPrfKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for JwtHmacKey","synthetic":false,"types":[]},{"text":"impl Debug for JwtHmacKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for KmsAeadKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for KmsAeadKey","synthetic":false,"types":[]},{"text":"impl Debug for KmsEnvelopeAeadKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for KmsEnvelopeAeadKey","synthetic":false,"types":[]},{"text":"impl Debug for PrfBasedDeriverParams","synthetic":false,"types":[]},{"text":"impl Debug for PrfBasedDeriverKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for PrfBasedDeriverKey","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPkcs1Params","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPkcs1PublicKey","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPkcs1PrivateKey","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPkcs1KeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPssParams","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPssPublicKey","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPssPrivateKey","synthetic":false,"types":[]},{"text":"impl Debug for RsaSsaPssKeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for XChaCha20Poly1305KeyFormat","synthetic":false,"types":[]},{"text":"impl Debug for XChaCha20Poly1305Key","synthetic":false,"types":[]},{"text":"impl Debug for TinkError","synthetic":false,"types":[]}];
implementors["tink_awskms"] = [{"text":"impl Debug for AwsClient","synthetic":false,"types":[]}];
implementors["tink_signature"] = [{"text":"impl Debug for SignatureEncoding","synthetic":false,"types":[]}];
implementors["tink_testing_server"] = [{"text":"impl Debug for ServerInfoRequest","synthetic":false,"types":[]},{"text":"impl Debug for ServerInfoResponse","synthetic":false,"types":[]},{"text":"impl Debug for KeysetGenerateRequest","synthetic":false,"types":[]},{"text":"impl Debug for KeysetGenerateResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for KeysetPublicRequest","synthetic":false,"types":[]},{"text":"impl Debug for KeysetPublicResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for KeysetToJsonRequest","synthetic":false,"types":[]},{"text":"impl Debug for KeysetToJsonResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for KeysetFromJsonRequest","synthetic":false,"types":[]},{"text":"impl Debug for KeysetFromJsonResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for AeadEncryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for AeadEncryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for AeadDecryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for AeadDecryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for DeterministicAeadEncryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for DeterministicAeadEncryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for DeterministicAeadDecryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for DeterministicAeadDecryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for StreamingAeadEncryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for StreamingAeadEncryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for StreamingAeadDecryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for StreamingAeadDecryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for ComputeMacRequest","synthetic":false,"types":[]},{"text":"impl Debug for ComputeMacResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for VerifyMacRequest","synthetic":false,"types":[]},{"text":"impl Debug for VerifyMacResponse","synthetic":false,"types":[]},{"text":"impl Debug for HybridEncryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for HybridEncryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for HybridDecryptRequest","synthetic":false,"types":[]},{"text":"impl Debug for HybridDecryptResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for SignatureSignRequest","synthetic":false,"types":[]},{"text":"impl Debug for SignatureSignResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for SignatureVerifyRequest","synthetic":false,"types":[]},{"text":"impl Debug for SignatureVerifyResponse","synthetic":false,"types":[]},{"text":"impl Debug for PrfSetKeyIdsRequest","synthetic":false,"types":[]},{"text":"impl Debug for PrfSetKeyIdsResponse","synthetic":false,"types":[]},{"text":"impl Debug for Output","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl Debug for PrfSetComputeRequest","synthetic":false,"types":[]},{"text":"impl Debug for PrfSetComputeResponse","synthetic":false,"types":[]},{"text":"impl Debug for Result","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for MetadataClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for KeysetClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for AeadClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for DeterministicAeadClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for StreamingAeadClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for MacClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for HybridClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for SignatureClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Debug for PrfSetClient&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Metadata&gt; Debug for MetadataServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Keyset&gt; Debug for KeysetServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Aead&gt; Debug for AeadServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + DeterministicAead&gt; Debug for DeterministicAeadServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + StreamingAead&gt; Debug for StreamingAeadServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Mac&gt; Debug for MacServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Hybrid&gt; Debug for HybridServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + Signature&gt; Debug for SignatureServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug + PrfSet&gt; Debug for PrfSetServer&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;Debug&gt; Debug for _Inner&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl Debug for AeadServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for DaeadServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for KeysetServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for MacServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for MetadataServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for PrfSetServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for SignatureServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for StreamingAeadServerImpl","synthetic":false,"types":[]},{"text":"impl Debug for Opt","synthetic":false,"types":[]}];
implementors["tink_testutil"] = [{"text":"impl Debug for WycheproofSuite","synthetic":false,"types":[]},{"text":"impl Debug for WycheproofGroup","synthetic":false,"types":[]},{"text":"impl Debug for WycheproofResult","synthetic":false,"types":[]},{"text":"impl Debug for WycheproofCase","synthetic":false,"types":[]},{"text":"impl Debug for DummyAeadKeyManager","synthetic":false,"types":[]},{"text":"impl Debug for DummyAead","synthetic":false,"types":[]},{"text":"impl Debug for DummyMac","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()