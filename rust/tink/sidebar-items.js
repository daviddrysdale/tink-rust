initSidebarItems({"constant":[["UPSTREAM_VERSION","The upstream Tink version that this Rust port is based on."]],"enum":[["Primitive","The primitives available in Tink."]],"mod":[["cryptofmt","Provides constants and convenience methods that define the format of ciphertexts and signatures."],["keyset","Provide methods to generate, read, write or validate keysets."],["primitiveset","Provides a container for a set of cryptographic primitives."],["proto","Auto-generated code from protocol buffer message definitions."],["registry","Provides a container that for each supported key type holds a corresponding `KeyManager` object, which can generate new keys or instantiate the primitive corresponding to given key."],["subtle","Common methods needed in subtle implementations."],["utils","Utilities for Tink Rust code."]],"trait":[["Aead","`Aead` is the interface for authenticated encryption with additional authenticated data."],["AeadBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["DeterministicAead","`DeterministicAead` is the interface for deterministic authenticated encryption with associated data."],["DeterministicAeadBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["EncryptingWrite","Trait for an object that writes encrypted data.  Users must call `close()` to finish."],["HybridDecrypt","`HybridDecrypt` is the interface for hybrid decryption."],["HybridDecryptBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["HybridEncrypt","`HybridEncrypt` is the interface for hybrid encryption."],["HybridEncryptBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["Mac","`Mac` is the interface for MACs (Message Authentication Codes). This interface should be used for authentication only, and not for other purposes (for example, it should not be used to generate pseudorandom bytes)."],["MacBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["Prf","The `Prf` trait is an abstraction for an element of a pseudo random function family, selected by a key. It has the following property:"],["PrfBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["Signer","`Signer` is the signing interface for digital signature."],["SignerBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["StreamingAead","`StreamingAead` is an interface for streaming authenticated encryption with associated data."],["StreamingAeadBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."],["Verifier","`Verifier` is the verifying interface for digital signature."],["VerifierBoxClone","Trait bound to indicate that primitive trait objects should support cloning themselves as trait objects."]],"type":[["KeyId","Type alias for `u32` values being used as key identifiers."]]});