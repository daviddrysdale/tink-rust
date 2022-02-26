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

use tink_core::keyset::insecure;
use tink_proto::key_data::KeyMaterialType;
use tink_tests::expect_err;

#[test]
fn test_keyset_manager_basic() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm = tink_core::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm.add(&kt, /* primary= */ true)
        .expect("cannot rotate when key template is available");
    let h = ksm.handle().expect("cannot get keyset handle");
    let ks = insecure::keyset_material(&h);
    assert_eq!(
        1,
        ks.key.len(),
        "expect the number of keys in the keyset is 1"
    );
    assert_eq!(ks.key[0].key_id, ks.primary_key_id);
    assert_eq!(
        ks.key[0].key_data.as_ref().unwrap().type_url,
        tink_tests::HMAC_TYPE_URL
    );
    assert_eq!(ks.key[0].status, tink_proto::KeyStatusType::Enabled as i32);
    assert_eq!(
        ks.key[0].output_prefix_type,
        tink_proto::OutputPrefixType::Tink as i32
    );
}

#[test]
fn test_keyset_manager_operations() {
    tink_aead::init();
    let mut key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key.
    let mut keyset_manager = tink_core::keyset::Manager::new();
    keyset_manager
        .add(&key_template, /* as_primary= */ true)
        .unwrap();
    assert_eq!(1, keyset_manager.key_count());

    // Verify the keyset.
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    let key_id_0 = keyset.key[0].key_id;
    assert_eq!(key_id_0, keyset.primary_key_id);
    assert_eq!(
        keyset.key[0].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[0].output_prefix_type,
        tink_proto::OutputPrefixType::Tink as i32
    );
    assert_eq!(
        keyset.key[0].key_data.as_ref().unwrap().type_url,
        tink_tests::AES_GCM_TYPE_URL
    );
    assert_eq!(
        KeyMaterialType::Symmetric as i32,
        keyset.key[0].key_data.as_ref().unwrap().key_material_type
    );

    // Add another key.
    key_template.output_prefix_type = tink_proto::OutputPrefixType::Raw as i32;
    let key_id_1 = keyset_manager
        .add(&key_template, /* as_primary= */ false)
        .unwrap();
    assert_eq!(2, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(2, keyset.key.len());
    assert_eq!(key_id_0, keyset.primary_key_id);
    assert_ne!(keyset.key[0].key_data, keyset.key[1].key_data);
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[1].output_prefix_type,
        tink_proto::OutputPrefixType::Raw as i32
    );
    assert_eq!(
        keyset.key[1].key_data.as_ref().unwrap().type_url,
        tink_tests::AES_GCM_TYPE_URL
    );
    assert_eq!(
        KeyMaterialType::Symmetric as i32,
        keyset.key[1].key_data.as_ref().unwrap().key_material_type
    );

    // And another one, via rotation.
    key_template.output_prefix_type = tink_proto::OutputPrefixType::Legacy as i32;
    let key_id_2 = keyset_manager
        .add(&key_template, /* primary= */ true)
        .unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(3, keyset.key.len());
    assert_eq!(key_id_2, keyset.primary_key_id);
    assert_ne!(keyset.key[0].key_data, keyset.key[2].key_data);
    assert_ne!(keyset.key[1].key_data, keyset.key[2].key_data);
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[2].output_prefix_type,
        tink_proto::OutputPrefixType::Legacy as i32
    );
    assert_eq!(
        keyset.key[2].key_data.as_ref().unwrap().type_url,
        tink_tests::AES_GCM_TYPE_URL
    );
    assert_eq!(
        KeyMaterialType::Symmetric as i32,
        keyset.key[2].key_data.as_ref().unwrap().key_material_type
    );

    // Change the primary.
    keyset_manager.set_primary(key_id_1).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(3, keyset_manager.key_count());
    assert_eq!(3, keyset.key.len());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Clone a keyset via the manager, and check equality.
    let keyset_manager_2 =
        tink_core::keyset::Manager::new_from_handle(keyset_manager.handle().unwrap());
    let keyset_2 = insecure::keyset_material(&keyset_manager_2.handle().unwrap());
    assert_eq!(keyset, keyset_2);

    // Disable a key, and try to set it as primary.
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    keyset_manager.disable(key_id_2).unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );

    let result = keyset_manager.set_primary(key_id_2);
    expect_err(result, "must be Enabled");
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Enable ENABLED key, disable a DISABLED one.
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    keyset_manager.enable(key_id_1).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );

    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );
    keyset_manager.disable(key_id_2).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );

    // Enable the disabled key, then destroy it, and try to re-enable.
    keyset_manager.enable(key_id_2).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert!(keyset.key[2].key_data.is_some());

    keyset_manager.destroy(key_id_2).unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Destroyed as i32
    );
    assert!(keyset.key[2].key_data.is_none());

    let result = keyset_manager.enable(key_id_2);
    expect_err(result, "Cannot enable key");
    let result = keyset_manager.disable(key_id_2);
    expect_err(result, "Cannot disable key");
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Destroyed as i32
    );
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Delete the destroyed key, then try to destroy and delete it again.
    keyset_manager.delete(key_id_2).unwrap();
    assert_eq!(2, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(2, keyset.key.len());

    let result = keyset_manager.destroy(key_id_2);
    expect_err(result, "not found");

    let result = keyset_manager.delete(key_id_2);
    expect_err(result, "not found");

    // Try disabling/destroying/deleting the primary key.
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    let result = keyset_manager.disable(key_id_1);
    expect_err(result, "Cannot disable primary");

    let result = keyset_manager.destroy(key_id_1);
    expect_err(result, "Cannot destroy primary");

    let result = keyset_manager.delete(key_id_1);
    expect_err(result, "Cannot delete primary");

    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Delete the first key, then try to set it as primary.
    keyset_manager.delete(key_id_0).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(1, keyset.key.len());
    assert_eq!(key_id_1, keyset.key[0].key_id);

    let result = keyset_manager.set_primary(key_id_0);
    expect_err(result, "not found");
    assert_eq!(1, keyset_manager.key_count());

    // Operations with invalid key ID fail
    let invalid_key_id = 99999; // assume this doesn't accidentally clash
    assert!(keyset_manager.set_primary(invalid_key_id).is_err());
    assert!(keyset_manager.enable(invalid_key_id).is_err());
    assert!(keyset_manager.disable(invalid_key_id).is_err());
    assert!(keyset_manager.destroy(invalid_key_id).is_err());
    assert!(keyset_manager.delete(invalid_key_id).is_err());
}

#[test]
fn test_keyset_manager_corrupt_primary_key() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key which has an invalid status value.
    let mut km = tink_core::keyset::Manager::new();
    km.add(&key_template, /* primary= */ true).unwrap();
    let mut keyset = insecure::keyset_material(&km.handle().unwrap());
    keyset.key[0].status = 999;
    let key_id = keyset.key[0].key_id;

    let kh = insecure::new_handle(keyset).unwrap();
    let mut km = tink_core::keyset::Manager::new_from_handle(kh);

    // All operations shoud fail.
    let result = km.enable(key_id);
    expect_err(result, "Cannot enable");
    let result = km.disable(key_id);
    expect_err(result, "Cannot disable");
    let result = km.destroy(key_id);
    expect_err(result, "Cannot destroy");
    let result = km.set_primary(key_id);
    expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_corrupt_secondary_key() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a valid primary key and a second key with an invalid status
    // value.
    let mut km = tink_core::keyset::Manager::new();
    let _primary_key_id = km.add(&key_template, /* primary= */ true).unwrap();
    let secondary_key_id = km.add(&key_template, false).unwrap();
    let mut keyset = insecure::keyset_material(&km.handle().unwrap());
    keyset.key[1].status = 999;

    let kh = insecure::new_handle(keyset).unwrap();
    let mut km = tink_core::keyset::Manager::new_from_handle(kh);

    // All operations shoud fail.
    let result = km.enable(secondary_key_id);
    expect_err(result, "Cannot enable");
    let result = km.disable(secondary_key_id);
    expect_err(result, "Cannot disable");
    let result = km.destroy(secondary_key_id);
    expect_err(result, "Cannot destroy");
    let result = km.set_primary(secondary_key_id);
    expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_invalid_key_id() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key.
    let mut km = tink_core::keyset::Manager::new();
    km.add(&key_template, /* primary= */ true).unwrap();

    // All operations shoud fail with an invalid key_id.
    let key_id = 9999;
    let result = km.enable(key_id);
    expect_err(result, "not found");
    let result = km.disable(key_id);
    expect_err(result, "not found");
    let result = km.destroy(key_id);
    expect_err(result, "not found");
    let result = km.set_primary(key_id);
    expect_err(result, "not found");
}

#[test]
fn test_keyset_manager_unknown_prefix_type() {
    tink_aead::init();
    let mut key_template = tink_aead::aes128_gcm_key_template();
    for prefix_type in &[9999, tink_proto::OutputPrefixType::UnknownPrefix as i32] {
        key_template.output_prefix_type = *prefix_type;

        let mut km = tink_core::keyset::Manager::new();
        let result = km.add(&key_template, /* primary= */ true);
        expect_err(result, "unknown output prefix type");
    }
}

#[test]
fn test_existing_keyset() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm1 = tink_core::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm1.add(&kt, /* primary= */ true)
        .expect("cannot rotate when key template is available");

    let h1 = ksm1.handle().expect("cannot get keyset handle");
    let ks1 = insecure::keyset_material(&h1);

    let mut ksm2 = tink_core::keyset::Manager::new_from_handle(h1);
    ksm2.add(&kt, /* primary= */ true)
        .expect("failed to rotate");
    let h2 = ksm2.handle().expect("cannot get keyset handle");
    let ks2 = insecure::keyset_material(&h2);

    assert_eq!(ks2.key.len(), 2, "expect the number of keys to be 2");
    assert_eq!(
        format!("{:?}", ks1.key[0]),
        format!("{:?}", ks2.key[0]),
        "expect the first key in two keysets to be the same"
    );
    assert_eq!(
        ks2.key[1].key_id, ks2.primary_key_id,
        "expect the second key to be primary"
    );
}

#[test]
fn test_keyset_manager_full() {
    tink_mac::init();

    // Test a full keyset manager cycle: add, get info, set primary.
    let mut ksm = tink_core::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm.add(&kt, /* as_primary= */ false).unwrap();
    let h1 = ksm.handle().unwrap();
    let info = h1.keyset_info();
    assert_eq!(
        info.key_info.len(),
        1,
        "Expected one key but got {}",
        info.key_info.len()
    );
    let new_primary_key = info.key_info[0].key_id;
    ksm.set_primary(new_primary_key).unwrap();
    // validate this is a valid keyset
    let h1 = ksm.handle().unwrap();
    let ks1 = insecure::keyset_material(&h1);
    let result = tink_core::keyset::validate(&ks1);
    assert!(
        result.is_ok(),
        "keyset {:?} failed validation: {:?}",
        ks1,
        result
    );
}

#[test]
fn test_unknown_output_prefix_type_fails() {
    let mut ksm1 = tink_core::keyset::Manager::new();
    let mut kt = tink_mac::hmac_sha256_tag128_key_template();
    kt.output_prefix_type = tink_proto::OutputPrefixType::UnknownPrefix as i32;
    let result = ksm1.add(&kt, /* primary= */ true);
    expect_err(result, "unknown output prefix type");
}

#[test]
fn test_keyset_manager_add() {
    tink_mac::init();

    let mut ksm = tink_core::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    let key_id = ksm.add(&kt, /* as_primary= */ false).unwrap();
    let h1 = ksm.handle().unwrap();
    let ks = insecure::keyset_material(&h1);
    assert_eq!(ks.key.len(), 1, "Expected one key but got {}", ks.key.len());
    assert_eq!(
        ks.key[0].key_id, key_id,
        "Expected added key_id to be {} but got {}",
        key_id, ks.key[0].key_id
    );
    assert_eq!(
        ks.key[0].status,
        tink_proto::KeyStatusType::Enabled as i32,
        "Expected key to be enabled but got {:?}",
        ks.key[0].status
    );
    // no primary key set
    assert_eq!(
        ks.primary_key_id, 0,
        "Expected no primary key but got {}",
        ks.primary_key_id
    );
}

#[test]
fn test_keyset_manager_add_with_bad_template() {
    let mut ksm = tink_core::keyset::Manager::new();
    let kt = tink_proto::KeyTemplate {
        type_url: "invalid type".to_string(),
        output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
        value: vec![],
    };
    let result = ksm.add(&kt, /* as_primary= */ false);
    assert!(result.is_err());
}

#[test]
fn test_keyset_manager_enable() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Disabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // enable key
    ksm1.enable(key_id).unwrap();
    let h2 = ksm1.handle().unwrap();
    let ks2 = insecure::keyset_material(&h2);
    assert_eq!(
        ks2.key.len(),
        1,
        "Expected only one key, got {}",
        ks2.key.len()
    );
    assert_eq!(
        ks2.key[0].key_id, key_id,
        "Expected key_id {}, got {}",
        key_id, ks2.key[0].key_id
    );
    assert_eq!(
        ks2.key[0].status,
        tink_proto::KeyStatusType::Enabled as i32,
        "Expected key to be enabled, but got {:?}",
        ks2.key[0].status,
    );
}

#[test]
fn test_keyset_manager_enable_with_unknown_status() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::UnknownStatus,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // enable key
    let result = ksm1.enable(key_id);
    expect_err(result, "Cannot enable");
}

#[test]
fn test_keyset_manager_enable_with_destroyed() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Destroyed,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // enable key
    let result = ksm1.enable(key_id);
    expect_err(result, "Cannot enable");
}

#[test]
fn test_keyset_manager_enable_with_missing_key() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::UnknownStatus,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // enable key
    let result = ksm1.enable(43u32);
    expect_err(result, "not found");
}

#[test]
fn test_keyset_manager_set_primary() {
    let key_id = 42u32;
    let new_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        new_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // set primary key
    ksm1.set_primary(new_key_id).unwrap();
    let h2 = ksm1.handle().unwrap();
    let ks2 = insecure::keyset_material(&h2);
    assert_eq!(ks2.key.len(), 2, "Expected two keys, got {}", ks2.key.len());
    assert_eq!(
        ks2.primary_key_id, new_key_id,
        "Expected new key to be primary, got {}",
        ks2.primary_key_id
    );
}

#[test]
fn test_keyset_manager_set_primary_with_disabled_key() {
    let key_id = 42u32;
    let new_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    // create a disabled key
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Disabled,
        new_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // set primary key
    let result = ksm1.set_primary(new_key_id);
    expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_set_primary_with_destroyed_key() {
    let key_id = 42u32;
    let new_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    // create a destroyed key
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Destroyed,
        new_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // set primary key
    let result = ksm1.set_primary(new_key_id);
    expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_set_primary_with_unknown_status_key() {
    let key_id = 42u32;
    let new_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    // create an unknown status key
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::UnknownStatus,
        new_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // set primary key
    let result = ksm1.set_primary(new_key_id);
    expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_set_primary_with_missing_key() {
    let key_id = 42u32;
    let new_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    // create an unknown status key
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::UnknownStatus,
        new_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // set primary key
    let result = ksm1.set_primary(44u32);
    expect_err(result, "not found");
}

#[test]
fn test_keyset_manager_disable() {
    let primary_key_id = 42u32;
    let other_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        primary_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        other_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(primary_key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // disable key
    ksm1.disable(other_key_id).unwrap();
    let h2 = ksm1.handle().unwrap();
    let ks2 = insecure::keyset_material(&h2);
    assert_eq!(
        ks2.primary_key_id, primary_key_id,
        "Expected same key to be primary, got {}",
        ks2.primary_key_id
    );
    assert_eq!(ks2.key.len(), 2, "Expected two keys, got {}", ks2.key.len());
    assert_eq!(
        ks2.key[1].status,
        tink_proto::KeyStatusType::Disabled as i32,
        "Expected key to be disabled, got {:?}",
        ks2.key[1].status
    );
}

#[test]
fn test_keyset_manager_disable_with_primary_key() {
    let primary_key_id = 42u32;
    let other_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        primary_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        other_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(primary_key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // disable key
    let result = ksm1.disable(primary_key_id);
    expect_err(result, "Cannot disable primary key");
    let h2 = ksm1.handle().unwrap();
    let ks2 = insecure::keyset_material(&h2);
    assert_eq!(
        ks2.primary_key_id, primary_key_id,
        "Expected same key to be primary, got {}",
        ks2.primary_key_id,
    );
}

#[test]
fn test_keyset_manager_disable_with_destroyed_key() {
    let primary_key_id = 42u32;
    let other_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        primary_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    // destroyed key
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Destroyed,
        other_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(primary_key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // disable key
    let result = ksm1.disable(other_key_id);
    expect_err(result, "Cannot disable");
}

#[test]
fn test_keyset_manager_disable_with_missing_key() {
    let primary_key_id = 42u32;
    let other_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        primary_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        other_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(primary_key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // disable key
    let result = ksm1.disable(44u32);
    expect_err(result, "not found");
}

#[test]
fn test_keyset_manager_delete() {
    let key_id = 42u32;
    let other_key_id = 43u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let key2 = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        other_key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key, key2]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // delete key
    ksm1.delete(other_key_id).unwrap();
    let h2 = ksm1.handle().unwrap();
    let ks2 = insecure::keyset_material(&h2);
    assert_eq!(
        ks2.key.len(),
        1,
        "Expected only one key but got {}",
        ks2.key.len()
    );
    assert!(
        ks2.key[0].key_id == key_id,
        "Expected key_id {} to be present but got {}",
        key_id,
        ks2.key[0].key_id
    );
    assert_eq!(
        ks2.key[0].status,
        tink_proto::KeyStatusType::Enabled as i32,
        "Expected key to be enabled but got {:?}",
        ks2.key[0].status
    );
}

#[test]
fn test_keyset_manager_delete_with_primary_key() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // delete key
    let result = ksm1.delete(key_id);
    expect_err(result, "primary key");
}

#[test]
fn test_keyset_manager_delete_with_missing_key() {
    let key_id = 42u32;
    let key_data = tink_tests::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_tests::new_key(
        &key_data,
        tink_proto::KeyStatusType::Enabled,
        key_id,
        tink_proto::OutputPrefixType::Tink,
    );
    let ks1 = tink_tests::new_keyset(key_id, vec![key]);
    let h1 = insecure::new_handle(ks1).unwrap();
    let mut ksm1 = tink_core::keyset::Manager::new_from_handle(h1);
    // delete key
    let result = ksm1.delete(43u32);
    expect_err(result, "not found");
}
