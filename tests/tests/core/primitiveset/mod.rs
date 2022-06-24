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

use tink_core::{primitiveset::Entry, KeyId, MacBoxClone, Primitive};
use tink_proto::{keyset::Key, KeyStatusType, OutputPrefixType};
use tink_tests::{new_dummy_key, DummyMac};

fn make_test_key(
    key_id: KeyId,
    status: KeyStatusType,
    output_prefix_type: OutputPrefixType,
    type_url: &str,
) -> Key {
    let mut k = new_dummy_key(key_id, status, output_prefix_type);
    if let Some(key_data) = &mut k.key_data {
        key_data.type_url = type_url.to_string();
    }
    k
}

#[test]
fn test_primitiveset_new() {
    let ps = tink_core::primitiveset::PrimitiveSet::new();
    assert!(ps.primary.is_none());
    assert!(ps.entries.is_empty());
}

fn check_equal(left: &[Entry], right: &[Entry]) {
    assert_eq!(left.len(), right.len());
    for i in 0..left.len() {
        assert_eq!(left[i].key_id, right[i].key_id);
        assert_eq!(left[i].status, right[i].status);
        assert_eq!(left[i].prefix_type, right[i].prefix_type);
        assert_eq!(left[i].prefix, right[i].prefix);
        assert_eq!(left[i].type_url, right[i].type_url);
        // `Entry.primitive` is not `PartialEq`, so compare outputs
        let left_data = if let Primitive::Mac(mac) = &left[i].primitive {
            mac.compute_mac(&[1, 2, 3, 4, 5]).unwrap()
        } else {
            panic!("not a MAC!")
        };
        let right_data = if let Primitive::Mac(mac) = &right[i].primitive {
            mac.compute_mac(&[1, 2, 3, 4, 5]).unwrap()
        } else {
            panic!("not a MAC!")
        };
        assert_eq!(left_data, right_data);
    }
}

#[test]
fn test_primitiveset_add_entries() {
    let keys = vec![
        make_test_key(
            1234543,
            KeyStatusType::Enabled,
            OutputPrefixType::Tink,
            "type.url.1",
        ),
        make_test_key(
            7213743,
            KeyStatusType::Enabled,
            OutputPrefixType::Legacy,
            "type.url.2",
        ),
        make_test_key(
            5294722,
            KeyStatusType::Enabled,
            OutputPrefixType::Raw,
            "type.url.3",
        ),
    ];
    let macs: Vec<DummyMac> = (0..keys.len())
        .map(|i| DummyMac {
            name: format!("{}", i),
        })
        .collect();
    let mut ps = tink_core::primitiveset::PrimitiveSet::new();

    let got: Vec<Entry> = (0..macs.len())
        .map(|i| {
            ps.add(Primitive::Mac(Box::new(macs[i].clone())), &keys[i])
                .unwrap()
        })
        .collect();

    let want = vec![
        Entry {
            key_id: 1234543,
            status: KeyStatusType::Enabled,
            primitive: Primitive::Mac(Box::new(DummyMac {
                name: "0".to_string(),
            })),
            prefix_type: OutputPrefixType::Tink,
            type_url: "type.url.1".to_string(),
            prefix: vec![1, 0, 18, 214, 111],
        },
        Entry {
            key_id: 7213743,
            status: KeyStatusType::Enabled,
            primitive: Primitive::Mac(Box::new(DummyMac {
                name: "1".to_string(),
            })),
            prefix_type: OutputPrefixType::Legacy,
            type_url: "type.url.2".to_string(),
            prefix: vec![0, 0, 110, 18, 175],
        },
        Entry {
            key_id: 5294722,
            status: KeyStatusType::Enabled,
            primitive: Primitive::Mac(Box::new(DummyMac {
                name: "2".to_string(),
            })),
            prefix_type: OutputPrefixType::Raw,
            type_url: "type.url.3".to_string(),
            prefix: vec![],
        },
    ];
    check_equal(&got, &want);
}

#[test]
fn test_primitiveset_raw_entries() {
    let keys = vec![
        make_test_key(
            1234543,
            KeyStatusType::Enabled,
            OutputPrefixType::Tink,
            "type.url.1",
        ),
        make_test_key(
            7213743,
            KeyStatusType::Enabled,
            OutputPrefixType::Legacy,
            "type.url.2",
        ),
        make_test_key(
            9473277,
            KeyStatusType::Enabled,
            OutputPrefixType::Raw,
            "type.url.3",
        ),
        make_test_key(
            5294722,
            KeyStatusType::Enabled,
            OutputPrefixType::Raw,
            "type.url.4",
        ),
    ];

    let macs: Vec<DummyMac> = (0..keys.len())
        .map(|i| DummyMac {
            name: format!("Mac#{}", i),
        })
        .collect();
    let mut ps = tink_core::primitiveset::PrimitiveSet::new();
    for i in 0..macs.len() {
        ps.add(Primitive::Mac(Box::new(macs[i].clone())), &keys[i])
            .unwrap();
    }
    let got = ps.raw_entries();
    let want = vec![
        Entry {
            key_id: keys[2].key_id,
            status: KeyStatusType::from_i32(keys[2].status).unwrap(),
            prefix_type: OutputPrefixType::from_i32(keys[2].output_prefix_type).unwrap(),
            type_url: keys[2].key_data.as_ref().unwrap().type_url.clone(),
            primitive: Primitive::Mac(macs[2].box_clone()),
            prefix: vec![],
        },
        Entry {
            key_id: keys[3].key_id,
            status: KeyStatusType::from_i32(keys[3].status).unwrap(),
            prefix_type: OutputPrefixType::from_i32(keys[3].output_prefix_type).unwrap(),
            type_url: keys[3].key_data.as_ref().unwrap().type_url.clone(),
            primitive: Primitive::Mac(macs[3].box_clone()),
            prefix: vec![],
        },
    ];
    check_equal(&got, &want);
}

#[test]
fn test_primitiveset_prefixed_entries() {
    struct TestCase {
        _tag: &'static str,
        prefix: Vec<u8>,
        keys: Vec<Key>,
        primitives: Vec<DummyMac>,
        want: Vec<Entry>,
    }
    for tc in vec![
        TestCase {
            _tag: "legacy Prefix",
            prefix: vec![0, 0, 18, 214, 111], // LEGACY_PREFIX + 1234543,
            keys: vec![
                make_test_key(
                    1234543,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Legacy,
                    "type.url.1",
                ),
                make_test_key(
                    7213743,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Tink,
                    "type.url.2",
                ),
            ],
            primitives: vec![
                DummyMac {
                    name: "1".to_string(),
                },
                DummyMac {
                    name: "2".to_string(),
                },
            ],
            want: vec![Entry {
                key_id: 1234543,
                status: KeyStatusType::Enabled,
                primitive: Primitive::Mac(Box::new(DummyMac {
                    name: "1".to_string(),
                })),
                prefix_type: OutputPrefixType::Legacy,
                type_url: "type.url.1".to_string(),
                prefix: vec![0, 0, 18, 214, 111],
            }],
        },
        TestCase {
            _tag: "raw prefix",
            prefix: vec![],
            keys: vec![
                make_test_key(
                    1234543,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Raw,
                    "type.url.1",
                ),
                make_test_key(
                    7213743,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Tink,
                    "type.url.2",
                ),
            ],
            primitives: vec![
                DummyMac {
                    name: "1".to_string(),
                },
                DummyMac {
                    name: "2".to_string(),
                },
            ],
            want: vec![Entry {
                key_id: 1234543,
                status: KeyStatusType::Enabled,
                primitive: Primitive::Mac(Box::new(DummyMac {
                    name: "1".to_string(),
                })),
                prefix_type: OutputPrefixType::Raw,
                type_url: "type.url.1".to_string(),
                prefix: vec![],
            }],
        },
        TestCase {
            _tag: "tink prefix  multiple entries",
            prefix: vec![1, 0, 18, 214, 111], // TINK_PREFIX + 1234543
            keys: vec![
                make_test_key(
                    1234543,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Tink,
                    "type.url.1",
                ),
                make_test_key(
                    1234543,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Tink,
                    "type.url.2",
                ),
                make_test_key(
                    1234543,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Raw,
                    "type.url.3",
                ),
                make_test_key(
                    7213743,
                    KeyStatusType::Enabled,
                    OutputPrefixType::Tink,
                    "type.url.4",
                ),
            ],
            primitives: vec![
                DummyMac {
                    name: "1".to_string(),
                },
                DummyMac {
                    name: "2".to_string(),
                },
                DummyMac {
                    name: "3".to_string(),
                },
                DummyMac {
                    name: "4".to_string(),
                },
            ],
            want: vec![
                Entry {
                    key_id: 1234543,
                    status: KeyStatusType::Enabled,
                    primitive: Primitive::Mac(Box::new(DummyMac {
                        name: "1".to_string(),
                    })),
                    prefix_type: OutputPrefixType::Tink,
                    type_url: "type.url.1".to_string(),
                    prefix: vec![1, 0, 18, 214, 111],
                },
                Entry {
                    key_id: 1234543,
                    status: KeyStatusType::Enabled,
                    primitive: Primitive::Mac(Box::new(DummyMac {
                        name: "2".to_string(),
                    })),
                    prefix_type: OutputPrefixType::Tink,
                    type_url: "type.url.2".to_string(),
                    prefix: vec![1, 0, 18, 214, 111],
                },
            ],
        },
    ] {
        let mut ps = tink_core::primitiveset::PrimitiveSet::new();
        for i in 0..tc.keys.len() {
            ps.add(Primitive::Mac(tc.primitives[i].box_clone()), &tc.keys[i])
                .unwrap();
        }
        let got = ps.entries_for_prefix(&tc.prefix);
        check_equal(&got, &tc.want);
    }
}

#[test]
fn test_primitiveset_add_with_invalid_input() {
    let mut ps = tink_core::primitiveset::PrimitiveSet::new();
    struct TestCase {
        _tag: &'static str,
        primitive: DummyMac,
        key: Key,
    }
    for tc in vec![
        TestCase {
            _tag: "unknown prefix type",
            primitive: DummyMac {
                name: "".to_string(),
            },
            key: make_test_key(
                0,
                KeyStatusType::Enabled,
                OutputPrefixType::UnknownPrefix,
                "type.url.1",
            ),
        },
        TestCase {
            _tag: "disabled key",
            primitive: DummyMac {
                name: "".to_string(),
            },
            key: make_test_key(
                0,
                KeyStatusType::Disabled,
                OutputPrefixType::Tink,
                "type.url.1",
            ),
        },
        TestCase {
            _tag: "nil key_data",
            primitive: DummyMac {
                name: "".to_string(),
            },
            key: Key {
                key_data: None,
                status: KeyStatusType::Enabled as i32,
                output_prefix_type: OutputPrefixType::Tink as i32,
                key_id: 0,
            },
        },
    ] {
        let result = ps.add(Primitive::Mac(Box::new(tc.primitive)), &tc.key);
        assert!(result.is_err());
    }
}
