// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fmt, ops::Deref};

use tls_codec::{DeserializeBytes, Error, Serialize, Size};

pub mod bool {
    use tls_codec::{DeserializeBytes, Serialize};

    pub fn tls_serialize<W: std::io::Write>(
        v: &bool,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        (*v as u8).to_be_bytes().tls_serialize(writer)
    }
    pub fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(bool, &[u8]), tls_codec::Error> {
        let (boolval, rest) = <u8>::tls_deserialize_bytes(bytes)?;
        let bool = boolval != 0;
        Ok((bool, rest))
    }
    pub fn tls_serialized_len(_: &bool) -> usize {
        1
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TlsStr<'a>(pub &'a str);

impl Size for TlsStr<'_> {
    fn tls_serialized_len(&self) -> usize {
        self.0.as_bytes().tls_serialized_len()
    }
}

impl Serialize for TlsStr<'_> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.as_bytes().tls_serialize(writer)
    }
}

#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
pub struct TlsString(pub String);

impl Deref for TlsString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for TlsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Size for TlsString {
    fn tls_serialized_len(&self) -> usize {
        TlsStr(&self.0).tls_serialized_len()
    }
}

impl DeserializeBytes for TlsString {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (string, rest) = <Vec<u8>>::tls_deserialize_bytes(bytes)?;
        let string = String::from_utf8(string)
            .map_err(|_| Error::DecodingError("Couldn't decode string.".to_owned()))?;
        Ok((Self(string), rest))
    }
}

impl Serialize for TlsString {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        TlsStr(&self.0).tls_serialize(writer)
    }
}

pub mod btreemap {
    use std::{collections::BTreeMap, io};
    use tls_codec::{
        vlen::{read_length, write_length},
        DeserializeBytes, Serialize, Size,
    };

    pub fn tls_serialized_len<K, V>(v: &BTreeMap<K, V>) -> usize
    where
        K: Size,
        V: Size,
    {
        let content_len = v
            .iter()
            .map(|(k, v)| k.tls_serialized_len() + v.tls_serialized_len())
            .sum();
        let len_len = write_length(&mut io::empty(), content_len).unwrap_or(0);
        content_len + len_len
    }

    pub fn tls_serialize<K, V, W>(
        v: &BTreeMap<K, V>,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error>
    where
        K: Serialize,
        V: Serialize,
        W: io::Write,
    {
        // We need to pre-compute the length of the content.
        // This requires more computations but the other option would be to buffer
        // the entire content, which can end up requiring a lot of memory.
        let content_length = v
            .iter()
            .map(|(k, v)| k.tls_serialized_len() + v.tls_serialized_len())
            .sum();
        let len_len = write_length(writer, content_length)?;

        // Serialize the elements
        #[cfg(debug_assertions)]
        let mut written = 0;
        for (k, v) in v.iter() {
            #[cfg(debug_assertions)]
            {
                written += k.tls_serialize(writer)?;
                written += v.tls_serialize(writer)?;
            }
            #[cfg(not(debug_assertions))]
            {
                k.tls_serialize(writer)?;
                v.tls_serialize(writer)?;
            }
        }
        #[cfg(debug_assertions)]
        if written != content_length {
            return Err(tls_codec::Error::LibraryError);
        }

        Ok(content_length + len_len)
    }

    pub fn tls_deserialize_bytes<K, V>(
        mut bytes: &[u8],
    ) -> Result<(BTreeMap<K, V>, &[u8]), tls_codec::Error>
    where
        K: DeserializeBytes + Ord,
        V: DeserializeBytes,
    {
        let (len, len_len) = read_length(&mut bytes)?;
        if len == 0 {
            return Ok((BTreeMap::new(), bytes));
        }

        let mut result = BTreeMap::new();
        let mut read = len_len;
        while (read - len_len) < len {
            let (key, key_remainder) = K::tls_deserialize_bytes(bytes)?;
            bytes = key_remainder;
            read += key.tls_serialized_len();

            let (value, value_remainder) = V::tls_deserialize_bytes(bytes)?;
            bytes = value_remainder;
            read += value.tls_serialized_len();

            result.insert(key, value);
        }
        Ok((result, bytes))
    }

    #[cfg(test)]
    mod tests {
        use crate::tls::TlsString;

        use super::*;

        #[test]
        fn test_tls_serde_empty_btreemap() {
            let map: BTreeMap<u64, TlsString> = Default::default();

            let mut buf = Vec::new();
            let len = tls_serialize(&map, &mut buf).unwrap();
            assert_eq!(len, 1);
            let (map2, remainder) = tls_deserialize_bytes(&buf).unwrap();
            assert_eq!(map, map2);
            assert_eq!(remainder.len(), 0);
        }

        #[test]
        fn test_tls_serde_btreemap() {
            let mut map: BTreeMap<u64, TlsString> = Default::default();
            map.insert(1u64, TlsString("hello".to_owned()));
            map.insert(3u64, TlsString("world".to_owned()));

            let mut buf = Vec::new();
            let len = tls_serialize(&map, &mut buf).unwrap();
            // varint(4) + 1 + len("hello") + bytes("hello") + 3 + len("world") + bytes("world")
            // 1 + 8 + 1 + 5 + 8 + 1 + 5
            assert_eq!(len, 29);
            let (map2, remainder) = tls_deserialize_bytes(&buf).unwrap();
            assert_eq!(map, map2);
            assert_eq!(remainder.len(), 0);
        }
    }
}
