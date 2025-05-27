// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fmt, ops::Deref};

use tls_codec::{
    DeserializeBytes, Error, Serialize, Size, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

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

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, TlsSize, TlsSerialize, TlsDeserializeBytes,
)]
pub struct TlsPair<
    K: std::fmt::Debug + Serialize + DeserializeBytes,
    V: std::fmt::Debug + Serialize + DeserializeBytes,
> {
    k: K,
    v: V,
}

pub mod btreemap {
    use std::collections::BTreeMap;
    use tls_codec::{DeserializeBytes, Serialize, Size};

    use super::TlsPair;

    pub fn tls_serialize<K, V, W: std::io::Write>(
        v: &BTreeMap<K, V>,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error>
    where
        K: std::fmt::Debug + Clone + Serialize + DeserializeBytes,
        V: std::fmt::Debug + Clone + Serialize + DeserializeBytes,
    {
        let vec = v
            .iter()
            .map(|(k, v)| TlsPair {
                k: k.clone(),
                v: v.clone(),
            })
            .collect::<Vec<_>>();
        vec.tls_serialize(writer)
    }
    pub fn tls_deserialize_bytes<K, V>(
        bytes: &[u8],
    ) -> Result<(BTreeMap<K, V>, &[u8]), tls_codec::Error>
    where
        K: std::fmt::Debug + Clone + Serialize + DeserializeBytes + Ord,
        V: std::fmt::Debug + Clone + Serialize + DeserializeBytes,
    {
        let (val, rest) = <Vec<TlsPair<K, V>>>::tls_deserialize_bytes(bytes)?;
        let btreemap = val
            .into_iter()
            .map(|p| (p.k, p.v))
            .collect::<BTreeMap<K, V>>();
        Ok((btreemap, rest))
    }
    pub fn tls_serialized_len<K, V>(v: &BTreeMap<K, V>) -> usize
    where
        K: std::fmt::Debug + Clone + Serialize + DeserializeBytes,
        V: std::fmt::Debug + Clone + Serialize + DeserializeBytes,
    {
        let vec = v
            .iter()
            .map(|(k, v)| TlsPair {
                k: k.clone(),
                v: v.clone(),
            })
            .collect::<Vec<_>>();
        vec.tls_serialized_len()
    }
}
