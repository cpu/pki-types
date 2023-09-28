//! This crate provides types for representing X.509 certificates, keys and other types as
//! commonly used in the rustls ecosystem. It is intended to be used by crates that need to work
//! with such X.509 types, such as [rustls](https://crates.io/crates/rustls),
//! [rustls-webpki](https://crates.io/crates/rustls-webpki),
//! [rustls-pemfile](https://crates.io/crates/rustls-pemfile), and others.
//!
//! Some of these crates used to define their own trivial wrappers around DER-encoded bytes.
//! However, in order to avoid inconvenient dependency edges, these were all disconnected. By
//! using a common low-level crate of types with long-term stable API, we hope to avoid the
//! downsides of unnecessary dependency edges while providing good interoperability between crates.
//!
//! ## DER and PEM
//!
//! Many of the types defined in this crate represent DER-encoded data. DER is a binary encoding of
//! the ASN.1 format commonly used in web PKI specifications. It is a binary encoding, so it is
//! relatively compact when stored in memory. However, as a binary format, it is not very easy to
//! work with for humans and in contexts where binary data is inconvenient. For this reason,
//! many tools and protocols use a ASCII-based encoding of DER, called PEM. In addition to the
//! base64-encoded DER, PEM objects are delimited by header and footer lines which indicate the type
//! of object contained in the PEM blob.
//!
//! The [rustls-pemfile](https://docs.rs/rustls-pemfile) crate can be used to parse PEM files.
//!
//! ## Creating new certificates and keys
//!
//! This crate does not provide any functionality for creating new certificates or keys. However,
//! the [rcgen](https://docs.rs/rcgen) crate can be used to create new certificates and keys.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unreachable_pub, clippy::use_self)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::time::Duration;
#[cfg(feature = "std")]
use std::net::IpAddr;
#[cfg(feature = "std")]
use std::time::SystemTime;

/// A DER-encoded X.509 private key, in one of several formats
///
/// See variant inner types for more detailed information.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum PrivateKeyDer<'a> {
    /// An RSA private key
    Pkcs1(PrivatePkcs1KeyDer<'a>),
    /// A Sec1 private key
    Sec1(PrivateSec1KeyDer<'a>),
    /// A PKCS#8 private key
    Pkcs8(PrivatePkcs8KeyDer<'a>),
}

impl<'a> PrivateKeyDer<'a> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_der(&self) -> &[u8] {
        match self {
            PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der(),
            PrivateKeyDer::Sec1(key) => key.secret_sec1_der(),
            PrivateKeyDer::Pkcs8(key) => key.secret_pkcs8_der(),
        }
    }
}

impl<'a> From<PrivatePkcs1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivatePkcs1KeyDer<'a>) -> Self {
        Self::Pkcs1(key)
    }
}

impl<'a> From<PrivateSec1KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivateSec1KeyDer<'a>) -> Self {
        Self::Sec1(key)
    }
}

impl<'a> From<PrivatePkcs8KeyDer<'a>> for PrivateKeyDer<'a> {
    fn from(key: PrivatePkcs8KeyDer<'a>) -> Self {
        Self::Pkcs8(key)
    }
}

/// A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC 3447
///
/// RSA private keys are identified in PEM context as `RSA PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivatePkcs1KeyDer<'a>(Der<'a>);

impl PrivatePkcs1KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_pkcs1_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivatePkcs1KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivatePkcs1KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivatePkcs1KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A Sec1-encoded plaintext private key; as specified in RFC 5915
///
/// Sec1 private keys are identified in PEM context as `EC PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivateSec1KeyDer<'a>(Der<'a>);

impl PrivateSec1KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_sec1_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivateSec1KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivateSec1KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivateSec1KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A DER-encoded plaintext private key; as specified in PKCS#8/RFC 5958
///
/// PKCS#8 private keys are identified in PEM context as `PRIVATE KEY` and when stored in a
/// file usually use a `.pem` or `.key` extension. For more on PEM files, refer to the crate
/// documentation.
#[derive(PartialEq)]
pub struct PrivatePkcs8KeyDer<'a>(Der<'a>);

impl PrivatePkcs8KeyDer<'_> {
    /// Yield the DER-encoded bytes of the private key
    pub fn secret_pkcs8_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a [u8]> for PrivatePkcs8KeyDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der(DerInner::Borrowed(slice)))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for PrivatePkcs8KeyDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der(DerInner::Owned(vec)))
    }
}

impl fmt::Debug for PrivatePkcs8KeyDer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivatePkcs1KeyDer")
            .field(&"[secret key elided]")
            .finish()
    }
}

/// A trust anchor (a.k.a. root CA)
///
/// Traditionally, certificate verification libraries have represented trust anchors as full X.509
/// root certificates. However, those certificates contain a lot more data than is needed for
/// verifying certificates. The [`TrustAnchor`] representation allows an application to store
/// just the essential elements of trust anchors.
#[derive(Clone, Debug, PartialEq)]
pub struct TrustAnchor<'a> {
    /// Value of the `subject` field of the trust anchor
    pub subject: Der<'a>,
    /// Value of the `subjectPublicKeyInfo` field of the trust anchor
    pub subject_public_key_info: Der<'a>,
    /// Value of DER-encoded `NameConstraints`, containing name constraints to the trust anchor, if any
    pub name_constraints: Option<Der<'a>>,
}

impl TrustAnchor<'_> {
    /// Yield a `'static` lifetime of the `TrustAnchor` by allocating owned `Der` variants
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> TrustAnchor<'static> {
        #[cfg(not(feature = "std"))]
        use alloc::borrow::ToOwned;
        TrustAnchor {
            subject: self.subject.as_ref().to_owned().into(),
            subject_public_key_info: self.subject_public_key_info.as_ref().to_owned().into(),
            name_constraints: self
                .name_constraints
                .as_ref()
                .map(|nc| nc.as_ref().to_owned().into()),
        }
    }
}

/// A Certificate Revocation List; as specified in RFC 5280
///
/// Certificate revocation lists are identified in PEM context as `X509 CRL` and when stored in a
/// file usually use a `.crl` extension. For more on PEM files, refer to the crate documentation.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateRevocationListDer<'a>(Der<'a>);

impl AsRef<[u8]> for CertificateRevocationListDer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for CertificateRevocationListDer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for CertificateRevocationListDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der::from(slice))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for CertificateRevocationListDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der::from(vec))
    }
}

/// A DER-encoded X.509 certificate; as specified in RFC 5280
///
/// Certificates are identified in PEM context as `CERTIFICATE` and when stored in a
/// file usually use a `.pem`, `.cer` or `.crt` extension. For more on PEM files, refer to the
/// crate documentation.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateDer<'a>(Der<'a>);

impl AsRef<[u8]> for CertificateDer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for CertificateDer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for CertificateDer<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(Der::from(slice))
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for CertificateDer<'a> {
    fn from(vec: Vec<u8>) -> Self {
        Self(Der::from(vec))
    }
}

/// An abstract signature verification algorithm.
///
/// One of these is needed per supported pair of public key type (identified
/// with `public_key_alg_id()`) and `signatureAlgorithm` (identified with
/// `signature_alg_id()`).  Note that both of these `AlgorithmIdentifier`s include
/// the parameters encoding, so separate `SignatureVerificationAlgorithm`s are needed
/// for each possible public key or signature parameters.
pub trait SignatureVerificationAlgorithm: Send + Sync {
    /// Verify a signature.
    ///
    /// `public_key` is the `subjectPublicKey` value from a `SubjectPublicKeyInfo` encoding
    /// and is untrusted.  The key's `subjectPublicKeyInfo` matches the [`AlgorithmIdentifier`]
    /// returned by `public_key_alg_id()`.
    ///
    /// `message` is the data over which the signature was allegedly computed.
    /// It is not hashed; implementations of this trait function must do hashing
    /// if that is required by the algorithm they implement.
    ///
    /// `signature` is the signature allegedly over `message`.
    ///
    /// Return `Ok(())` only if `signature` is a valid signature on `message`.
    ///
    /// Return `Err(InvalidSignature)` if the signature is invalid, including if the `public_key`
    /// encoding is invalid.  There is no need or opportunity to produce errors
    /// that are more specific than this.
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature>;

    /// Return the `AlgorithmIdentifier` that must equal a public key's
    /// `subjectPublicKeyInfo` value for this `SignatureVerificationAlgorithm`
    /// to be used for signature verification.
    fn public_key_alg_id(&self) -> AlgorithmIdentifier;

    /// Return the `AlgorithmIdentifier` that must equal the `signatureAlgorithm` value
    /// on the data to be verified for this `SignatureVerificationAlgorithm` to be used
    /// for signature verification.
    fn signature_alg_id(&self) -> AlgorithmIdentifier;
}

/// A detail-less error when a signature is not valid.
#[derive(Debug, Copy, Clone)]
pub struct InvalidSignature;

/// A DER encoding of the PKIX AlgorithmIdentifier type:
///
/// ```ASN.1
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL  }
///                                -- contains a value of the type
///                                -- registered for use with the
///                                -- algorithm object identifier value
/// ```
/// (from <https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2>)
///
/// The outer sequence encoding is *not included*, so this is the DER encoding
/// of an OID for `algorithm` plus the `parameters` value.
///
/// For example, this is the `rsaEncryption` algorithm:
///
/// ```
/// let rsa_encryption = rustls_pki_types::AlgorithmIdentifier::from_slice(
///     &[
///         // algorithm: 1.2.840.113549.1.1.1
///         0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
///         // parameters: NULL
///         0x05, 0x00
///     ]
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlgorithmIdentifier(&'static [u8]);

impl AlgorithmIdentifier {
    /// Makes a new `AlgorithmIdentifier` from a static octet slice.
    ///
    /// This does not validate the contents of the slice.
    pub const fn from_slice(bytes: &'static [u8]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for AlgorithmIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl Deref for AlgorithmIdentifier {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

/// A timestamp, tracking the number of non-leap seconds since the Unix epoch.
///
/// The Unix epoch is defined January 1, 1970 00:00:00 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The current time, as a `UnixTime`
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        Self::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(), // Safe: this code did not exist before 1970.
        )
    }

    /// Convert a `Duration` since the start of 1970 to a `UnixTime`
    ///
    /// The `duration` must be relative to the Unix epoch.
    pub fn since_unix_epoch(duration: Duration) -> Self {
        Self(duration.as_secs())
    }

    /// Number of seconds since the Unix epoch
    pub fn as_secs(&self) -> u64 {
        self.0
    }
}

/// DER-encoded data, either owned or borrowed
///
/// This wrapper type is used to represent DER-encoded data in a way that is agnostic to whether
/// the data is owned (by a `Vec<u8>`) or borrowed (by a `&[u8]`). Support for the owned
/// variant is only available when the `alloc` feature is enabled.
#[derive(Clone, PartialEq)]
pub struct Der<'a>(DerInner<'a>);

impl<'a> Der<'a> {
    /// A const constructor to create a `Der` from a borrowed slice
    pub const fn from_slice(der: &'a [u8]) -> Self {
        Self(DerInner::Borrowed(der))
    }
}

impl AsRef<[u8]> for Der<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            #[cfg(feature = "alloc")]
            DerInner::Owned(vec) => vec.as_ref(),
            DerInner::Borrowed(slice) => slice,
        }
    }
}

impl Deref for Der<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a> From<&'a [u8]> for Der<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self(DerInner::Borrowed(slice))
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for Der<'static> {
    fn from(vec: Vec<u8>) -> Self {
        Self(DerInner::Owned(vec))
    }
}

impl fmt::Debug for Der<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Der").field(&self.as_ref()).finish()
    }
}

/// Encodes ways a client can know the expected name of the server.
///
/// This currently covers knowing the DNS name of the server, but
/// will be extended in the future to supporting privacy-preserving names
/// for the server ("ECH").  For this reason this enum is `non_exhaustive`.
///
/// # Making one
///
/// If you have a DNS name as a `&str`, this type implements `TryFrom<&str>`,
/// so you can do:
///
/// ```
/// use rustls_pki_types::ServerName;
/// ServerName::try_from("example.com").expect("invalid DNS name");
///
/// // or, alternatively...
///
/// let x = "example.com".try_into().expect("invalid DNS name");
/// # let _: ServerName = x;
/// ```
#[cfg(all(feature = "std", feature = "alloc"))]
#[non_exhaustive]
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum ServerName {
    /// The server is identified by a DNS name.  The name
    /// is sent in the TLS Server Name Indication (SNI)
    /// extension.
    DnsName(DnsName),

    /// The server is identified by an IP address. SNI is not
    /// done.
    IpAddress(IpAddr),
}

#[cfg(all(feature = "std", feature = "alloc"))]
impl fmt::Debug for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DnsName(d) => f.debug_tuple("DnsName").field(&d.as_ref()).finish(),
            Self::IpAddress(i) => f.debug_tuple("IpAddress").field(i).finish(),
        }
    }
}

#[cfg(all(feature = "std", feature = "alloc"))]
impl ServerName {
    /// Return the name that should go in the SNI extension.
    /// If [`None`] is returned, the SNI extension is not included
    /// in the handshake.
    pub fn for_sni(&self) -> Option<DnsNameRef> {
        match self {
            Self::DnsName(dns_name) => Some(dns_name.borrow()),
            Self::IpAddress(_) => None,
        }
    }
}

/// Attempt to make a ServerName from a string by parsing
/// it as a DNS name.
#[cfg(all(feature = "std", feature = "alloc"))]
impl TryFrom<&str> for ServerName {
    type Error = InvalidDnsNameError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match DnsNameRef::try_from(s) {
            Ok(dns) => Ok(Self::DnsName(dns.to_owned())),
            Err(InvalidDnsNameError) => match s.parse() {
                Ok(ip) => Ok(Self::IpAddress(ip)),
                Err(_) => Err(InvalidDnsNameError),
            },
        }
    }
}

/// A type which encapsulates an owned string that is a syntactically valid DNS name.
#[cfg(feature = "alloc")]
#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub struct DnsName(String);

#[cfg(feature = "alloc")]
impl<'a> DnsName {
    /// Produce a borrowed `DnsNameRef` from this owned `DnsName`.
    pub fn borrow(&'a self) -> DnsNameRef<'a> {
        DnsNameRef(self.as_ref())
    }

    /// Validate the given bytes are a DNS name if they are viewed as ASCII.
    pub fn try_from_ascii(bytes: &[u8]) -> Result<Self, InvalidDnsNameError> {
        // nb. a sequence of bytes that is accepted by `validate()` is both
        // valid UTF-8, and valid ASCII.
        String::from_utf8(bytes.to_vec())
            .map_err(|_| InvalidDnsNameError)
            .and_then(Self::try_from)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<String> for DnsName {
    type Error = InvalidDnsNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate(value.as_bytes())?;
        Ok(Self(value))
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for DnsName {
    fn as_ref(&self) -> &str {
        AsRef::<str>::as_ref(&self.0)
    }
}

/// A type which encapsulates a borrowed string that is a syntactically valid DNS name.
#[derive(Eq, Hash, PartialEq, Debug)]
pub struct DnsNameRef<'a>(&'a str);

impl<'a> DnsNameRef<'a> {
    /// Copy this object to produce an owned `DnsName`.
    #[cfg(feature = "alloc")]
    pub fn to_owned(&'a self) -> DnsName {
        DnsName(self.0.to_string())
    }

    /// Copy this object to produce an owned `DnsName`, smashing the case to lowercase
    /// in one operation.
    #[cfg(feature = "alloc")]
    pub fn to_lowercase_owned(&'a self) -> DnsName {
        DnsName(self.0.to_lowercase())
    }
}

impl<'a> TryFrom<&'a str> for DnsNameRef<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(value: &'a str) -> Result<DnsNameRef<'a>, Self::Error> {
        validate(value.as_bytes())?;
        Ok(DnsNameRef(value))
    }
}

impl<'a> AsRef<str> for DnsNameRef<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The provided input could not be parsed because
/// it is not a syntactically-valid DNS Name.
#[derive(Debug)]
pub struct InvalidDnsNameError;

impl fmt::Display for InvalidDnsNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid dns name")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidDnsNameError {}

fn validate(input: &[u8]) -> Result<(), InvalidDnsNameError> {
    use State::*;
    let mut state = Start;

    /// "Labels must be 63 characters or less."
    const MAX_LABEL_LENGTH: usize = 63;

    /// https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
    const MAX_NAME_LENGTH: usize = 253;

    if input.len() > MAX_NAME_LENGTH {
        return Err(InvalidDnsNameError);
    }

    for ch in input {
        state = match (state, ch) {
            (Start | Next | NextAfterNumericOnly | Hyphen { .. }, b'.') => {
                return Err(InvalidDnsNameError)
            }
            (Subsequent { .. }, b'.') => Next,
            (NumericOnly { .. }, b'.') => NextAfterNumericOnly,
            (Subsequent { len } | NumericOnly { len } | Hyphen { len }, _)
                if len >= MAX_LABEL_LENGTH =>
            {
                return Err(InvalidDnsNameError)
            }
            (Start | Next | NextAfterNumericOnly, b'0'..=b'9') => NumericOnly { len: 1 },
            (NumericOnly { len }, b'0'..=b'9') => NumericOnly { len: len + 1 },
            (Start | Next | NextAfterNumericOnly, b'a'..=b'z' | b'A'..=b'Z' | b'_') => {
                Subsequent { len: 1 }
            }
            (Subsequent { len } | NumericOnly { len } | Hyphen { len }, b'-') => {
                Hyphen { len: len + 1 }
            }
            (
                Subsequent { len } | NumericOnly { len } | Hyphen { len },
                b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9',
            ) => Subsequent { len: len + 1 },
            _ => return Err(InvalidDnsNameError),
        };
    }

    if matches!(
        state,
        Start | Hyphen { .. } | NumericOnly { .. } | NextAfterNumericOnly
    ) {
        return Err(InvalidDnsNameError);
    }

    Ok(())
}

enum State {
    Start,
    Next,
    NumericOnly { len: usize },
    NextAfterNumericOnly,
    Subsequent { len: usize },
    Hyphen { len: usize },
}

#[derive(Clone, PartialEq)]
enum DerInner<'a> {
    #[cfg(feature = "alloc")]
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    static TESTS: &[(&str, bool)] = &[
        ("", false),
        ("localhost", true),
        ("LOCALHOST", true),
        (".localhost", false),
        ("..localhost", false),
        ("1.2.3.4", false),
        ("127.0.0.1", false),
        ("absolute.", true),
        ("absolute..", false),
        ("multiple.labels.absolute.", true),
        ("foo.bar.com", true),
        ("infix-hyphen-allowed.com", true),
        ("-prefixhypheninvalid.com", false),
        ("suffixhypheninvalid--", false),
        ("suffixhypheninvalid-.com", false),
        ("foo.lastlabelendswithhyphen-", false),
        ("infix_underscore_allowed.com", true),
        ("_prefixunderscorevalid.com", true),
        ("labelendswithnumber1.bar.com", true),
        ("xn--bcher-kva.example", true),
        (
            "sixtythreesixtythreesixtythreesixtythreesixtythreesixtythreesix.com",
            true,
        ),
        (
            "sixtyfoursixtyfoursixtyfoursixtyfoursixtyfoursixtyfoursixtyfours.com",
            false,
        ),
        (
            "012345678901234567890123456789012345678901234567890123456789012.com",
            true,
        ),
        (
            "0123456789012345678901234567890123456789012345678901234567890123.com",
            false,
        ),
        (
            "01234567890123456789012345678901234567890123456789012345678901-.com",
            false,
        ),
        (
            "012345678901234567890123456789012345678901234567890123456789012-.com",
            false,
        ),
        ("numeric-only-final-label.1", false),
        ("numeric-only-final-label.absolute.1.", false),
        ("1starts-with-number.com", true),
        ("1Starts-with-number.com", true),
        ("1.2.3.4.com", true),
        ("123.numeric-only-first-label", true),
        ("a123b.com", true),
        ("numeric-only-middle-label.4.com", true),
        ("1000-sans.badssl.com", true),
        ("twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfiftythreecharacters.twohundredandfi", true),
        ("twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourcharacters.twohundredandfiftyfourc", false),
    ];

    #[cfg(feature = "std")]
    #[test]
    fn test_validation() {
        for (input, expected) in TESTS {
            std::println!("test: {:?} expected valid? {:?}", input, expected);
            let name_ref = super::DnsNameRef::try_from(*input);
            assert_eq!(*expected, name_ref.is_ok());
            let name = super::DnsName::try_from(input.to_string());
            assert_eq!(*expected, name.is_ok());
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn error_is_debug() {
        assert_eq!(
            alloc::format!("{:?}", super::InvalidDnsNameError),
            "InvalidDnsNameError"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn error_is_display() {
        assert_eq!(
            alloc::format!("{}", super::InvalidDnsNameError),
            "invalid dns name"
        );
    }

    #[cfg(all(feature = "alloc", feature = "std"))]
    #[test]
    fn dns_name_is_debug() {
        let example = super::DnsName::try_from("example.com".to_string()).unwrap();
        assert_eq!(alloc::format!("{:?}", example), "DnsName(\"example.com\")");
    }

    #[cfg(feature = "std")]
    #[test]
    fn dns_name_traits() {
        let example = super::DnsName::try_from("example.com".to_string()).unwrap();
        assert_eq!(example, example); // PartialEq

        use std::collections::HashSet;
        let mut h = HashSet::<super::DnsName>::new();
        h.insert(example);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn try_from_ascii_rejects_bad_utf8() {
        assert_eq!(
            alloc::format!("{:?}", super::DnsName::try_from_ascii(b"\x80")),
            "Err(InvalidDnsNameError)"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dns_name_ref_is_debug() {
        let example = super::DnsNameRef::try_from("example.com").unwrap();
        assert_eq!(
            alloc::format!("{:?}", example),
            "DnsNameRef(\"example.com\")"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn dns_name_ref_traits() {
        let example = super::DnsNameRef::try_from("example.com").unwrap();
        assert_eq!(example, example); // PartialEq

        use std::collections::HashSet;
        let mut h = HashSet::<super::DnsNameRef>::new();
        h.insert(example);
    }
}
