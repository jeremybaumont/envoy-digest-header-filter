pub use self::factory::SampleHttpFilterFactory;

mod config;
mod factory;
mod filter;
mod stats;

use std::{fmt, str::FromStr};
use std::error::Error as StdError;

use ring;
use envoy::host::ByteString;

/// The Error type
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// There was an error parsing a ShaSize
    ParseShaSize,
    /// There was an error parsing a Digest
    ParseDigest,
    /// The digest doesn't match
    InvalidDigest,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            _ => self.description(),
        };

        write!(f, "{}", s)
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParseShaSize => "Failed to parse ShaSize",
            Error::ParseDigest => "Failed to parse Digest",
            Error::InvalidDigest => "Digest does not match Body",
        }
    }
}

/// Defines variants for the size of SHA hash.
///
/// Since this isn't being used for encryption or identification, it doesn't need to be very
/// strong. That said, it's ultimately up to the user of this library, so we provide options for
/// 256, 384, and 512.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShaSize {
    TwoFiftySix,
    ThreeEightyFour,
    FiveTwelve,
}

impl fmt::Display for ShaSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            ShaSize::TwoFiftySix => "SHA-256",
            ShaSize::ThreeEightyFour => "SHA-384",
            ShaSize::FiveTwelve => "SHA-512",
        };

        write!(f, "{}", s)
    }
}

impl FromStr for ShaSize {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s {
            "SHA-256" => ShaSize::TwoFiftySix,
            "SHA-384" => ShaSize::ThreeEightyFour,
            "SHA-512" => ShaSize::FiveTwelve,
            _ => return Err(Error::ParseShaSize),
        };

        Ok(res)
    }
}

/// Defines a wrapper around an &ByteString that can be turned into a `Digest`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestBody<'a>(&'a ByteString);

impl<'a> RequestBody<'a> {
    /// Creates a new `RequestBody` struct from a `&ByteString` representing a plaintext body.
    pub fn new(body: &'a ByteString) -> Self {
        RequestBody(body)
    }

    /// Consumes the `RequestBody`, producing a `Digest`.
    pub fn digest(self, sha_size: ShaSize) -> Digest {
        let size = match sha_size {
            ShaSize::TwoFiftySix => &ring::digest::SHA256,
            ShaSize::ThreeEightyFour => &ring::digest::SHA384,
            ShaSize::FiveTwelve => &ring::digest::SHA512,
        };

        let d = ring::digest::digest(size, self.0);
        let b = base64::encode(&d);

        Digest::from_base64_and_size(ByteString::from(b), sha_size)
    }
}

/// Defines the `Digest` type.
///
/// This type can be compared to another `Digest`, or turned into a `ByteString` for use in request
/// headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    digest: ByteString,
    size: ShaSize,
}

impl Digest {
    /// Creates a new `Digest` from a series of bytes representing a plaintext body and a
    pub fn new(body: &ByteString, size: ShaSize) -> Self {
        RequestBody::new(body).digest(size)
    }

    /// Creates a new `Digest` from a base64-encoded digest `ByteString` and a `ShaSize`.
    pub fn from_base64_and_size(digest: ByteString, size: ShaSize) -> Self {
        Digest { digest, size }
    }

    /// Get the `ShaSize` of the current `Digest`
    pub fn sha_size(&self) -> ShaSize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.digest.is_empty()
    }

    /// Represents the `Digest` as a `ByteString`.
    pub fn as_string(&self) -> ByteString {
        ByteString::from(format!("{}={}", self.size, self.digest))
    }

    /// Verify a given message body with the digest.
    pub fn verify(&self, body: &ByteString) -> Result<(), Error> {
        let digest = Digest::new(body, self.size);

        if *self == digest {
            Ok(())
        } else {
            Err(Error::InvalidDigest)
        }
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let eq_index = s.find('=').ok_or(Error::ParseDigest)?;
        let tup = s.split_at(eq_index);
        let val = tup.1.get(1..).ok_or(Error::ParseDigest)?;

        Ok(Digest {
            digest: ByteString::from(val.to_owned()),
            size: tup.0.parse()?,
        })
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, RequestBody, ShaSize};
    use envoy::host::ByteString;

    const D256: &'static str = "bFp1K/TT36l9YQ8frlh/cVGuWuFEy1rCUNpGwQCSEow=";
    const D384: &'static str = "wOx5d657W3O8k2P7SW18Y/Kj/Rqm02pzgFVBInHOj7hbc0IrYGVXwzid3vTH82um";
    const D512: &'static str =
        "t13li71PxOlxHbZRB3ICZxjwBkYxhellKbMEQjT2udmQRP1fzIrmT49EGy9zNdTS5/JKjxqidsIQBO3i+9DBDQ==";

    #[test]
    fn digest_256() {
        digest(D256.to_owned(), ShaSize::TwoFiftySix);
    }

    #[test]
    fn digest_384() {
        digest(D384.to_owned(), ShaSize::ThreeEightyFour);
    }

    #[test]
    fn digest_512() {
        digest(D512.to_owned(), ShaSize::FiveTwelve);
    }

    #[test]
    fn invalid_digest_256() {
        digest_ne(ShaSize::TwoFiftySix)
    }

    #[test]
    fn invalid_digest_384() {
        digest_ne(ShaSize::ThreeEightyFour)
    }

    #[test]
    fn invalid_digest_512() {
        digest_ne(ShaSize::FiveTwelve)
    }

    #[test]
    fn parse_digest_256() {
        parse_digest(format!("SHA-256={}", D256));
    }

    #[test]
    fn parse_digest_384() {
        parse_digest(format!("SHA-384={}", D384));
    }

    #[test]
    fn parse_digest_512() {
        parse_digest(format!("SHA-512={}", D512));
    }

    #[test]
    fn invalid_parse_digest() {
        parse_digest_ne("not a valid digest");
    }

    #[test]
    fn parse_sha_256() {
        parse_sha("SHA-256");
    }

    #[test]
    fn parse_sha_384() {
        parse_sha("SHA-384");
    }

    #[test]
    fn parse_sha_512() {
        parse_sha("SHA-512");
    }

    #[test]
    fn invalid_parse_sha() {
        parse_sha_ne("SHA-420");
    }

    fn digest(provided: String, sha_size: ShaSize) {
        let some_body = &ByteString::from(b"The content of a thing");
        let body = RequestBody::new(some_body);
        let digest = body.digest(sha_size);

        assert_eq!(Digest::from_base64_and_size(&ByteString::from(provided), sha_size), digest);
    }

    fn digest_ne(sha_size: ShaSize) {
        let some_body = &ByteString::from(b"The content of a thing");
        let body = RequestBody::new(some_body);
        let digest = body.digest(sha_size);

        assert_ne!(
            Digest::from_base64_and_size(&ByteString::from("not a hash".to_owned()), sha_size),
            digest
        );
    }

    fn parse_digest(digest: String) {
        let d = digest.parse::<Digest>();

        assert!(d.is_ok());
    }

    fn parse_digest_ne(digest: &str) {
        let d = digest.parse::<Digest>();

        assert!(d.is_err());
    }

    fn parse_sha(sha: &str) {
        let s = sha.parse::<ShaSize>();

        assert!(s.is_ok());
    }

    fn parse_sha_ne(sha: &str) {
        let s = sha.parse::<ShaSize>();

        assert!(s.is_err());
    }
}
