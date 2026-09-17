//! IP to Autonomous System (AS) lookups.
//!
//! IP to ASN lookups are done locally with an asmap file in Bitcoin Core's
//! binary format (see <https://github.com/bitcoin-core/asmap-data>). ASN to
//! AS name lookups use a dataset embedded at compile time. Neither requires
//! network access.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;

/// Maps IP addresses to Autonomous System Numbers (ASNs) using an asmap file.
#[derive(Debug)]
pub struct AsnLookup {
    asmap: asmap::Asmap,
}

impl AsnLookup {
    /// Loads and validates an asmap file in Bitcoin Core's binary format.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let asmap = asmap::Asmap::from_file(path)
            .with_context(|| format!("loading asmap file {}", path.display()))?;
        Ok(Self { asmap })
    }

    /// Size of the loaded asmap in bytes.
    pub fn len(&self) -> usize {
        self.asmap.as_bytes().len()
    }

    /// Returns true if the loaded asmap is empty. Never true for a validated asmap.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Looks up the ASN for an IP address string (without port and brackets, as
    /// returned by [`crate::util::ip_from_ipport`]).
    ///
    /// Returns `None` if `ip` is not an IPv4 or IPv6 literal (e.g. Tor or I2P
    /// addresses) or if the address is not mapped in the asmap (ASN 0).
    pub fn lookup(&self, ip: &str) -> Option<u32> {
        let addr: IpAddr = ip.parse().ok()?;
        match self.asmap.lookup(addr) {
            0 => None,
            asn => Some(asn),
        }
    }
}

/// Returns a human-readable name for an ASN, e.g. "Hetzner Online GmbH" for
/// AS24940. Falls back to "AS<asn>" if the ASN is not in the embedded dataset,
/// so the name stays unique per ASN.
pub fn as_name(asn: u32) -> String {
    match asinfo::lookup(asn) {
        Some(info) => info.description.to_string(),
        None => format!("AS{asn}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The test asmap maps 250.0.0.0/8 to AS1000 and 101.N.0.0/16 to ASN for N in 1..=8.
    fn test_asmap_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/fixtures/asmap-test.raw")
    }

    fn lookup() -> AsnLookup {
        AsnLookup::from_file(&test_asmap_path()).unwrap()
    }

    #[test]
    fn test_from_file_ok() {
        let l = lookup();
        assert_eq!(l.len(), 59);
        assert!(!l.is_empty());
    }

    #[test]
    fn test_from_file_missing() {
        let err = AsnLookup::from_file(Path::new("/nonexistent/asmap.dat")).unwrap_err();
        assert!(err.to_string().contains("/nonexistent/asmap.dat"));
    }

    #[test]
    fn test_from_file_garbage() {
        let path = std::env::temp_dir().join(format!("asn-garbage-{}.dat", std::process::id()));
        std::fs::write(&path, [0xFFu8; 64]).unwrap();
        let result = AsnLookup::from_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_mapped_ipv4() {
        let l = lookup();
        assert_eq!(l.lookup("101.3.0.1"), Some(3));
        assert_eq!(l.lookup("101.8.255.255"), Some(8));
        assert_eq!(l.lookup("250.1.2.3"), Some(1000));
    }

    #[test]
    fn test_lookup_unmapped_ipv4() {
        let l = lookup();
        assert_eq!(l.lookup("8.8.8.8"), None);
        assert_eq!(l.lookup("127.0.0.1"), None);
    }

    #[test]
    fn test_lookup_ipv6() {
        let l = lookup();
        // IPv4-mapped IPv6 addresses resolve like the IPv4 address.
        assert_eq!(l.lookup("::ffff:250.0.0.1"), Some(1000));
        // Native IPv6 is not mapped in the test asmap.
        assert_eq!(l.lookup("2001:db8::1"), None);
    }

    #[test]
    fn test_lookup_not_an_ip() {
        let l = lookup();
        assert_eq!(l.lookup("abcdefghijklmnop.onion"), None);
        assert_eq!(l.lookup("abcdefghijklmnop.b32.i2p"), None);
        assert_eq!(l.lookup(""), None);
        // ip:port combinations are expected to be split with util::ip_from_ipport first.
        assert_eq!(l.lookup("250.0.0.1:8333"), None);
    }

    #[test]
    fn test_as_name() {
        assert_eq!(as_name(1), "Level 3 Parent LLC");
        assert_eq!(as_name(24940), "Hetzner Online GmbH");
        assert_eq!(as_name(u32::MAX), "AS4294967295");
    }
}
