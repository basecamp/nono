//! The host's trust store, loaded once per proxy start.
//!
//! Three places need the OS trust store when a proxy starts: the route
//! store's per-route TLS connectors, the proxy server's shared upstream
//! connector, and the TLS intercept trust bundle written for the sandboxed
//! child. Loading it is slow on macOS (each call walks the keychains and
//! their trust settings, about 0.2 s), so a start takes one [`TrustRoots`]
//! snapshot and hands it to all three.
//!
//! The snapshot belongs to the start that took it: the next start takes its
//! own, so it sees a root added to or removed from the trust store since, and
//! a load that hit errors is tried again. A snapshot loads lazily, on first
//! use, so a start with nothing that needs the trust store never loads it.
//!
//! What each caller trusts is unchanged:
//!
//! * [`TrustRoots::base_root_store`]: webpki roots plus every native cert
//!   rustls can parse, as the route store and the server built it. A route
//!   with its own `tls_ca` clones it and adds that CA; every other caller
//!   shares it.
//! * [`TrustRoots::native`]: the native certs as loaded, for the intercept
//!   bundle, which writes them out as PEM and refuses to write a bundle when
//!   none loaded.

use rustls::pki_types::CertificateDer;
use std::sync::{Arc, OnceLock};
use tracing::debug;

/// The OS trust store as `rustls-native-certs` loaded it.
pub(crate) struct NativeRoots {
    /// Every certificate that loaded, in the order the platform returned them.
    pub(crate) certs: Vec<CertificateDer<'static>>,
    /// How many non-fatal errors the load reported.
    pub(crate) error_count: usize,
}

/// One start's view of the trust store, loaded on first use.
#[derive(Default)]
pub(crate) struct TrustRoots {
    native: OnceLock<NativeRoots>,
    base: OnceLock<Arc<rustls::RootCertStore>>,
}

impl TrustRoots {
    /// A snapshot that has not loaded anything yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The OS trust store, loaded on this snapshot's first use.
    pub(crate) fn native(&self) -> &NativeRoots {
        self.native.get_or_init(|| {
            let loaded = rustls_native_certs::load_native_certs();
            debug!(
                "loaded {} native cert(s) from the system trust store ({} error(s))",
                loaded.certs.len(),
                loaded.errors.len()
            );
            NativeRoots {
                certs: loaded.certs,
                error_count: loaded.errors.len(),
            }
        })
    }

    /// Webpki roots plus this snapshot's OS trust store, built on first use.
    pub(crate) fn base_root_store(&self) -> Arc<rustls::RootCertStore> {
        Arc::clone(
            self.base
                .get_or_init(|| Arc::new(root_store_from(self.native()))),
        )
    }
}

/// Webpki roots plus every cert in `native` that parses.
fn root_store_from(native: &NativeRoots) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in &native.certs {
        if let Err(e) = store.add(cert.clone()) {
            debug!("skipping unparseable native cert: {e}");
        }
    }
    store
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_loads_once() {
        let roots = TrustRoots::new();
        assert!(std::ptr::eq(roots.native(), roots.native()));
        assert!(Arc::ptr_eq(
            &roots.base_root_store(),
            &roots.base_root_store()
        ));
    }

    #[test]
    fn each_snapshot_loads_its_own() {
        // A later start's snapshot is a load of its own, never the earlier
        // one's: it sees the trust store as it is then.
        let first = TrustRoots::new();
        let second = TrustRoots::new();
        assert!(!std::ptr::eq(first.native(), second.native()));
        assert!(!Arc::ptr_eq(
            &first.base_root_store(),
            &second.base_root_store()
        ));
    }

    #[test]
    fn base_root_store_matches_a_fresh_build() {
        // The snapshot's store holds exactly what each caller used to build
        // for itself: webpki roots plus the native certs that parse.
        let mut fresh = rustls::RootCertStore::empty();
        fresh.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = fresh.add(cert);
        }
        assert_eq!(TrustRoots::new().base_root_store().roots, fresh.roots);
    }

    #[test]
    fn root_store_skips_unparseable_native_certs() {
        let native = NativeRoots {
            certs: vec![CertificateDer::from(vec![0x30, 0x00])],
            error_count: 0,
        };
        let store = root_store_from(&native);
        assert_eq!(store.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }
}
