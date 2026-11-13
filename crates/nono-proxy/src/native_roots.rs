//! The host's trust store, loaded once per process.
//!
//! Three places need the OS trust store: the route store's per-route TLS
//! connectors, the proxy server's shared upstream connector, and the TLS
//! intercept trust bundle written for the sandboxed child. Loading it is
//! slow on macOS (each call walks the keychains and their trust settings,
//! about 0.2 s), so it is loaded here once and shared.
//!
//! What each caller trusts is unchanged:
//!
//! * [`base_root_store`]: webpki roots plus every native cert rustls can
//!   parse, as the route store and the server built it. A route with its own
//!   `tls_ca` clones it and adds that CA; every other caller shares it.
//! * [`native_roots`]: the native certs as loaded, for the intercept bundle,
//!   which writes them out as PEM and refuses to write a bundle when none
//!   loaded.
//!
//! `rustls-native-certs` reads `SSL_CERT_FILE` and `SSL_CERT_DIR` when they
//! are set. nono never changes its own environment after startup, so a
//! second load in the same process would read the same sources.

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

static NATIVE_ROOTS: OnceLock<NativeRoots> = OnceLock::new();
static BASE_ROOT_STORE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();

/// The OS trust store, loaded on first use.
pub(crate) fn native_roots() -> &'static NativeRoots {
    NATIVE_ROOTS.get_or_init(|| {
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

/// Webpki roots plus the OS trust store, built on first use.
pub(crate) fn base_root_store() -> Arc<rustls::RootCertStore> {
    Arc::clone(BASE_ROOT_STORE.get_or_init(|| Arc::new(root_store_from(native_roots()))))
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
    fn native_roots_load_once() {
        assert!(std::ptr::eq(native_roots(), native_roots()));
    }

    #[test]
    fn base_root_store_is_shared() {
        assert!(Arc::ptr_eq(&base_root_store(), &base_root_store()));
    }

    #[test]
    fn base_root_store_matches_a_fresh_build() {
        // The shared store holds exactly what each caller used to build for
        // itself: webpki roots plus the native certs that parse.
        let mut fresh = rustls::RootCertStore::empty();
        fresh.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = fresh.add(cert);
        }
        let shared = base_root_store();
        assert_eq!(shared.roots, fresh.roots);
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
