//! WebSocket TLS policy on the caller's already-bound direct TCP socket.
//!
//! Own the Mozilla roots explicitly so the WebSocket adapter does not pull an
//! obsolete root compatibility crate into the dependency graph. Certificate,
//! hostname and time verification remain Rustls defaults; relay TLS keeps its
//! separate system-root policy.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::client::{Request, Response};
use tokio_tungstenite::tungstenite::{error::TlsError, Error};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

type Handshake = (WebSocketStream<MaybeTlsStream<TcpStream>>, Response);

pub(super) async fn handshake(
    request: Request,
    stream: TcpStream,
) -> Result<Handshake, Box<Error>> {
    let mut roots = RootCertStore::empty();
    if request.uri().scheme_str() == Some("wss") {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    handshake_with_roots(request, stream, roots).await
}

fn client_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    // Retain a process-selected provider; otherwise the existing dependency
    // graph uses ring. An explicit fallback avoids an ambiguous-provider panic
    // if another workspace consumer enables a second provider.
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

async fn handshake_with_roots(
    request: Request,
    stream: TcpStream,
    roots: RootCertStore,
) -> Result<Handshake, Box<Error>> {
    let connector = if request.uri().scheme_str() == Some("wss") {
        let config =
            client_config(roots).map_err(|error| Box::new(Error::Tls(TlsError::Rustls(error))))?;
        Connector::Rustls(Arc::new(config))
    } else {
        Connector::Plain
    };
    tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
        .await
        .map_err(Box::new)
}

#[cfg(test)]
mod tests;
