use super::*;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{CertificateError, ServerConfig};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

const LIMIT: Duration = Duration::from_secs(3);

fn identity(host: &str, from: i32, until: i32) -> (CertificateDer<'static>, ServerConfig) {
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
    params.not_before = rcgen::date_time_ymd(from, 1, 1);
    params.not_after = rcgen::date_time_ymd(until, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
    (der, config)
}

fn trusted(cert: CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    roots
}

fn request(port: u16) -> Request {
    let mut request = format!("wss://localhost:{port}/api/v1/signals/ws")
        .into_client_request()
        .unwrap();
    for (key, value) in [
        (AUTHORIZATION.as_str(), "Bearer tls-test-token"),
        (
            SEC_WEBSOCKET_PROTOCOL.as_str(),
            super::super::SIGNAL_WS_PROTOCOL,
        ),
        ("x-p2wlan-room-roster-wake", "1"),
        ("x-p2wlan-registration-seq", "37"),
    ] {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    request
}

async fn direct_stream(port: u16) -> TcpStream {
    p2pnet_netbind::connect_tcp_host("127.0.0.1", port, None)
        .await
        .unwrap()
}

struct ExpectedHeaders(u16);

impl tokio_tungstenite::tungstenite::handshake::server::Callback for ExpectedHeaders {
    fn on_request(
        self,
        request: &Request,
        mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        assert_eq!(request.uri().path(), "/api/v1/signals/ws");
        for name in [
            AUTHORIZATION.as_str(),
            SEC_WEBSOCKET_PROTOCOL.as_str(),
            "x-p2wlan-room-roster-wake",
            "x-p2wlan-registration-seq",
        ] {
            assert_eq!(
                request.headers()[name],
                self::request(self.0).headers()[name]
            );
        }
        response.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(super::super::SIGNAL_WS_PROTOCOL),
        );
        Ok(response)
    }
}

#[tokio::test]
async fn trusted_tls_preserves_bound_socket_headers_protocol_and_frames() {
    let (cert, config) = identity("localhost", 2020, 2040);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        let mut socket = tokio_tungstenite::accept_hdr_async(stream, ExpectedHeaders(port))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("bounded-frame".into())
        );
        socket.send(Message::Text("received".into())).await.unwrap();
    };
    let client = async {
        let tcp = direct_stream(port).await;
        let local = tcp.local_addr().unwrap();
        let (mut socket, response) = handshake_with_roots(request(port), tcp, trusted(cert))
            .await
            .unwrap();
        match socket.get_ref() {
            MaybeTlsStream::Rustls(tls) => assert_eq!(tls.get_ref().0.local_addr().unwrap(), local),
            _ => panic!("wss must negotiate TLS on the original TCP socket"),
        }
        assert_eq!(
            response.headers()[SEC_WEBSOCKET_PROTOCOL],
            super::super::SIGNAL_WS_PROTOCOL
        );
        socket
            .send(Message::Text("bounded-frame".into()))
            .await
            .unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("received".into())
        );
    };
    timeout(LIMIT, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

async fn rejected_tls(host: &str, from: i32, until: i32, mozilla_policy: bool) -> CertificateError {
    let (cert, config) = identity(host, from, until);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .is_err());
    };
    let client = async {
        let tcp = direct_stream(port).await;
        let result = if mozilla_policy {
            handshake(request(port), tcp).await
        } else {
            handshake_with_roots(request(port), tcp, trusted(cert)).await
        };
        let Error::Io(error) = *result.unwrap_err() else {
            panic!("expected a TLS I/O certificate rejection")
        };
        match error
            .get_ref()
            .unwrap()
            .downcast_ref::<rustls::Error>()
            .unwrap()
        {
            rustls::Error::InvalidCertificate(reason) => reason.clone(),
            other => panic!("unexpected TLS error: {other:?}"),
        }
    };
    let (_, reason) = timeout(LIMIT, async { tokio::join!(server, client) })
        .await
        .unwrap();
    reason
}

#[tokio::test]
async fn production_mozilla_roots_reject_untrusted_certificate() {
    assert!(matches!(
        rejected_tls("localhost", 2020, 2040, true).await,
        CertificateError::UnknownIssuer
    ));
}

#[tokio::test]
async fn trusted_tls_rejects_wrong_hostname() {
    assert!(matches!(
        rejected_tls("wrong.invalid", 2020, 2040, false).await,
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
    ));
}

#[tokio::test]
async fn trusted_tls_rejects_expired_certificate() {
    assert!(matches!(
        rejected_tls("localhost", 2000, 2001, false).await,
        CertificateError::Expired | CertificateError::ExpiredContext { .. }
    ));
}

#[tokio::test]
async fn trusted_tls_rejects_not_yet_valid_certificate() {
    assert!(matches!(
        rejected_tls("localhost", 2090, 2091, false).await,
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
    ));
}

#[tokio::test]
async fn production_plain_ws_keeps_original_socket_without_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(tcp).await.unwrap();
        socket
            .send(Message::Text("plain-ready".into()))
            .await
            .unwrap();
    };
    let client = async {
        let tcp = direct_stream(port).await;
        let local = tcp.local_addr().unwrap();
        let req = format!("ws://localhost:{port}/api/v1/signals/ws")
            .into_client_request()
            .unwrap();
        let (mut socket, _) = handshake(req, tcp).await.unwrap();
        match socket.get_ref() {
            MaybeTlsStream::Plain(stream) => assert_eq!(stream.local_addr().unwrap(), local),
            _ => panic!("ws must retain the original plain TCP stream"),
        }
        assert_eq!(
            socket.next().await.unwrap().unwrap(),
            Message::Text("plain-ready".into())
        );
    };
    timeout(LIMIT, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}
