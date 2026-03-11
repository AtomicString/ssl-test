use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rcgen::CertifiedKey;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::{io, net::TcpListener};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> io::Result<()> {
    tokio::spawn(async {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let listener: TcpListener = TcpListener::bind(addr).await.unwrap();
        println!("HTTP listening on http://{addr}");

        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(hello_service);
                if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                    eprintln!("[HTTP:{peer}] error: {err}");
                }
            });
        }
    });

    let tls_acceptor = build_tls_acceptor_self_signed()?;
    let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    println!("HTTPS listening on https://{addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);

                    let svc = service_fn(hello_service);

                    if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                        eprintln!("[HTTPS:{peer}] error: {err}");
                    }
                }
                Err(e) => eprintln!("[ACCEPT:{peer}] TLS handshake error: {e}"),
            }
        });
    }
}

async fn hello_service(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = Full::from(Bytes::from_static(b"Hello from hyper over (T)LS\n"));
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )
        .body(body)
        .unwrap();
    Ok(resp)
}

fn build_tls_acceptor_self_signed() -> io::Result<TlsAcceptor> {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(to_io)?;
    let cert_der = cert.der().clone();
    let key_der = signing_key.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let priv_key = PrivateKeyDer::Pkcs8(key_der.into());

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)
        .map_err(to_io)?;

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
