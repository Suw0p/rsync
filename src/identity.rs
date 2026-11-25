use crate::config::Config;
use anyhow::{Context, Result, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{fs, io::BufReader, path::Path, sync::Arc};

pub fn create(config: &Config) -> Result<String> {
    let ca_key = KeyPair::generate()?;
    // These names are certificate identities, independent of the binary and state
    // directory names. Existing paired certificates must keep their TLS server name.
    let mut ca_params = CertificateParams::new(vec!["sync-ca".to_string()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec!["sync-node".to_string()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    fs::write(config.ca_path(), ca_cert.pem())?;
    fs::write(config.cert_path(), leaf_cert.pem())?;
    fs::write(config.key_path(), leaf_key.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config.key_path(), fs::Permissions::from_mode(0o600))?;
    }
    Ok(hex::encode(blake3::hash(ca_cert.der().as_ref()).as_bytes()))
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        fs::File::open(path).with_context(|| format!("open certificate {}", path.display()))?;
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(file)).collect::<std::io::Result<_>>()?;
    ensure!(!certs.is_empty(), "certificate file is empty");
    Ok(certs)
}

fn key(config: &Config) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(config.key_path())?;
    rustls_pemfile::private_key(&mut BufReader::new(file))?.context("node private key missing")
}

fn roots(config: &Config) -> Result<RootCertStore> {
    let peer = certificates(&config.peer_path())?;
    ensure!(
        peer.len() == 1,
        "peer file must contain exactly one CA certificate"
    );
    let mut roots = RootCertStore::empty();
    roots.add(peer[0].clone())?;
    Ok(roots)
}

pub fn add_peer(config: &Config, cert: &Path, expected: &str) -> Result<()> {
    let pem =
        fs::read_to_string(cert).with_context(|| format!("read certificate {}", cert.display()))?;
    add_peer_pem(config, &pem, expected)
}

pub fn add_peer_pem(config: &Config, pem: &str, expected: &str) -> Result<()> {
    ensure!(pem.len() <= 8 * 1024, "peer certificate is too large");
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<std::io::Result<_>>()?;
    ensure!(
        certs.len() == 1,
        "peer file must contain exactly one CA certificate"
    );
    let actual = hex::encode(blake3::hash(certs[0].as_ref()).as_bytes());
    ensure!(
        actual.eq_ignore_ascii_case(expected),
        "fingerprint mismatch: got {actual}"
    );
    let own = certificates(&config.ca_path())?;
    ensure!(
        own[0].as_ref() != certs[0].as_ref(),
        "cannot trust self as peer"
    );
    let mut store = RootCertStore::empty();
    store
        .add(certs[0].clone())
        .context("peer certificate is not a valid CA")?;
    let tmp = config.private_path().join("peer-ca.pem.tmp");
    fs::write(&tmp, pem)?;
    fs::rename(tmp, config.peer_path())?;
    Ok(())
}

pub fn ca_fingerprint(config: &Config) -> Result<String> {
    let certs = certificates(&config.ca_path())?;
    ensure!(certs.len() == 1, "node CA must contain one certificate");
    Ok(hex::encode(blake3::hash(certs[0].as_ref()).as_bytes()))
}

pub fn require_peer(config: &Config) -> Result<()> {
    ensure!(
        config.peer_path().is_file(),
        "peer is not configured; run peer-add"
    );
    Ok(())
}

pub fn client_config(config: &Config) -> Result<Arc<ClientConfig>> {
    let certs = certificates(&config.cert_path())?;
    let c = ClientConfig::builder()
        .with_root_certificates(roots(config)?)
        .with_client_auth_cert(certs, key(config)?)?;
    Ok(Arc::new(c))
}

pub fn server_config(config: &Config) -> Result<Arc<ServerConfig>> {
    let certs = certificates(&config.cert_path())?;
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(config)?)).build()?;
    let s = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key(config)?)?;
    Ok(Arc::new(s))
}
