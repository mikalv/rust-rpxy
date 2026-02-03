use thiserror::Error;

#[derive(Error, Debug)]
/// Error type for rpxy-acme
pub enum RpxyAcmeError {
  /// Missing or invalid acme registry path
  #[error("ACME registry path is required. Configure 'data_dir' in your config file.")]
  InvalidAcmeRegistryPath,
  /// Invalid url
  #[error("Invalid url: {0}")]
  InvalidUrl(#[from] url::ParseError),
  /// IO error
  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),
  /// TLS client configuration error
  #[error("TLS client configuration error: {0}")]
  TlsClientConfig(String),
  /// Write permission error - cannot write certificates to the specified path
  #[error("Cannot write certificates for domain '{domain}' to '{path}': {source}")]
  WritePermissionDenied {
    domain: String,
    path: String,
    source: std::io::Error,
  },
}
