use super::toml::{ConfigToml, ConfigTomlExt};
use crate::error::{anyhow, ensure};
use ahash::HashMap;
use clap::Arg;
use hot_reload::{ReloaderReceiver, ReloaderService};
use rpxy_certs::{CryptoFileSourceBuilder, CryptoReloader, ServerCryptoBase, build_cert_reloader};
use rpxy_lib::{AppConfigList, ProxyConfig};
use std::path::PathBuf;

#[cfg(feature = "acme")]
use rpxy_acme::{ACME_DIR_URL, AcmeManager};

/// Resolve a path against data_dir.
/// If path is absolute, return as-is. Otherwise, join with data_dir.
fn resolve_path_against_data_dir(path: &str, data_dir: &str) -> PathBuf {
  let p = PathBuf::from(path);
  if p.is_absolute() {
    p
  } else {
    PathBuf::from(data_dir).join(p)
  }
}

/// Parsed options from CLI
/// Options for configuring the application.
///
/// # Fields
/// - `config_file_path`: Path to the configuration file.
/// - `log_dir_path`: Optional path to the log directory.
pub struct Opts {
  pub config_file_path: String,
  pub log_dir_path: Option<String>,
}

/// Parses command-line arguments into an [`Opts`](rpxy-bin/src/config/parse.rs:13) struct.
///
/// Returns a populated [`Opts`](rpxy-bin/src/config/parse.rs:13) on success, or an error if parsing fails.
/// Expects a required `--config` argument and an optional `--log-dir` argument.
pub fn parse_opts() -> Result<Opts, anyhow::Error> {
  let _ = include_str!("../../Cargo.toml");
  let options = clap::command!()
    .arg(
      Arg::new("config_file")
        .long("config")
        .short('c')
        .value_name("FILE")
        .required(true)
        .help("Configuration file path like ./config.toml"),
    )
    .arg(
      Arg::new("log_dir")
        .long("log-dir")
        .short('l')
        .value_name("LOG_DIR")
        .help("Directory for log files. If not specified, logs are printed to stdout."),
    );
  let matches = options.get_matches();

  let config_file_path = matches.get_one::<String>("config_file").unwrap().to_owned();
  let log_dir_path = matches.get_one::<String>("log_dir").map(|v| v.to_owned());

  Ok(Opts {
    config_file_path,
    log_dir_path,
  })
}

/// Build proxy and app settings from config using ConfigTomlExt
pub fn build_settings(config: &ConfigToml) -> Result<(ProxyConfig, AppConfigList), anyhow::Error> {
  config.validate_and_build_settings()
}

/* ----------------------- */

/// Helper to build a CryptoFileSource for an app, handling ACME if enabled
#[cfg(feature = "acme")]
fn build_tls_for_app_acme(
  tls: &mut super::toml::TlsOption,
  acme_option: &Option<super::toml::AcmeOption>,
  server_name: &str,
  acme_registry_path: &str,
  acme_dir_url: &str,
) -> Result<(), anyhow::Error> {
  if let Some(true) = tls.acme {
    ensure!(acme_option.is_some() && tls.tls_cert_key_path.is_none() && tls.tls_cert_path.is_none());
    let subdir = format!("{}/{}", acme_registry_path, server_name.to_ascii_lowercase());
    let file_name =
      rpxy_acme::DirCache::cached_cert_file_name(&[server_name.to_ascii_lowercase()], acme_dir_url.to_ascii_lowercase());
    let cert_path = format!("{}/{}", subdir, file_name);
    tls.tls_cert_key_path = Some(cert_path.clone());
    tls.tls_cert_path = Some(cert_path);
  }
  Ok(())
}

/// Build cert map
/// Builds the certificate manager for TLS applications.
///
/// # Arguments
/// * `config` - Reference to the parsed configuration.
///
/// # Returns
/// Returns an option containing a tuple of certificate reloader service and receiver, or `None` if TLS is not enabled.
/// Returns an error if configuration is invalid or required fields are missing.
pub async fn build_cert_manager(
  config: &ConfigToml,
) -> Result<
  Option<(
    ReloaderService<CryptoReloader, ServerCryptoBase>,
    ReloaderReceiver<ServerCryptoBase>,
  )>,
  anyhow::Error,
> {
  let apps = config.apps.as_ref().ok_or(anyhow!("No apps"))?;
  if config.listen_port_tls.is_none() {
    return Ok(None);
  }

  #[cfg(feature = "acme")]
  let acme_option = config.experimental.as_ref().and_then(|v| v.acme.clone());
  #[cfg(feature = "acme")]
  let acme_dir_url = acme_option
    .as_ref()
    .and_then(|v| v.dir_url.as_deref())
    .unwrap_or(ACME_DIR_URL);

  // Check if any app uses ACME
  #[cfg(feature = "acme")]
  let any_app_uses_acme = apps.0.values().any(|app| {
    app.tls.as_ref().and_then(|t| t.acme).unwrap_or(false)
  });

  // Require data_dir if ACME is used
  #[cfg(feature = "acme")]
  let acme_registry_path = if any_app_uses_acme {
    let data_dir = config.data_dir.as_ref().ok_or_else(|| {
      anyhow!("ACME is enabled but 'data_dir' is not set. Please add to your config:\n  data_dir = \"/var/lib/rpxy\"")
    })?;
    let registry_subpath = acme_option
      .as_ref()
      .and_then(|v| v.registry_path.as_deref())
      .unwrap_or("acme");
    resolve_path_against_data_dir(registry_subpath, data_dir)
      .to_string_lossy()
      .to_string()
  } else {
    // Not used, but need a placeholder for the code below
    String::new()
  };

  let mut crypto_source_map = HashMap::default();
  for app in apps.0.values() {
    if let Some(tls) = app.tls.as_ref() {
      let server_name = app.server_name.as_ref().ok_or(anyhow!("No server name"))?;

      #[cfg(not(feature = "acme"))]
      ensure!(tls.tls_cert_key_path.is_some() && tls.tls_cert_path.is_some());

      #[cfg(feature = "acme")]
      let mut tls = tls.clone();
      #[cfg(feature = "acme")]
      build_tls_for_app_acme(&mut tls, &acme_option, server_name, &acme_registry_path, acme_dir_url)?;

      let crypto_file_source = CryptoFileSourceBuilder::default()
        .tls_cert_path(tls.tls_cert_path.as_ref().unwrap())
        .tls_cert_key_path(tls.tls_cert_key_path.as_ref().unwrap())
        .client_ca_cert_path(tls.client_ca_cert_path.as_deref())
        .build()?;
      crypto_source_map.insert(server_name.to_owned(), crypto_file_source);
    }
  }
  let res = build_cert_reloader(&crypto_source_map, None).await?;
  Ok(Some(res))
}

/* ----------------------- */
#[cfg(feature = "acme")]
/// Build acme manager
/// Builds the ACME manager for automatic certificate management (enabled with the `acme` feature).
///
/// # Arguments
/// * `config` - Reference to the parsed configuration.
/// * `runtime_handle` - Tokio runtime handle for async operations.
///
/// # Returns
/// Returns an option containing an [`AcmeManager`] if ACME is configured, or `None` otherwise.
/// Returns an error if configuration is invalid or required fields are missing.
pub async fn build_acme_manager(
  config: &ConfigToml,
  runtime_handle: tokio::runtime::Handle,
) -> Result<Option<AcmeManager>, anyhow::Error> {
  let acme_option = config.experimental.as_ref().and_then(|v| v.acme.clone());
  let Some(acme_option) = acme_option else {
    return Ok(None);
  };

  let domains: Vec<String> = config
    .apps
    .as_ref()
    .unwrap()
    .0
    .values()
    .filter_map(|app| {
      if let Some(tls) = app.tls.as_ref() {
        if let Some(true) = tls.acme {
          return Some(app.server_name.as_ref().unwrap().to_owned());
        }
      }
      None
    })
    .collect();

  if domains.is_empty() {
    return Ok(None);
  }

  // Require data_dir for ACME
  let data_dir = config.data_dir.as_ref().ok_or_else(|| {
    anyhow!("ACME is enabled but 'data_dir' is not set. Please add to your config:\n  data_dir = \"/var/lib/rpxy\"")
  })?;

  // Resolve registry_path against data_dir
  let registry_subpath = acme_option.registry_path.as_deref().unwrap_or("acme");
  let resolved_registry_path = resolve_path_against_data_dir(registry_subpath, data_dir);

  let acme_manager = AcmeManager::try_new(
    acme_option.dir_url.as_deref(),
    Some(resolved_registry_path.to_string_lossy().as_ref()),
    &[acme_option.email],
    domains.as_slice(),
    runtime_handle,
  )?;

  Ok(Some(acme_manager))
}
