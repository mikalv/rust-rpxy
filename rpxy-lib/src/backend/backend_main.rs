use crate::{
  AppConfig, AppConfigList,
  error::*,
  log::*,
  name_exp::{ByteName, ServerName},
};
use ahash::HashMap;
use derive_builder::Builder;
use std::borrow::Cow;
use wildcard::Wildcard;

use super::upstream::PathManager;

/// Struct serving information to route incoming connections, like server name to be handled and tls certs/keys settings.
#[derive(Builder)]
pub struct BackendApp {
  #[builder(setter(into))]
  /// backend application name, e.g., app1
  pub app_name: String,
  #[builder(setter(custom))]
  /// server name, e.g., example.com, in [[ServerName]] object
  pub server_name: ServerName,
  /// struct of reverse proxy serving incoming request
  pub path_manager: PathManager,
  /// tls settings: https redirection with 30x
  #[builder(default)]
  pub https_redirection: Option<bool>,
  /// tls settings: mutual TLS is enabled
  #[builder(default)]
  #[allow(unused)]
  pub mutual_tls: Option<bool>,
}
impl<'a> BackendAppBuilder {
  pub fn server_name(&mut self, server_name: impl Into<Cow<'a, str>>) -> &mut Self {
    self.server_name = Some(server_name.to_server_name());
    self
  }
}

#[derive(Default)]
/// HashMap and some meta information for multiple Backend structs.
pub struct BackendAppManager {
  /// HashMap of Backend structs, key is server name
  pub apps: HashMap<ServerName, BackendApp>,
  /// for plaintext http
  pub default_server_name: Option<ServerName>,
}

impl BackendAppManager {
  /// Find backend app for given server name.
  /// First tries exact match, then falls back to wildcard matching.
  /// Exact matches always take priority over wildcard patterns.
  pub fn find_app(&self, server_name: &ServerName) -> Option<&BackendApp> {
    // 1. Try exact match first
    if let Some(app) = self.apps.get(server_name) {
      return Some(app);
    }

    // 2. Try wildcard match
    let server_name_str: String = server_name.try_into().unwrap_or_default();
    let server_name_bytes = server_name_str.as_bytes();

    for (pattern_name, app) in &self.apps {
      let pattern_str: String = pattern_name.try_into().unwrap_or_default();
      if pattern_str.contains('*') {
        if let Ok(pattern) = Wildcard::new(pattern_str.as_bytes()) {
          if pattern.is_match(server_name_bytes) {
            return Some(app);
          }
        }
      }
    }

    None
  }
}

impl TryFrom<&AppConfig> for BackendApp {
  type Error = RpxyError;

  fn try_from(app_config: &AppConfig) -> Result<Self, Self::Error> {
    let mut backend_builder = BackendAppBuilder::default();
    let path_manager = PathManager::try_from(app_config)?;
    backend_builder
      .app_name(app_config.app_name.clone())
      .server_name(app_config.server_name.clone())
      .path_manager(path_manager);
    // TLS settings and build backend instance
    let backend = if app_config.tls.is_none() {
      backend_builder.build()?
    } else {
      let tls = app_config.tls.as_ref().unwrap();
      backend_builder
        .https_redirection(Some(tls.https_redirection))
        .mutual_tls(Some(tls.mutual_tls))
        .build()?
    };
    Ok(backend)
  }
}

impl TryFrom<&AppConfigList> for BackendAppManager {
  type Error = RpxyError;

  fn try_from(config_list: &AppConfigList) -> Result<Self, Self::Error> {
    let mut manager = Self::default();
    for app_config in config_list.inner.iter() {
      let backend: BackendApp = BackendApp::try_from(app_config)?;
      manager.apps.insert(app_config.server_name.clone().to_server_name(), backend);

      info!(
        "Registering application {} ({})",
        &app_config.server_name, &app_config.app_name
      );
    }

    // default backend application for plaintext http requests
    let Some(default_app_name) = &config_list.default_app else {
      return Ok(manager);
    };

    let default_server_name = manager
      .apps
      .iter()
      .filter(|(_k, v)| &v.app_name == default_app_name)
      .map(|(_, v)| v.server_name.clone())
      .collect::<Vec<_>>();

    if !default_server_name.is_empty() {
      info!(
        "Serving plaintext http for requests to unconfigured server_name by app {} (server_name: {}).",
        &default_app_name,
        (&default_server_name[0]).try_into().unwrap_or_else(|_| "".to_string())
      );

      manager.default_server_name = Some(default_server_name[0].clone());
    }

    Ok(manager)
  }
}
