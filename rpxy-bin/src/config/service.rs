use super::toml::ConfigToml;
use async_trait::async_trait;
use hot_reload::AsyncFileLoad;
use std::path::{Path, PathBuf};

pub type ConfigTomlReloader = hot_reload::file_reloader::FileReloader<ConfigToml>;

/// Resolve data_dir to absolute path based on config file location
fn resolve_data_dir(config: &mut ConfigToml, config_path: &Path) {
  if let Some(ref data_dir) = config.data_dir {
    let data_path = PathBuf::from(data_dir);
    if data_path.is_relative() {
      // Resolve relative to config file's directory
      if let Some(config_dir) = config_path.parent() {
        let resolved = config_dir.join(&data_path);
        config.data_dir = Some(resolved.to_string_lossy().to_string());
      }
    }
  }
}

impl TryFrom<&PathBuf> for ConfigToml {
  type Error = String;

  fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
    let config_str = std::fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;
    let mut config_toml: ConfigToml = toml::from_str(&config_str).map_err(|e| format!("Failed to parse toml config: {}", e))?;
    resolve_data_dir(&mut config_toml, path);
    Ok(config_toml)
  }
}

#[async_trait]
impl AsyncFileLoad for ConfigToml {
  type Error = String;

  async fn async_load_from<T>(path: T) -> Result<Self, Self::Error>
  where
    T: AsRef<Path> + Send,
  {
    let path_ref = path.as_ref();
    let config_str = tokio::fs::read_to_string(path_ref)
      .await
      .map_err(|e| format!("Failed to read config file: {}", e))?;
    let mut config_toml: ConfigToml = toml::from_str(&config_str).map_err(|e| format!("Failed to parse toml config: {}", e))?;
    resolve_data_dir(&mut config_toml, path_ref);
    Ok(config_toml)
  }
}

// impl From<ConfigToml> for ConfigToml {
//   fn from(val: ConfigToml) -> Self {
//     val
//   }
// }
