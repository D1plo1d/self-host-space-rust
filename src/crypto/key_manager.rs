use std::path::PathBuf;

use super::IdentityKey;
use super::WebTransportEphemeralKey;
use chrono::{TimeZone, Utc};
use eyre::eyre;
use eyre::Result;

pub struct KeyManager {
    key_dir: PathBuf,
    /// WebTransport ephemeral keys sorted in order of the date each key takes effect. The server should always use the first ephemeral key
    /// from this list.
    /// Generally there should be 2 epehemral keys: The current one used by the server and the upcoming key that will be switched to once
    /// the current key expires.
    pub ephemeral_keys: Vec<WebTransportEphemeralKey>,
    // The identity key for this server. This can be used by clients to access this specific server (and no others in it's group).
    pub server_identity: IdentityKey,
    // The identity key for the server's group. This private key is shared between the servers in the group although it could be be implemented
    // with key splitting in the future to prevent any single group memember from being able to extract the whole key. This can be used by clients
    // to query the signalling server for a group of servers and then load balance between them or provide fallback options if a server
    // is offline.
    pub server_group: IdentityKey,
}

const EPHEMERAL_PREFIX: &'static str = "ephemeral_ecdsa_";

impl KeyManager {
    pub fn current_ephemeral_key(&self) -> Option<&WebTransportEphemeralKey> {
        self.ephemeral_keys.first()
    }

    pub async fn load_or_create<P: Into<PathBuf>>(key_dir: P) -> Result<Self> {
        let key_dir = key_dir.into();

        let mut server_keys = KeyManager {
            server_identity: IdentityKey::load_or_create(key_dir.join("id_ecdsa.pub")).await?,
            server_group: IdentityKey::load_or_create(key_dir.join("group_ecdsa.pub")).await?,
            ephemeral_keys: Vec::new(),
            key_dir: key_dir.into(),
        };

        // Ephemeral keys setup
        server_keys.update_ephemeral_keys().await?;

        Ok(server_keys)
    }

    pub async fn update_ephemeral_keys(&mut self) -> Result<()> {
        let ephemeral_keys = std::fs::read_dir(&self.key_dir)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            // Filter for only ephemeral certs by file name
            .filter_map(|cert| {
                cert.file_name()
                    .into_string()
                    .ok()
                    .filter(|file_name| {
                        file_name.starts_with(EPHEMERAL_PREFIX) && file_name.ends_with(".cert")
                    })
                    .map(|cert_file_name| {
                        let priv_key_file_name = cert_file_name.replacen(".cert", "", 1);
                        let mut private_key = cert.path();
                        private_key.set_file_name(&priv_key_file_name[..]);

                        // Parse the ephemeral key timestamp from it's file name
                        let takes_effect_at = priv_key_file_name
                            .replacen(EPHEMERAL_PREFIX, "", 1)
                            .parse()?;
                        let takes_effect_at = Utc
                            .timestamp_opt(takes_effect_at, 0)
                            .earliest()
                            .ok_or_else(|| eyre!("Invalid ephemeral key timestamp"))?;

                        Ok(WebTransportEphemeralKey {
                            private_key,
                            cert: cert.path(),
                            takes_effect_at,
                        })
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        // Delete ephemeral keys/certs due for replacement
        for eph in ephemeral_keys.iter().filter(|eph| eph.should_be_replaced()) {
            std::fs::remove_file(&eph.cert)?;
            std::fs::remove_file(&eph.private_key)?;
        }

        // Remove ephemeral keys that are past their replacement dates from the list
        let mut ephemeral_keys = ephemeral_keys
            .into_iter()
            .filter(|eph| !eph.should_be_replaced())
            .collect::<Vec<_>>();

        // Create new ephemeral keys as needed
        if ephemeral_keys.len() < 2 {
            let mut next_takes_effect_at = ephemeral_keys
                .iter()
                .map(|eph| eph.replace_at())
                .max()
                .unwrap_or(Utc::now());

            for _ in 0..(2 - ephemeral_keys.len()) {
                let timestamp = next_takes_effect_at.timestamp();
                let cert_pem_path = self
                    .key_dir
                    .join(format!("{EPHEMERAL_PREFIX}{timestamp}.cert"));
                let priv_key_pem_path = self.key_dir.join(format!("{EPHEMERAL_PREFIX}{timestamp}"));
                let eph = WebTransportEphemeralKey::generate(
                    cert_pem_path,
                    priv_key_pem_path,
                    next_takes_effect_at,
                )?;

                next_takes_effect_at = eph.replace_at();
                ephemeral_keys.push(eph);
            }
        }

        ephemeral_keys.sort_by_key(|eph| eph.takes_effect_at);
        self.ephemeral_keys = ephemeral_keys;

        Ok(())
    }
}
