use eyre::eyre;
use eyre::Result;
use jwt_simple::prelude::*;
use log::trace;
use log::warn;
use tokio::task::JoinHandle;

use crate::crypto::KeyManager;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebTransportRoute {
    pub url: String,
    /// True if the route is scoped to the local network, false if the route may be accessible outside the network
    pub is_local: bool,
    /// True connecting to this route requires IPv6
    pub is_ipv6: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GraphQLResponse {
    // data: Option<serde_json::Value>,
    errors: Option<serde_json::Value>,
}

pub fn announce_routing(
    signalling_server_url: &str,
    route_announcements: &Vec<WebTransportRoute>,
    keys: &KeyManager,
) -> Result<JoinHandle<()>> {
    // Generate auth tokens
    let group_auth = keys.server_identity.sign_jwt(
        serde_json::json!({
            "sub": "self",
            "aud": signalling_server_url.clone(),
            "selfSignature": true,
        }),
        Duration::from_mins(10),
    )?;

    let server_auth = keys.server_identity.sign_jwt(
        serde_json::json!({
            "sub": "self",
            "aud": signalling_server_url.clone(),
            "selfSignature": true,
        }),
        Duration::from_mins(10),
    )?;

    // Announce the server's IP addresses and public key
    let client = reqwest::Client::new();
    let req = client
        .post(signalling_server_url)
        .json(&serde_json::json!({
            "query": "mutation($input: WebTransportRoutingInput!) { updateWebTransportRouting(input: $input) { id } }",
            "variables": {
                "input": {
                    "hostPublicKey": keys.server_identity.identity_public_key,
                    "hostAuth": server_auth,
                    "groupPublicKey": keys.server_group.identity_public_key,
                    "groupAuth": group_auth,
                    "routes": &route_announcements,
                    "ephemeralKeyFingerprints": keys.ephemeral_keys.iter().map(|eph| eph.sha256_fingerprint()).collect::<Vec<_>>()
                }
            },
        }));

    Ok(tokio::spawn(async move {
        let max_retry_delay = std::time::Duration::from_secs(5);
        let mut retry_backoff = retry::delay::Fibonacci::from_millis(100);
        loop {
            if let Err(err) = send_signalling_req(&req).await {
                warn!("Error contacting signalling server, will retry.");
                trace!("Signalling error: {:?}", err);
            } else {
                break;
            }
            if let Some(retry_delay) = retry_backoff.next() {
                let retry_delay = if retry_delay < max_retry_delay {
                    retry_delay
                } else {
                    max_retry_delay
                };
                tokio::time::sleep(retry_delay).await;
            }
        }
    }))
}

async fn send_signalling_req(req: &reqwest::RequestBuilder) -> Result<()> {
    let res: GraphQLResponse = req
        .try_clone()
        .ok_or_else(|| eyre!("Unable to clone signalling req builder"))?
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if let Some(errors_json) = res.errors {
        return Err(eyre!(
            "Received a GraphQL error from the signalling server:\n{}",
            serde_json::to_string(&errors_json).unwrap()
        ));
    }

    Ok(())
}
