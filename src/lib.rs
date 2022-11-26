pub use crate::crypto::KeyManager;
use crate::external_ip_resolver::ExternalIPResolver;
pub use crate::server::AsyncWebTransportServer;
use crate::signalling::WebTransportRoute;
use chrono::Utc;
use eyre::Result;
use futures::Future;
use log::debug;
use std::net::IpAddr;
use std::sync::Arc;
use stun::agent::*;
use stun::client::*;
use stun::message::*;
use stun::xoraddr::*;
use tokio::net::UdpSocket;
use tokio::time::timeout;

mod crypto;
mod external_ip_resolver;
mod server;
mod signalling;

pub struct Server {
    pub port: u16,
    pub stun_server: String,
    pub signalling_server_url: String,
    pub keys: KeyManager,
}

impl Server {
    pub fn new(keys: KeyManager) -> Self {
        Self {
            port: 4430,
            stun_server: "stun.l.google.com:19302".to_string(),
            // TODO: change this to the public server URL once one is available
            signalling_server_url: "http://localhost:8080".to_string(),
            keys,
        }
    }
}

impl Server {
    /// on_server: Callback to start the web server - this will get executed whenever the public ip changes to restart the server
    pub async fn serve<H: Fn(AsyncWebTransportServer) -> F, F: Future<Output = ()>>(
        self,
        on_server: H,
    ) -> Result<()> {
        loop {
            let socket_addr = format!("0:{}", self.port);
            let mut initial_public_ip: Option<IpAddr> = None;

            // Collect the local IP addresses so they can be announced to the signalling server
            let mut route_announcements = local_ip_address::list_afinet_netifas()
                .unwrap()
                .into_iter()
                .filter(|(name, _)| name != "lo")
                .map(|(_, ip)| WebTransportRoute {
                    url: format!(
                        "https://{}:{}",
                        if ip.is_ipv6() {
                            format!("[{ip}]")
                        } else {
                            ip.to_string()
                        },
                        self.port,
                    ),
                    is_local: true,
                    is_ipv6: ip.is_ipv6(),
                })
                .collect::<Vec<_>>();

            // Create the UDP port
            let conn = Arc::new(UdpSocket::bind(socket_addr).await?);

            // Collect STUN information
            debug!("Collecting STUN data from: {}", &self.stun_server);
            // Attempt 10 times to get the external ip address and NAT mapped port number via STUN
            for _ in 0..10 {
                let conn_clone = Arc::clone(&conn);
                let conn_wrapper = ExternalIPResolver {
                    conn: conn_clone,
                    stun_server: self.stun_server.clone(),
                };

                let mut client = ClientBuilder::new()
                    .with_conn(Arc::new(conn_wrapper))
                    .build()?;
                let (handler_tx, mut handler_rx) = tokio::sync::mpsc::unbounded_channel();

                let mut msg = Message::new();
                msg.build(&[
                    Box::new(TransactionId::default()),
                    Box::new(BINDING_REQUEST),
                ])?;

                client.send(&msg, Some(Arc::new(handler_tx))).await?;

                if let Some(event) = handler_rx.recv().await {
                    let msg = event.event_body?;
                    let mut xor_addr = XorMappedAddress::default();
                    xor_addr.get_from(&msg)?;

                    // Add the external IP to the route announcements to be sent to the signalling server
                    route_announcements.push(WebTransportRoute {
                        url: format!("https://{}:{}", xor_addr.ip, xor_addr.port),
                        is_local: false,
                        is_ipv6: xor_addr.ip.is_ipv6(),
                    });
                    initial_public_ip = Some(xor_addr.ip);
                    break;
                }

                client.close().await?;
            }

            // Load the server's self-signed certs
            let ephemeral_key = self
                .keys
                .current_ephemeral_key()
                .expect("Ephermal key not found")
                .clone();

            // Prepare the Web Transport server
            let http_over_wt = server::AsyncWebTransportServer::new(
                conn,
                &ephemeral_key.cert,
                &ephemeral_key.private_key,
            )
            .await
            .unwrap();

            // Announce the server's IP addresses and public key
            let signalling_future = signalling::announce_routing(
                &self.signalling_server_url,
                &route_announcements,
                &self.keys,
            )?;

            // Watch for public IP address changes
            let ip_change_listener = tokio::task::spawn(async move {
                loop {
                    if let Some(new_ip) = public_ip::addr().await {
                        // If the IP address has changed then return from this future and restart the WebTransport server
                        if Some(new_ip) != initial_public_ip {
                            return;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            });

            // Start the web server over web transport using the UDP port that the STUN queries were made with.
            let stream_handler = on_server(http_over_wt);

            let joined_future = futures::future::join(stream_handler, signalling_future);
            let joined_future =
                futures::future::select(Box::pin(joined_future), ip_change_listener);

            debug!(
                "Web Transport server started on:\n{}",
                route_announcements
                    .iter()
                    .map(|r| format!(
                        " - {} Address:  {}\n",
                        if r.is_local { "Local" } else { "Global" },
                        r.url
                    ))
                    .collect::<String>(),
            );

            debug!(
                "Server SHA256 Fingerprint:\n{}",
                ephemeral_key.sha256_fingerprint(),
            );
            debug!(
                "Server B58 Fingerprint:\n{}",
                self.keys.server_identity.b58_fingerprint
            );

            // Restart the server before the ephemeral key in use expires
            let _ = timeout(
                (ephemeral_key.replace_at() - Utc::now()).to_std()?,
                joined_future,
            )
            .await;
        }
    }
}
