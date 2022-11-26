// Copyright (C) 2019, Cloudflare, Inc., and 2022, Rob Gilson
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use eyre::eyre;
use eyre::Result;
use futures::future;
use futures::future::Either;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use std::net;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::DuplexStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use std::collections::HashMap;
use std::pin::Pin;

use quiche::h3::webtransport::ServerSession;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;
struct ClientInternal {
    conn: Pin<Box<quiche::Connection>>,
    stream_duplexes: HashMap<u64, Arc<Mutex<tokio::io::DuplexStream>>>,
    session: Option<ServerSession>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, ClientInternal>;

pub struct AsyncWebTransportServer {
    clients: ClientMap,
    conn_id_seed: ring::hmac::Key,
    socket: Arc<UdpSocket>,
    config: quiche::Config,
}

impl AsyncWebTransportServer {
    pub async fn new(
        socket: Arc<UdpSocket>,
        cert_pem_path: &Path,
        sk_pem_path: &Path,
    ) -> Result<Self> {
        // Create the configuration for the QUIC connections.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        config
            .load_cert_chain_from_pem_file(
                cert_pem_path
                    .to_str()
                    .ok_or_else(|| eyre!("Non UTF8 path to cert file"))?,
            )
            .unwrap();
        config
            .load_priv_key_from_pem_file(
                sk_pem_path
                    .to_str()
                    .ok_or_else(|| eyre!("Non UTF8 path to cert file"))?,
            )
            .unwrap();

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 65536, 65536);

        // let mut h3_config = quiche::h3::Config::new().unwrap();

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let clients = ClientMap::new();

        Ok(Self {
            clients,
            socket,
            conn_id_seed,
            config,
        })
    }

    /// Generate a stateless retry token.
    ///
    /// The token includes the static string `"quiche"` followed by the IP address
    /// of the client and by the original destination connection ID generated by the
    /// client.
    ///
    /// Note that this function is only an example and doesn't do any cryptographic
    /// authenticate of the token. *It should not be used in production system*.
    fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
        let mut token = Vec::new();

        token.extend_from_slice(b"quiche");

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        token.extend_from_slice(&addr);
        token.extend_from_slice(&hdr.dcid);

        token
    }

    /// Validates a stateless retry token.
    ///
    /// This checks that the ticket includes the `"quiche"` static string, and that
    /// the client IP address matches the address stored in the ticket.
    ///
    /// Note that this function is only an example and doesn't do any cryptographic
    /// authenticate of the token. *It should not be used in production system*.
    fn validate_token<'a>(
        src: &net::SocketAddr,
        token: &'a [u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        if token.len() < 6 {
            return None;
        }

        if &token[..6] != b"quiche" {
            return None;
        }

        let token = &token[6..];

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
            return None;
        }

        Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
    }

    pub fn into_stream(
        self,
    ) -> genawaiter::sync::Gen<
        Result<DuplexStream, std::io::Error>,
        (),
        impl futures::Future<Output = ()>,
    > {
        genawaiter::sync::Gen::new(move |co| self.serve_inner(co))
    }

    pub async fn serve_inner(
        mut self,
        co: genawaiter::sync::Co<std::io::Result<DuplexStream>, ()>,
    ) -> () {
        'read: loop {
            let mut out = [0; MAX_DATAGRAM_SIZE];

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            for client in self.clients.values_mut() {
                loop {
                    let (write, send_info) = match client.conn.send(&mut out) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("{} done writing", client.conn.trace_id());
                            break;
                        }

                        Err(e) => {
                            error!("{} send failed: {:?}", client.conn.trace_id(), e);

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                    if let Err(e) = self.socket.send_to(&out[..write], &send_info.to).await {
                        error!("send() failed: {:?}", e);
                        co.yield_(Err(e)).await;
                        return;
                    }

                    trace!("{} written {} bytes", client.conn.trace_id(), write);
                }
            }

            drop(out);

            // Garbage collect closed connections.
            self.clients.retain(|_, c| {
                if c.conn.is_closed() {
                    // info!("{} connection collected {:?}", c.conn.trace_id(), c.conn.stats());
                    info!("connection collected {}", c.conn.trace_id());
                }

                !c.conn.is_closed()
            });

            let mut buf = [0; 65535];

            // Find the shorter timeout from all the active connections.
            let timeout = self
                .clients
                .values()
                .filter_map(|c| c.conn.timeout())
                .min()
                .unwrap_or(std::time::Duration::MAX);

            // Create a list of the client connection IDs, stream IDs and duplexes so that ownership can be passed to the client writes
            // future in order to receive notifications of pending writes for each stream.
            let client_duplexes =
                self.clients
                    .iter()
                    .flat_map(|(conn_id, client)| {
                        client.stream_duplexes.iter().map(|(stream_id, duplex)| {
                            (conn_id.clone(), *stream_id, (*duplex).clone())
                        })
                    })
                    .collect::<Vec<_>>();

            // Poll for pending messages to be sent to each stream
            let client_writes_future = future::poll_fn(move |cx: &mut std::task::Context<'_>| {
                let mut read_buf_data = [0; 65535];
                let mut read_buf = tokio::io::ReadBuf::new(&mut read_buf_data);

                for (conn_id, stream_id, duplex) in client_duplexes.iter() {
                    if let Ok(mut duplex) = duplex.try_lock() {
                        if let Poll::Ready(result) =
                            Pin::new(&mut *duplex).poll_read(cx, &mut read_buf)
                        {
                            return Poll::Ready((
                                conn_id.clone(),
                                *stream_id,
                                result.map(|_| read_buf.filled().to_owned()),
                            ));
                        }
                    }
                }
                Poll::Pending
            });

            // Check for QUIC timeouts, pending writes (pending messages to send to a stream), and incoming UDP packets
            let (len, from) = match tokio::time::timeout(
                timeout,
                future::select(
                    Box::pin(client_writes_future),
                    Box::pin(self.socket.recv_from(&mut buf)),
                ),
            )
            .await
            {
                // Send a message to a client
                Ok(Either::Left(((conn_id, stream_id, Ok(read_buf)), _))) => {
                    if let Some(client) = self.clients.get_mut(&conn_id) {
                        if let Some(server_session) = client.session.as_mut() {
                            server_session
                                .send_stream_data(&mut client.conn, stream_id, &read_buf[..])
                                .unwrap();
                        }
                    }
                    continue 'read;
                }
                Ok(Either::Left(((conn_id, _stream_id, Err(e)), _))) => {
                    trace!(
                        "Error reading webtransport write buffer, closing client connection: {:?}",
                        e
                    );
                    self.clients.remove(&conn_id);
                    continue 'read;
                }
                Ok(Either::Right((Ok((len, from)), _))) => (len, from),
                Ok(Either::Right((Err(e), _))) => {
                    error!("Error reading webtransport UDP socket");
                    co.yield_(Err(e)).await;
                    return;
                }
                Err(_) => {
                    trace!("timed out");
                    self.clients.values_mut().for_each(|c| c.conn.on_timeout());
                    continue 'read;
                }
            };

            let mut out = [0; MAX_DATAGRAM_SIZE];

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                }
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !self.clients.contains_key(&hdr.dcid)
                && !self.clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    trace!("Packet is not Initial. This is normally due to STUN packets");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                    let out = &out[..len];

                    if let Err(e) = self.socket.send_to(out, &from).await {
                        error!("send() failed: {:?}", e);
                        co.yield_(Err(e)).await;
                        return;
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = Self::mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = self.socket.send_to(&out, &from).await {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        error!("send() failed: {:?}", e);
                        co.yield_(Err(e)).await;
                        return;
                    }
                    continue 'read;
                }

                let odcid = Self::validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(&scid, odcid.as_ref(), from, &mut self.config).unwrap();

                self.clients.insert(
                    scid.clone(),
                    ClientInternal {
                        conn,
                        session: None,
                        stream_duplexes: HashMap::new(),
                    },
                );

                self.clients.get_mut(&scid).unwrap()
            } else {
                match self.clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => self.clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo { from };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                }
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new HTTP/3 connection as soon as the QUIC connection
            // is established.
            if (client.conn.is_in_early_data() || client.conn.is_established())
                && client.session.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let server_session =
                    quiche::h3::webtransport::ServerSession::with_transport(&mut client.conn)
                        .unwrap();
                client.session = Some(server_session);
            }

            drop(client);

            // The `poll` can pull out the events that occurred according to the data passed here.
            for (
                _,
                ClientInternal {
                    conn,
                    session,
                    stream_duplexes,
                },
            ) in self
                .clients
                .iter_mut()
                .filter(|(_, client)| client.session.is_some())
            {
                let server_session = session.as_mut().unwrap();

                loop {
                    match server_session.poll(conn) {
                        Ok(quiche::h3::webtransport::ServerEvent::ConnectRequest(_req)) => {
                            // you can handle request with
                            // req.authority()
                            // req.path()
                            // and you can validate this request with req.origin()
                            server_session.accept_connect_request(conn, None).unwrap();
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::StreamData(stream_id)) => {
                            let mut buf = vec![0; 10000];
                            while let Ok(len) =
                                server_session.recv_stream_data(conn, stream_id, &mut buf)
                            {
                                let stream_data = &buf[0..len];

                                dbg!(String::from_utf8_lossy(stream_data));

                                // handle stream_data
                                if (stream_id & 0x2) == 0 {
                                    // Create one duplex per stream
                                    if !stream_duplexes.contains_key(&stream_id) {
                                        let (internal_duplex, external_duplex) =
                                            tokio::io::duplex(64);

                                        stream_duplexes.insert(
                                            stream_id,
                                            Arc::new(Mutex::new(internal_duplex)),
                                        );
                                        co.yield_(Ok(external_duplex)).await;
                                    };

                                    let duplex = stream_duplexes.get_mut(&stream_id).unwrap();
                                    if let Err(e) = duplex.lock().await.write_all(stream_data).await
                                    {
                                        error!("{} read failed: {:?}", conn.trace_id(), e);

                                        conn.close(false, 0x1, b"fail").ok();
                                        break;
                                    };
                                } else {
                                    trace!("Unexpected unidirectional stream received");
                                }
                            }
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::StreamFinished(stream_id)) => {
                            // A WebTrnasport stream finished
                            info!("Stream finished {:?}", stream_id);
                            stream_duplexes.remove(&stream_id);
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::Datagram) => {
                            info!("Received a datagram!");
                            let mut buf = vec![0; 1500];
                            while let Ok((in_session, offset, total)) =
                                server_session.recv_dgram(conn, &mut buf)
                            {
                                if in_session {
                                    let dgram = &buf[offset..total];
                                    dbg!(std::string::String::from_utf8_lossy(dgram));
                                    // handle this dgram

                                    // for instance, you can write echo-server like following
                                    server_session.send_dgram(conn, dgram).unwrap();
                                } else {
                                    // this dgram is not related to current WebTransport session. ignore.
                                }
                            }
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionReset(_e)) => {
                            // Peer reset session stream, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionFinished) => {
                            // Peer finish session stream, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionGoAway) => {
                            // Peer signalled it is going away, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::Other(_stream_id, _event)) => {
                            // Original h3::Event which is not related to WebTransport.
                        }

                        Err(quiche::h3::webtransport::Error::Done) => {
                            break;
                        }

                        Err(_e) => {
                            break;
                        }
                    }
                }
            }
        }
    }
}
