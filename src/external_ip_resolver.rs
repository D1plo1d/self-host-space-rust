use std::sync::Arc;

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::{ToSocketAddrs, UdpSocket};
use webrtc_util::Conn;
use webrtc_util::Result;

pub struct ExternalIPResolver<T: ToSocketAddrs + Send + Sync> {
    pub conn: Arc<UdpSocket>,
    pub stun_server: T,
}

#[async_trait]
impl<T: ToSocketAddrs + Send + Sync> Conn for ExternalIPResolver<T> {
    async fn connect(&self, _addr: SocketAddr) -> Result<()> {
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.conn.recv(buf).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.conn.recv_from(buf).await?)
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        Ok(self.conn.send_to(buf, &self.stun_server).await?)
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> Result<usize> {
        Ok(self.conn.send_to(buf, &self.stun_server).await?)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.conn.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
