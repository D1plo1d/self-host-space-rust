use eyre::Result;
use self_host_space::KeyManager;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let keys = KeyManager::load_or_create("./target").await.unwrap();

    let server = self_host_space::Server::new(keys);

    server
        .serve(|async_wt_server| async {
            let route = warp::path("index.js")
                .map(|| "document.body.append('<h1>Hello from WebTransport Server!</h1>')");

            let connection_stream = async_wt_server.into_stream();
            warp::serve(route).serve_incoming(connection_stream).await;
        })
        .await
        .unwrap();

    Ok(())
}
