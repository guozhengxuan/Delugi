//! Local authentication qualification probe; not a consensus benchmark.
use std::{env,net::SocketAddr};
use tokio::io::{AsyncReadExt,AsyncWriteExt};
#[tokio::main(flavor="current_thread")]
async fn main()->Result<(),Box<dyn std::error::Error>> {
    let args:Vec<_>=env::args().collect();
    let address:SocketAddr=args[2].parse()?;
    assert!(network::eval_tls::enabled());
    match args[1].as_str() {
        "server"=>{
            let listener=tokio::net::TcpListener::bind(address).await?;
            println!("ready");
            let (socket,_)=listener.accept().await?;
            let (mut stream,peer)=network::eval_tls::accept(socket).await?;
            network::eval_tls::PEER.scope(peer,async move {
                let mut author=[0;32];stream.read_exact(&mut author).await?;
                network::eval_tls::require_peer(&author)?;
                stream.write_all(b"accepted").await?;
                Ok::<(),std::io::Error>(())
            }).await?;
        },
        "client"=>{
            let mut stream=network::eval_tls::connect(address).await?;
            stream.write_all(&hex::decode(&args[3])?).await?;
            let mut ack=[0;8];stream.read_exact(&mut ack).await?;
            assert_eq!(&ack,b"accepted");
        },
        _=>panic!("expected server/client"),
    }
    Ok(())
}
