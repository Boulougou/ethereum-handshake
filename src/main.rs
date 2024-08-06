use futures::future;

use crate::handshake::handshake;
use crate::utils::key_gen::KeyGen;

mod messages;
mod utils;
mod handshake;

#[tokio::main]
async fn main() {
    let mut key_gen = KeyGen::new();
    let initiator_secret_key= key_gen.generate_secret_key();

    let enodes = [
        "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303",
        "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303",
    ];

    let futures = enodes.map(|enode| tokio::spawn(trigger_handshake(enode, initiator_secret_key)));
    let _results = future::join_all(futures).await;
}

async fn trigger_handshake(enode_url : &str,
                           initiator_secret_key: secp256k1::SecretKey) {
    let result = handshake(enode_url, &initiator_secret_key).await;
    match result {
        Ok(_) => println!("Handshake completed for {enode_url}!!!"),
        Err(e) => println!("Handshake failed for {enode_url}: {}", e)
    }
}
