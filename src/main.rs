use std::env;

use futures::future;
use tokio::task::JoinHandle;

use crate::handshake::handshake;
use crate::utils::key_gen::KeyGen;

mod messages;
mod utils;
mod handshake;

#[tokio::main]
async fn main() {
    let enodes = parse_enodes_from_args();
    let initiator_secret_key = generate_secret_key();

    let futures = spawn_handshake_tasks(enodes, initiator_secret_key);
    join_handshake_tasks(futures).await;
}

fn parse_enodes_from_args() -> Vec<String> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <enode1> <enode2> ... <enodeN>", args[0]);
        std::process::exit(1);
    }

    let enodes = args.split_off(1);
    enodes
}

fn generate_secret_key() -> secp256k1::SecretKey {
    let mut key_gen = KeyGen::new();
    key_gen.generate_secret_key()
}

fn spawn_handshake_tasks(enodes: Vec<String>, initiator_secret_key: secp256k1::SecretKey) -> Vec<JoinHandle<()>> {
    enodes.
        into_iter().
        map(|enode| tokio::spawn(
            trigger_handshake(enode, initiator_secret_key))).
        collect()
}

async fn trigger_handshake(enode_url : String,
                           initiator_secret_key: secp256k1::SecretKey) {
    let result = handshake(&enode_url, &initiator_secret_key).await;
    match result {
        Ok(_) => println!("Handshake completed for {enode_url}!!!"),
        Err(e) => println!("Handshake failed for {enode_url}: {:?}", e)
    }
}

async fn join_handshake_tasks(futures: Vec<JoinHandle<()>>) {
    let results = future::join_all(futures).await;

    let any_failure = results.iter().any(|r| r.is_err());
    if any_failure {
        println!("Could not join all tasks");
        std::process::exit(-1);
    }
}
