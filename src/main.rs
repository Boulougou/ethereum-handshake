use std::env;

use futures::future;
use tokio::task::JoinHandle;

use crate::handshake::{handshake, pretty_enode};
use crate::utils::KeyGen;

mod auth;
mod utils;
mod handshake;
mod frame;

#[tokio::main]
async fn main() {
    let enodes = parse_enodes_from_args();
    let (initiator_secret_key, initiator_public_key) = generate_key_pair();

    let futures = spawn_handshake_tasks(enodes, initiator_secret_key, initiator_public_key);
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

fn generate_key_pair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
    let mut key_gen = KeyGen::new();
    key_gen.generate_key_pair()
}

fn spawn_handshake_tasks(enodes: Vec<String>,
                         initiator_secret_key: secp256k1::SecretKey,
                         initiator_public_key: secp256k1::PublicKey) -> Vec<JoinHandle<()>> {
    enodes.
        into_iter().
        map(|enode| tokio::spawn(
            trigger_handshake(enode, initiator_secret_key, initiator_public_key))).
        collect()
}

async fn trigger_handshake(enode_url : String,
                           initiator_secret_key: secp256k1::SecretKey,
                           initiator_public_key: secp256k1::PublicKey) {
    println!("{} Starting handshake", pretty_enode(&enode_url));
    let result = handshake(&enode_url, &initiator_secret_key, &initiator_public_key).await;
    match result {
        Ok(_) => println!("{} ** Handshake completed ***", pretty_enode(&enode_url)),
        Err(e) => eprintln!("{} !!! Handshake failed: {:?} !!!",  pretty_enode(&enode_url), e)
    }
}

async fn join_handshake_tasks(futures: Vec<JoinHandle<()>>) {
    let results = future::join_all(futures).await;

    let any_failure = results.iter().any(|r| r.is_err());
    if any_failure {
        eprintln!("Could not join all tasks");
        std::process::exit(-1);
    }
}
