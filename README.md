# ethereum-handshake
**ethereum-handshake** is a command-line tool (written in Rust) that implements [RLPx handshake](https://github.com/ethereum/devp2p/blob/master/rlpx.md), which is a handshake for establishing communication between Ethereum nodes.

These are the high level steps performed during the handshake as [quoted from the spec](https://github.com/ethereum/devp2p/blob/master/rlpx.md#initial-handshake):

>An RLPx connection is established by creating a TCP connection and agreeing on ephemeral
key material for further encrypted and authenticated communication. The process of
creating those session keys is the 'handshake' and is carried out between the 'initiator'
(the node which opened the TCP connection) and the 'recipient' (the node which accepted it).
>
>1. initiator connects to recipient and sends its `auth` message
>2. recipient accepts, decrypts and verifies `auth` (checks that recovery of signature ==
   `keccak256(ephemeral-pubk)`)
>3. recipient generates `auth-ack` message from `remote-ephemeral-pubk` and `nonce`
>4. recipient derives secrets and sends the first encrypted frame containing the [Hello] message
>5. initiator receives `auth-ack` and derives secrets
>6. initiator sends its first encrypted frame containing initiator [Hello] message
>7. recipient receives and authenticates first encrypted frame
>8. initiator receives and authenticates first encrypted frame
>9. cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides
>
>Either side may disconnect if authentication of the first framed packet fails.

## Usage

The command line tool expects a list of Ethereum node urls, and it will attempt to perform an RLPx handshake with each one of them in parallel.

Here is an example using URLs of Ethereum main net nodes (as taken from [geth codebase](https://github.com/ethereum/go-ethereum/blob/811a69cd3cf77fe9b63c7dc260ff92a79c631846/params/bootnodes.go#L23)):
```
cargo run \
   enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303 \
   enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303 \
   enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303 \
   enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303
```
It will log the handshake steps for each node, prefixing each line with the shortened enode-url. In that particular run below, the handshake was completed with only one of the nodes, as the other three sent a `Disconnect (0x04)` message, which means that they already have [too many peers connected](https://github.com/ethereum/devp2p/blob/master/rlpx.md#disconnect-0x01).
```
Running `target\debug\ethereum-handshake.exe enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303 enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303 enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303 enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303`
[enode://2b252a] Starting handshake
[enode://d860a0] Starting handshake
[enode://22a823] Starting handshake
[enode://4aeb4a] Starting handshake
[enode://2b252a] Connected to 65.108.70.101:30303
[enode://2b252a] Sent Auth message
[enode://4aeb4a] Connected to 157.90.35.166:30303
[enode://4aeb4a] Sent Auth message
[enode://22a823] Connected to 3.209.45.79:30303
[enode://d860a0] Connected to 18.138.108.67:30303
[enode://d860a0] Sent Auth message
[enode://22a823] Sent Auth message
[enode://2b252a] Received Ack message
[enode://2b252a] Frame context was initialized
[enode://2b252a] Sent HelloMessage { protocol_version: 5, client_id: "Boulougou-Ethereum/0.1.0", capabilities: [("eth", 68)], listen_port: 0, node_id: PublicKey(4d367ca462f257c3d016f07274296ced049e6adb037001c59db8cd7a22fc46fcd8d196ddfd292901fa75b5c48cdaa70c1e3b35f14fed8d508981a7371a63cd25) }
[enode://2b252a] Received incoming frame
[enode://2b252a] !!! Handshake failed: Received Disconnect instead of Hello, reason for disconnection: 0x4 !!!
[enode://d860a0] Received Ack message
[enode://22a823] Received Ack message
[enode://d860a0] Frame context was initialized
[enode://22a823] Frame context was initialized
[enode://d860a0] Sent HelloMessage { protocol_version: 5, client_id: "Boulougou-Ethereum/0.1.0", capabilities: [("eth", 68)], listen_port: 0, node_id: PublicKey(4d367ca462f257c3d016f07274296ced049e6adb037001c59db8cd7a22fc46fcd8d196ddfd292901fa75b5c48cdaa70c1e3b35f14fed8d508981a7371a63cd25) }
[enode://22a823] Sent HelloMessage { protocol_version: 5, client_id: "Boulougou-Ethereum/0.1.0", capabilities: [("eth", 68)], listen_port: 0, node_id: PublicKey(4d367ca462f257c3d016f07274296ced049e6adb037001c59db8cd7a22fc46fcd8d196ddfd292901fa75b5c48cdaa70c1e3b35f14fed8d508981a7371a63cd25) }
[enode://d860a0] Received incoming frame
[enode://d860a0] !!! Handshake failed: [enode://22a823] Received incoming frame
Received Disconnect instead of Hello, reason for disconnection: 0x4 !!!
[enode://22a823] !!! Handshake failed: Received Disconnect instead of Hello, reason for disconnection: 0x4 !!!
[enode://4aeb4a] Received Ack message
[enode://4aeb4a] Frame context was initialized
[enode://4aeb4a] Sent HelloMessage { protocol_version: 5, client_id: "Boulougou-Ethereum/0.1.0", capabilities: [("eth", 68)], listen_port: 0, node_id: PublicKey(4d367ca462f257c3d016f07274296ced049e6adb037001c59db8cd7a22fc46fcd8d196ddfd292901fa75b5c48cdaa70c1e3b35f14fed8d508981a7371a63cd25) }
[enode://4aeb4a] Received incoming frame
[enode://4aeb4a] Received valid HelloMessage { protocol_version: 5, client_id: "Geth/v1.14.5-stable-0dd173a7/linux-amd64/go1.22.4", capabilities: [("eth", 68), ("snap", 1)], listen_port: 0, node_id: PublicKey(6c5c263e14082aed5de2599b8e0da248074bc079e8dccfc4e2234bc1b64aeb4a522098afdaec44a4cfe37d278e3ff9f2913d6788a22c31e341e6c8cb746e9325) }
[enode://4aeb4a] ** Handshake completed ***
```

### Testing with a local ethereum node

You can run the handshake targeting an ethereum node running locally, for example [reth](https://github.com/paradigmxyz/reth). In order to run `reth` in a docker container on your local machine, you can run this command:
```
docker run -v rethdata:/root/.local/share/reth/mainnet -d \
   -p 9001:9001 -p 30303:30303 -p 30303:30303/udp \
   --name reth ghcr.io/paradigmxyz/reth:v1.0.4 \
   node -vvvvv --disable-discovery --http --http.api admin --metrics 0.0.0.0:9001
```
This will run `reth` with trace logs enabled (`-vvvvv`), discovery disabled so that there is less noise from communication with other nodes, and admin RPC endpoints enabled so that we can retrieve enode URL.

In order to retrieve the enode url, we need to hit the RPC admin endpoint from inside the container, using the command below (it will install `curl` and `jq` in the process):
```
docker exec -it reth /bin/bash -c "apt update && apt install -y curl jq && \
    curl -X POST --header 'Content-Type: application/json' \
    --data '{\"jsonrpc\":\"2.0\",\"method\":\"admin_nodeInfo\",\"params\":[],\"id\":1}' \
    http://127.0.0.1:8545 | jq .result.enode"
```
It will eventually print the enode URL:
```
Selecting previously unselected package libcurl4:amd64.
Preparing to unpack .../11-libcurl4_7.81.0-1ubuntu1.17_amd64.deb ...
Unpacking libcurl4:amd64 (7.81.0-1ubuntu1.17) ...
...
...
Running hooks in /etc/ca-certificates/update.d...
done.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1430  100  1368  100    62   579k  26898 --:--:-- --:--:-- --:--:--  698k
"enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303"
```
Then using the enode url:
```
$ cargo run "enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303"
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.10s
     Running `target\debug\ethereum-handshake.exe enode://5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d@127.0.0.1:30303`
[enode://5f379b] Starting handshake
[enode://5f379b] Connected to 127.0.0.1:30303
[enode://5f379b] Sent Auth message
[enode://5f379b] Received Ack message
[enode://5f379b] Frame context was initialized
[enode://5f379b] Sent HelloMessage { protocol_version: 5, client_id: "Boulougou-Ethereum/0.1.0", capabilities: [("eth", 68)], listen_port: 0, node_id: PublicKey(3032fb7e0bfbb5ea2f89824bbc186a6070df7f56a67dd35db70e0ceeb8071754702d27fe3f727d2577bf50bb6e919cceade79af0c97754f67ae2e64ae125d934) }
[enode://5f379b] Received incoming frame
[enode://5f379b] Received valid HelloMessage { protocol_version: 5, client_id: "reth/v1.0.4-e24e4c77/x86_64-unknown-linux-gnu", capabilities: [("eth", 68), ("eth", 67), ("eth", 66)], listen_port: 30303, node_id: PublicKey(35e6dfaf186ca3c37e4c3367061a43291da6da86e403acddbefcb734969b375f7d40bcfe79303ca23f17e7737850ef61333ba9c8d7c51f7e1eaf03e5bf0d195e) }
[enode://5f379b] ** Handshake completed ***
```
Inspecting `reth` container logs, will show that the handshake was completed successfully, i.e. after exchanging Auth/Ack messages and Hello frames, the node will send an eth status message (`sending eth status to peer`). Then the connection is dropped (since the command line tool exits after receiving the Hello): 
```
2024-08-11T09:21:57.250860Z TRACE net::session: new pending incoming session remote_addr=192.168.65.1:57188 session_id=SessionId(0)
2024-08-11T09:21:57.250926Z TRACE net: Incoming connection remote_addr=192.168.65.1:57188
2024-08-11T09:21:57.250933Z TRACE net: Incoming connection session_id=SessionId(0) remote_addr=192.168.65.1:57188
2024-08-11T09:21:57.251073Z TRACE reth_ecies::stream: incoming ecies stream
2024-08-11T09:21:57.253211Z TRACE decode{peer=None state=Auth}: reth_ecies::codec: parsing auth
2024-08-11T09:21:57.253619Z TRACE reth_ecies::stream: receiving ecies auth
2024-08-11T09:21:57.253645Z TRACE reth_ecies::stream: sending ecies ack
2024-08-11T09:21:57.253912Z TRACE reth_eth_wire::p2pstream: sending p2p hello to peer hello=HelloMessageWithProtocols { protocol_version: V5, client_version: "reth/v1.0.4-e24e4c77/x86_64-unknown-linux-gnu", protocols: [Protocol { cap: Capability { name: "eth", version: 68 }, messages: 13 }, Protocol { cap: Capability { name: "eth", version: 67 }, messages: 13 }, Protocol { cap: Capability { name: "eth", version: 66 }, messages: 15 }], port: 30303, id: 0x5f379b9634b7fcbeddac03e486daa61d29431a0667334c7ec3a36c18afdfe6355e190dbfe503af1e7e1fc5d7c8a93b3361ef507873e7173fa23c3079febc407d }
2024-08-11T09:21:57.254035Z TRACE decode{peer=Some(0x541707b8ee0c0eb75dd37da6567fdf70606a18bc4b82892feab5fb0b7efb323034d925e14ae6e27af65477c9f09ae7adce9c916ebb50bf77257d723ffe272d70) state=Header}: reth_ecies::codec: current len 0, need 32
2024-08-11T09:21:57.257647Z TRACE reth_eth_wire::p2pstream: validating incoming p2p hello from peer hello=HelloMessage { protocol_version: V5, client_version: "Boulougou-Ethereum/0.1.0", capabilities: [Capability { name: "eth", version: 68 }], port: 0, id: 0x541707b8ee0c0eb75dd37da6567fdf70606a18bc4b82892feab5fb0b7efb323034d925e14ae6e27af65477c9f09ae7adce9c916ebb50bf77257d723ffe272d70 }
2024-08-11T09:21:57.257694Z TRACE reth_eth_wire::ethstream: sending eth status to peer status=Status { version: 68, chain: mainnet, total_difficulty: 17179869184, blockhash: d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3, genesis: d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3, forkid: ForkId { hash: ForkHash("fc64ec04"), next: 118C30 } }
2024-08-11T09:21:57.257776Z TRACE decode{peer=Some(0x541707b8ee0c0eb75dd37da6567fdf70606a18bc4b82892feab5fb0b7efb323034d925e14ae6e27af65477c9f09ae7adce9c916ebb50bf77257d723ffe272d70) state=Header}: reth_ecies::codec: current len 0, need 32
2024-08-11T09:21:57.259225Z TRACE decode{peer=Some(0x541707b8ee0c0eb75dd37da6567fdf70606a18bc4b82892feab5fb0b7efb323034d925e14ae6e27af65477c9f09ae7adce9c916ebb50bf77257d723ffe272d70) state=Header}: reth_ecies::codec: current len 0, need 32
2024-08-11T09:21:57.259436Z TRACE net::session: disconnected pending session session_id=SessionId(0) remote_addr=192.168.65.1:57188 error=Some(Eth(EthHandshakeError(NoResponse)))
2024-08-11T09:21:57.259494Z TRACE net: Incoming pending session failed remote_addr=192.168.65.1:57188 error=Some(Eth(EthHandshakeError(NoResponse)))
```