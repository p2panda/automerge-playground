mod operation;
mod private_key;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ReadDoc};
use clap::Parser;
use p2panda_core::{Extension, PrivateKey};
use p2panda_engine::extensions::PruneFlag;
use p2panda_engine::IngestExt;
use p2panda_net::network::{InEvent, OutEvent};
use p2panda_net::{LocalDiscovery, NetworkBuilder, TopicId};
use p2panda_store::{MemoryStore, TopicMap};
use p2panda_sync::protocols::log_height::LogHeightSyncProtocol;
use tokio::sync::{mpsc, RwLock};
use tokio::task;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::operation::{create_operation, decode_payload, encode_payload, Extensions};
use crate::private_key::generate_or_load_private_key;

const RELAY_ENDPOINT: &str = "https://staging-euw1-1.relay.iroh.network";

const NETWORK_ID: [u8; 32] = [
    88, 32, 213, 152, 167, 24, 186, 1, 3, 254, 88, 233, 132, 3, 250, 122, 6, 92, 186, 200, 3, 56,
    15, 250, 97, 54, 147, 196, 19, 200, 72, 168,
];

const TOPIC_ID: [u8; 32] = [
    26, 168, 189, 40, 246, 66, 205, 157, 135, 38, 216, 243, 48, 229, 78, 193, 59, 143, 14, 42, 99,
    94, 15, 70, 74, 130, 34, 113, 175, 25, 198, 211,
];

/// Automerge + p2panda!
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to private key file.
    #[arg(short, long)]
    private_key: Option<PathBuf>,

    /// Public key of another peer to connect to.
    #[arg(short, long)]
    node_id: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Prepare automerge "document"
    let doc = Arc::new(RwLock::new(AutoCommit::new()));

    // Ask for user input via stdin
    let (line_tx, mut line_rx) = mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));
    println!("usage: <key> <value> [prune]");

    let private_key = match args.private_key {
        Some(path) => {
            generate_or_load_private_key(path).expect("generating or loading private key")
        }
        None => PrivateKey::new(),
    };
    println!("me: {}", private_key.public_key());

    let store = MemoryStore::<u64, Extensions>::new();

    // Write all data of this author into the same log
    let log_id = 1;

    // Join p2panda network and enable mDNS discovery
    let mut network = NetworkBuilder::new(NETWORK_ID)
        .sync(LogHeightSyncProtocol {
            topic_map: ConstantMap::new(log_id),
            store: store.clone(),
        })
        .private_key(private_key.clone())
        .discovery(LocalDiscovery::new()?)
        .relay(RELAY_ENDPOINT.parse()?, false, 0);

    // We can give the process a <public key> as an argument. This can be another peer we want to
    // connect to over the internet
    if let Some(node_id) = args.node_id {
        network = network.direct_address(
            node_id.parse().expect("invalid public key as argument"),
            vec![],
            None,
        );
    }

    let network = network.build().await?;

    // Subscribe to topic in network and establish a channel to write to and read from
    let (tx, rx) = network.subscribe(TOPIC_ID).await?;

    {
        let mut store = store.clone();
        let doc = doc.clone();

        task::spawn(async move {
            while let Some(text) = line_rx.recv().await {
                // 1. Via stdin we can write key-value pairs into the map CRDT. Additionally we can
                //    prune our log by adding the prune command at the end.
                //
                //    Format: "<key> <value> [prune]"
                let parts: Vec<_> = text.strip_suffix("\n").unwrap().split(' ').collect();
                if parts.len() != 2 && parts.len() != 3 {
                    continue;
                }
                let prune_flag = parts.len() == 3 && parts[2].contains("prune");

                // 2. Update automerge document and encode resulting CRDT as bytes
                let bytes = {
                    let mut doc = doc.write().await;

                    // Make sure the key-value map CRDT at the root of the document exists
                    let root = match doc.get(automerge::ROOT, "root").expect("root exists") {
                        Some(root) => root.1,
                        None => doc
                            .put_object(automerge::ROOT, "root", ObjType::Map)
                            .expect("inserting map at root"),
                    };

                    // Write our key-value pair into the map
                    doc.put(&root, parts[0], parts[1])
                        .expect("inserting key-value pair in map");

                    // If the prune flag is set we want a complete snapshot of the current document
                    if prune_flag {
                        doc.save()
                    } else {
                        doc.save_incremental()
                    }
                };

                // 3. Create p2panda operation with automerge data as payload and send it into the
                //    network
                let operation =
                    create_operation(&mut store, &private_key, log_id, Some(&bytes), prune_flag)
                        .await
                        .expect("creating operation");

                println!(
                    "◆ created operation seq_num={} public_key={} prune={}",
                    operation.header.seq_num, operation.header.public_key, prune_flag
                );

                {
                    let doc = doc.read().await;
                    print_document(&*doc);
                }

                let bytes =
                    encode_payload(operation.header, operation.body).expect("encoding payload");
                tx.send(InEvent::Message { bytes })
                    .await
                    .expect("sending message");
            }
        });
    }

    task::spawn(async move {
        let stream = BroadcastStream::new(rx);

        let stream = stream.filter_map(|event| match event {
            Ok(OutEvent::Ready) => {
                println!("connected");
                None
            }
            Ok(OutEvent::Message { bytes, .. }) => match decode_payload(&bytes) {
                Ok(raw_operation) => Some(raw_operation),
                Err(err) => {
                    eprintln!("failed deserializing JSON: {err}");
                    None
                }
            },
            Err(err) => {
                eprintln!("failed receiver: {err}");
                None
            }
        });

        let mut stream = stream.ingest(store, 128).filter_map(|event| match event {
            Ok(operation) => Some(operation),
            Err(err) => {
                eprintln!("failed ingesting operation: {err}");
                None
            }
        });

        loop {
            if let Some(operation) = stream.next().await {
                let Some(body) = operation.body else {
                    continue;
                };

                {
                    let mut doc = doc.write().await;

                    let prune_flag: PruneFlag = operation.header.extract().unwrap();
                    if prune_flag.is_set() {
                        let mut doc_remote = AutoCommit::load(&body.to_bytes()).unwrap();
                        doc.merge(&mut doc_remote).unwrap();
                    } else {
                        doc.load_incremental(&body.to_bytes()).unwrap();
                    }
                }

                {
                    let doc = doc.read().await;
                    print_document(&*doc);
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;

    Ok(())
}

fn print_document<R>(doc: &R)
where
    R: ReadDoc,
{
    let serialized = serde_json::to_string_pretty(&automerge::AutoSerde::from(doc)).unwrap();
    println!("{serialized}");
}

fn input_loop(line_tx: mpsc::Sender<String>) -> Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin();
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.clone())?;
        buffer.clear();
    }
}

/// Maps any topic always to the same log id.
#[derive(Debug)]
struct ConstantMap(u64);

impl ConstantMap {
    pub fn new(log_id: u64) -> Self {
        Self(log_id)
    }
}

impl TopicMap<TopicId, u64> for ConstantMap {
    fn get(&self, _topic: &TopicId) -> Option<u64> {
        Some(self.0)
    }
}
