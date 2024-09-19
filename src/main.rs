use std::collections::HashMap;
// use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use anyhow::Result;
use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ReadDoc};
use p2panda_core::{Body, Extension, Header, Operation, PrivateKey};
use p2panda_engine::extensions::{PruneFlag, StreamName};
use p2panda_engine::{DecodeExt, IngestExt};
use p2panda_net::network::{InEvent, OutEvent};
use p2panda_net::{LocalDiscovery, NetworkBuilder};
use p2panda_store::{LogStore, MemoryStore, OperationStore};
use p2panda_sync::protocols::log_height::LogHeightSyncProtocol;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
// use tracing_subscriber::layer::SubscriberExt;
// use tracing_subscriber::util::SubscriberInitExt;
// use tracing_subscriber::EnvFilter;

const NETWORK_ID: [u8; 32] = [
    88, 32, 213, 152, 167, 24, 186, 1, 3, 254, 88, 233, 132, 3, 250, 122, 6, 92, 186, 200, 3, 56,
    15, 250, 97, 54, 147, 196, 19, 200, 72, 168,
];

const TEST_TOPIC_ID: [u8; 32] = [1; 32];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Extensions {
    #[serde(rename = "s")]
    pub stream_name: StreamName,

    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub prune_flag: Option<PruneFlag>,
}

impl Extension<StreamName> for Extensions {
    fn extract(&self) -> Option<StreamName> {
        Some(self.stream_name.clone())
    }
}

impl Extension<PruneFlag> for Extensions {
    fn extract(&self) -> Option<PruneFlag> {
        self.prune_flag
            .clone()
            .or_else(|| Some(PruneFlag::default()))
    }
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

#[tokio::main]
async fn main() -> Result<()> {
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
    //     .with(EnvFilter::from_default_env())
    //     .try_init()
    //     .ok();

    let doc = Arc::new(RwLock::new(AutoCommit::new()));

    let (line_tx, mut line_rx) = mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    let private_key = PrivateKey::new();
    let store = MemoryStore::new();
    let stream_name = StreamName::new(private_key.public_key(), Some("test".into()));

    println!("me: {}", private_key.public_key());

    let mut sync_map = HashMap::new();
    sync_map.insert(TEST_TOPIC_ID, stream_name.clone());

    let network = NetworkBuilder::new(NETWORK_ID)
        .sync(LogHeightSyncProtocol {
            log_ids: sync_map,
            store: store.clone(),
        })
        .private_key(private_key.clone())
        // .relay(
        //     "https://staging-euw1-1.relay.iroh.network".parse()?,
        //     false,
        //     0,
        // )
        // .direct_address(p2panda_core::PublicKey::from_str("")?, vec![], None)
        .discovery(LocalDiscovery::new()?)
        .build()
        .await?;

    let (tx, rx) = network.subscribe(TEST_TOPIC_ID).await?;

    {
        let mut store = store.clone();
        let doc = doc.clone();

        task::spawn(async move {
            while let Some(text) = line_rx.recv().await {
                let parts: Vec<_> = text.split(' ').collect();

                if parts.len() != 2 && parts.len() != 3 {
                    continue;
                }

                let prune_flag = parts.len() == 3 && parts[2].contains("prune");

                let bytes = {
                    let mut doc = doc.write().unwrap();
                    let contacts = match doc.get(automerge::ROOT, "contacts").unwrap() {
                        Some(contacts) => contacts.1,
                        None => doc
                            .put_object(automerge::ROOT, "contacts", ObjType::Map)
                            .unwrap(),
                    };
                    doc.put(&contacts, parts[0], parts[1]).unwrap();
                    if prune_flag {
                        doc.save()
                    } else {
                        doc.save_incremental()
                    }
                };

                let operation = create_operation(
                    &mut store,
                    &private_key,
                    &stream_name,
                    Some(&bytes),
                    prune_flag,
                )
                .await
                .expect("creating operation");

                println!(
                    "created operation seq_num={} public_key={} prune={}",
                    operation.header.seq_num, operation.header.public_key, prune_flag
                );
                let raw_operation = (
                    operation.header.to_bytes(),
                    operation.body.map(|body| body.to_bytes()),
                );
                let bytes = serde_json::to_vec(&raw_operation).expect("encoding");

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
            Ok(OutEvent::Message { bytes, .. }) => {
                let raw_operation: Result<(Vec<u8>, Option<Vec<u8>>), _> =
                    serde_json::from_slice(&bytes);
                match raw_operation {
                    Ok(data) => Some(data),
                    Err(err) => {
                        eprintln!("failed deserializing JSON: {err}");
                        None
                    }
                }
            }
            Err(err) => {
                eprintln!("failed receiver: {err}");
                None
            }
        });

        let stream = stream.decode().filter_map(|event| match event {
            Ok((header, body)) => Some((header, body)),
            Err(err) => {
                eprintln!("failed decoding operation: {err}");
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
                if let Some(body) = operation.body {
                    let mut doc = doc.write().unwrap();

                    let prune_flag: PruneFlag = operation.header.extract().unwrap();
                    if prune_flag.is_set() {
                        let mut doc_remote = AutoCommit::load(&body.to_bytes()).unwrap();
                        doc.merge(&mut doc_remote).unwrap();
                    } else {
                        doc.load_incremental(&body.to_bytes()).unwrap();
                    }
                    let serialized =
                        serde_json::to_string(&automerge::AutoSerde::from(&doc.clone())).unwrap();
                    println!("{serialized}");
                }
            }
        }
    });

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn create_operation(
    store: &mut MemoryStore<StreamName, Extensions>,
    private_key: &PrivateKey,
    stream_name: &StreamName,
    body: Option<&[u8]>,
    prune_flag: bool,
) -> Result<Operation<Extensions>> {
    let body = body.map(Body::new);

    let public_key = private_key.public_key();

    let latest_operation = store.latest_operation(&public_key, &stream_name).await?;

    let (seq_num, backlink) = match latest_operation {
        Some(operation) => (operation.header.seq_num + 1, Some(operation.hash)),
        None => (0, None),
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let extensions = Extensions {
        stream_name: stream_name.to_owned(),
        prune_flag: Some(PruneFlag::new(prune_flag)),
    };

    let mut header = Header {
        version: 1,
        public_key,
        signature: None,
        payload_size: body.as_ref().map_or(0, |body| body.size()),
        payload_hash: body.as_ref().map(|body| body.hash()),
        timestamp,
        seq_num,
        backlink,
        previous: vec![],
        extensions: Some(extensions),
    };
    header.sign(private_key);

    let operation = Operation {
        hash: header.hash(),
        header,
        body,
    };

    store.insert_operation(&operation, &stream_name).await?;

    if prune_flag {
        assert!(
            operation.header.seq_num > 0,
            "can't prune from first operation in log"
        );
        store
            .delete_operations(
                &operation.header.public_key,
                &stream_name,
                operation.header.seq_num,
            )
            .await?;
    }

    Ok(operation)
}
