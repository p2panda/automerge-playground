use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use p2panda_core::{
    validate_backlink, validate_operation, Body, Extension, Header, Operation, PrivateKey,
};
use p2panda_net::network::{InEvent, OutEvent};
use p2panda_net::{LocalDiscovery, NetworkBuilder};
use p2panda_store::{LogStore, MemoryStore, OperationStore};
use p2panda_sync::protocols::log_height::LogHeightSyncProtocol;
use serde::{Deserialize, Serialize};
use tokio::task;

const NETWORK_ID: [u8; 32] = [
    88, 32, 213, 152, 167, 24, 186, 1, 3, 254, 88, 233, 132, 3, 250, 122, 6, 92, 186, 200, 3, 56,
    15, 250, 97, 54, 147, 196, 19, 200, 72, 168,
];

const TEST_TOPIC_ID: [u8; 32] = [1; 32];

const PRUNE_NTH: usize = 4;

#[derive(Clone, Debug, Hash, Default, Eq, PartialEq, Serialize, Deserialize)]
struct LogId(pub u64);

#[derive(Clone, Debug, Hash, Default, Eq, PartialEq, Serialize, Deserialize)]
struct PruneFlag(pub bool);

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Extensions {
    #[serde(rename = "l")]
    pub log_id: LogId,

    #[serde(rename = "p", skip_serializing_if = "Option::is_none")]
    pub prune_flag: Option<PruneFlag>,
}

impl Extension<LogId> for Extensions {
    fn extract(&self) -> Option<LogId> {
        Some(self.log_id.clone())
    }
}

impl Extension<PruneFlag> for Extensions {
    fn extract(&self) -> Option<PruneFlag> {
        Some(PruneFlag(self.prune_flag.is_some()))
    }
}

#[derive(Clone)]
struct Store(Arc<RwLock<MemoryStore<LogId, Extensions>>>);

impl Store {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(MemoryStore::new())))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let private_key = PrivateKey::new();
    let store = Store::new();
    let log_id = LogId(1);

    let mut sync_map = HashMap::new();
    sync_map.insert(TEST_TOPIC_ID, log_id.clone());

    let network = NetworkBuilder::new(
        NETWORK_ID,
        LogHeightSyncProtocol {
            log_ids: sync_map,
            store: store.0.clone(),
        },
    )
    .private_key(private_key.clone())
    .discovery(LocalDiscovery::new()?)
    .build()
    .await?;

    let (tx, mut rx) = network.subscribe(TEST_TOPIC_ID).await?;

    {
        let mut store = store.clone();
        task::spawn(async move {
            let mut counter = 0;

            loop {
                let operation = create_operation(
                    &mut store,
                    &private_key,
                    &log_id,
                    Some(b"Hello Panda"),
                    counter % PRUNE_NTH == 0,
                )
                .await
                .expect("creating operation");

                let bytes =
                    encode_operation(operation.header, operation.body).expect("encoding operation");

                tx.send(InEvent::Message { bytes })
                    .await
                    .expect("sending message");

                tokio::time::sleep(Duration::from_secs(2)).await;

                counter += 1;
            }
        });
    }

    {
        let mut store = store.clone();
        task::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(OutEvent::Ready) => {
                        println!("connected");
                    }
                    Ok(OutEvent::Message { bytes, .. }) => {
                        let Ok((header, body)) = decode_operation(&bytes) else {
                            eprintln!("failed decoding operation");
                            continue;
                        };

                        println!(
                            "received operation {} {}",
                            header.seq_num, header.public_key
                        );

                        if let Err(err) = ingest_operation(&mut store, header, body).await {
                            eprintln!("failed ingesting operation: {err}");
                            continue;
                        }
                    }
                    Err(err) => {
                        eprintln!("failed receiver: {err}");
                    }
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn create_operation(
    store: &mut Store,
    private_key: &PrivateKey,
    log_id: &LogId,
    body: Option<&[u8]>,
    prune_flag: bool,
) -> Result<Operation<Extensions>> {
    let body = body.map(Body::new);

    let public_key = private_key.public_key();

    let mut store = store.0.write().unwrap();

    let latest_operation = store.latest_operation(public_key, log_id.to_owned())?;

    let (seq_num, backlink) = match latest_operation {
        Some(operation) => (operation.header.seq_num + 1, Some(operation.hash)),
        None => (0, None),
    };

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    let extensions = Extensions {
        log_id: log_id.to_owned(),
        prune_flag: if prune_flag {
            Some(PruneFlag(true))
        } else {
            None
        },
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

    store.insert_operation(operation.clone(), log_id.to_owned())?;

    if prune_flag {
        store.delete_operations(
            operation.header.public_key,
            log_id.to_owned(),
            operation.header.seq_num,
        )?;
    }

    Ok(operation)
}

async fn ingest_operation(
    store: &mut Store,
    header: Header<Extensions>,
    body: Option<Body>,
) -> Result<Operation<Extensions>> {
    let operation = Operation {
        hash: header.hash(),
        header,
        body,
    };
    // @TODO: Backlink _needs_ to exists if there's no pruning point
    validate_operation(&operation)?;

    let mut store = store.0.write().unwrap();

    let already_exists = store.get_operation(operation.hash)?.is_some();
    if !already_exists {
        let log_id: LogId = operation
            .header
            .extract()
            .ok_or(anyhow!("missing 'log_id' field in header"))?;
        let latest_operation = store
            .latest_operation(operation.header.public_key, log_id.to_owned())
            .context("critical store failure")?;

        if let Some(latest_operation) = latest_operation {
            validate_backlink(&latest_operation.header, &operation.header)?;
        }

        store
            .insert_operation(operation.clone(), log_id.clone())
            .context("critical store failure")?;

        let prune_flag: PruneFlag = operation
            .header
            .extract()
            .ok_or(anyhow!("missing 'prune_flag' field in header"))?;

        if prune_flag.0 {
            store.delete_operations(
                operation.header.public_key,
                log_id,
                operation.header.seq_num,
            )?;
        }
    }

    Ok(operation)
}

fn decode_operation(bytes: &[u8]) -> Result<(Header<Extensions>, Option<Body>)> {
    let header_and_body = ciborium::from_reader::<(Header<Extensions>, Option<Body>), _>(bytes)?;
    Ok(header_and_body)
}

fn encode_operation(header: Header<Extensions>, body: Option<Body>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(header, body), &mut bytes)?;
    Ok(bytes)
}
