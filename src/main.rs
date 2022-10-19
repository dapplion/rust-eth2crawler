use discv5::{enr, enr::{CombinedKey, NodeId}, Discv5, Discv5ConfigBuilder};
use std::net::SocketAddr;
use hex;
use sqlx::mysql::MySqlPool;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::env;

use sqlx::{mysql::MySqlPoolOptions};


const ETHEREUM_MAINNET_BOOTNODES: [&str; 4] = [
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
    "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
    "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",
];

#[tokio::main]
async fn main() {
    println!("rust-eth2crawler");

    // mysql://[user[:password]@][host][:port][/dbname][?param1=value1&...]
    // let database_url = "mysql://lion:password@localhost:3306/eth2nodes";
    let database_url = env::var("DATABASE_URL").expect("Must provide DATABASE_URL env");

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url).await.unwrap();

    // listening address and port
    let listen_addr = "0.0.0.0:9000".parse::<SocketAddr>().unwrap();

    let enr_key = CombinedKey::generate_secp256k1();
    let enr = enr::EnrBuilder::new("v4").build(&enr_key).unwrap();

    let config = Discv5ConfigBuilder::new().build();
    let mut discv5 = Discv5::new(enr, enr_key, config).unwrap();

    // In order to bootstrap the routing table an external ENR should be added
    // This can be done via add_enr. I.e.:
    for enr_txt in ETHEREUM_MAINNET_BOOTNODES {
        let enr = enr_txt.parse::<enr::Enr<enr::CombinedKey>>().expect("Invalid base64 encoded ENR");
        discv5.add_enr(enr).unwrap();
        println!("Added boot ENR {:?}", enr_txt);
    }

    // start the discv5 server
    discv5.start(listen_addr).await.unwrap();
    println!("Stared server on {:?}", listen_addr);

    // run a find_node query
    loop {
        let found_enrs = discv5.find_node(NodeId::random()).await.unwrap();

        println!("Found {:?} nodes", found_enrs.len());

        for enr in found_enrs {
            let node_id = enr.node_id();

            let ip = if let Some(ip) = enr.ip4() {
                ip
            } else {
                continue;
            };

            let eth2 = if let Some(eth2) = enr.get("eth2") {
                eth2
            } else {
                continue;
            };

            // eth2 = (
            //     fork_digest: ForkDigest
            //     next_fork_version: Version
            //     next_fork_epoch: Epoch
            // )
            if eth2.len() < 4 + 4 + 8 {
                continue;
            }
            let fork_digest = &eth2[0..4];
            let next_fork_version = &eth2[4..8];
            let next_fork_epoch = &eth2[8..16];

            let attnets: Option<&[u8]> = enr.get("attnets").map(|v| &v[0..8]);
            let syncnets: Option<&[u8]> = enr.get("syncnets").map(|v| &v[0..1]);

            let id = hash_enr(&enr) as i64;

            println!("node {:?} {:?} {:?} id {:?}", ip, hex::encode(eth2), hex::encode(node_id.raw()), id);

            let enr_id = match db_insert_enr(&pool, ENRModel {
                id,
                node_id: &node_id.raw(),
                seq: enr.seq() as i64,
                ip: &ip.octets(),
                tcp: enr.tcp4(),
                udp: enr.udp4(),
                fork_digest,
                next_fork_version,
                next_fork_epoch,
                attnets,
                syncnets,
                seen_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs(),
                enr_txt: enr.to_base64()
            }).await {
                Ok(enr_id) => enr_id,
                Err(error) => {
                    println!("Error insterting ENR: {:?}", error);
                    continue;
                },
            };
        }
    }

    // Crawler has to:
    // - Fetch all possible ENRs
    // - Ping ENRs to ensure they are alive
    // - Run identity libp2p protocol to gather data
    // - Do a status query to check if nodes are synced
}

fn hash_enr(enr: &enr::Enr<CombinedKey>) -> u64 {
    let enr_rlp = rlp::encode(enr);
    let mut s = DefaultHasher::new();
    enr_rlp.hash(&mut s);
    s.finish()
}

pub struct ENRModel<'a> {
    /// Digest of the full ENR for unique identification, SQL suppors only signed types
    pub id: i64,
    pub node_id: &'a[u8],
    pub seq: i64, // SQL suppors only signed types
    pub ip: &'a[u8],
    pub tcp: Option<u16>,
    pub udp: Option<u16>,
    pub fork_digest: &'a[u8],
    pub next_fork_version: &'a[u8],
    // Also in binary since SQL does not support unsigned types, so max value is 2^63-1.
    // Nodes represent not knowing next fork max unsigned value which SQL can't represent
    pub next_fork_epoch: &'a[u8],
    pub attnets: Option<&'a[u8]>,
    pub syncnets: Option<&'a[u8]>,
    pub seen_timestamp: u64,
    pub enr_txt: String,
}

async fn db_insert_enr<'a>(pool: &MySqlPool, enr: ENRModel<'a>) -> Result<u64, sqlx::Error> {
    // Insert the task, then obtain the ID of this row
    let enr_id = sqlx::query!(
        r#"
INSERT INTO enrs ( id, node_id, seq, ip, tcp, udp, fork_digest, next_fork_version, next_fork_epoch, attnets, syncnets, seen_timestamp, enr_txt )
VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
        "#,
        enr.id,
        enr.node_id,
        enr.seq,
        enr.ip,
        enr.tcp,
        enr.udp,
        enr.fork_digest,
        enr.next_fork_version,
        enr.next_fork_epoch,
        enr.attnets,
        enr.syncnets,
        enr.seen_timestamp,
        enr.enr_txt
    )
    .execute(pool)
    .await?
    .last_insert_id();

    Ok(enr_id)
}