use std::{ io::Cursor, net::SocketAddr, sync::{ Arc, Mutex, atomic::{ AtomicBool, Ordering } } };

use aes::Aes128;
use azalea_crypto::Aes128CfbDec;
use azalea_protocol::{
    packets::{
        ClientIntention,
        ConnectionProtocol,
        PROTOCOL_VERSION,
        config::{
            ClientboundConfigPacket,
            ClientboundCustomPayload,
            ClientboundFinishConfiguration,
            ServerboundConfigPacket,
        },
        handshake::ServerboundHandshakePacket,
        login::{
            ClientboundHello,
            ClientboundLoginFinished,
            ClientboundLoginPacket,
            ServerboundLoginPacket,
        },
        status::{
            ClientboundPongResponse,
            ClientboundStatusPacket,
            ClientboundStatusResponse,
            ServerboundStatusPacket,
            c_status_response::{ Players, Version },
        },
    },
    read::{ deserialize_packet, read_raw_packet },
    write::{ encode_to_network_packet, serialize_packet, write_raw_packet },
};
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use rsa::{ Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey };
use tokio::{
    io::AsyncWriteExt,
    net::{ TcpListener, TcpStream, tcp::{ OwnedReadHalf, OwnedWriteHalf } },
    sync::mpsc,
};
use tracing::{ debug, error, info, warn };

use crate::connection::RawConnection;

pub type Aes128CfbEnc = cfb8::Encryptor<Aes128>;

#[derive(Clone)]
pub struct ProxyPlugin {
    pub bind_addr: SocketAddr,
    pub tokio_handle: tokio::runtime::Handle,
}

impl ProxyPlugin {
    pub fn new(bind_addr: SocketAddr, tokio_handle: tokio::runtime::Handle) -> Self {
        Self { bind_addr, tokio_handle }
    }
}

impl Plugin for ProxyPlugin {
    fn build(&self, app: &mut App) {
        let (client_tx, client_rx) = mpsc::unbounded_channel::<PendingClient>();

        let mut rng = rand::rng();
        let private_key = Arc::new(RsaPrivateKey::new(&mut rng, 2048).unwrap());
        let public_key = Arc::new(RsaPublicKey::from(private_key.as_ref()));

        let config_packets: Arc<Mutex<Vec<Box<[u8]>>>> = Arc::new(Mutex::new(Vec::new()));

        let state = ProxyState {
            attached: Arc::new(Mutex::new(None)),
            client_rx: Mutex::new(client_rx),
            config_packets: config_packets.clone(),
        };

        let bind_addr = self.bind_addr;
        let handle = self.tokio_handle.clone();
        std::thread::spawn(move || {
            handle.spawn(run_listener(
                bind_addr,
                private_key,
                public_key,
                client_tx,
                config_packets,
            ));
        });

        app.insert_resource(state)
            .add_systems(PreUpdate, (
                accept_client,
                buffer_config_packets,
                forward_server_to_client,
            ).chain())
            .add_systems(PostUpdate, forward_client_to_server);
    }
}

#[derive(Resource)]
pub struct ProxyState {
    pub attached: Arc<Mutex<Option<AttachedClient>>>,
    client_rx: Mutex<mpsc::UnboundedReceiver<PendingClient>>,
    pub config_packets: Arc<Mutex<Vec<Box<[u8]>>>>,
}

pub struct PendingClient {
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
    pub client_enc_key: [u8; 16],
}

pub struct AttachedClient {
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
}

fn accept_client(state: Res<ProxyState>) {
    let Ok(mut rx) = state.client_rx.try_lock() else { return };
    let Ok(pending) = rx.try_recv() else { return };

    info!("Vanilla client attached");

    *state.attached.lock().unwrap() = Some(AttachedClient {
        serverbound_rx: pending.serverbound_rx,
        clientbound_tx: pending.clientbound_tx,
        disconnected: pending.disconnected,
    });
}

// Accumulate config-state packets from the server into the replay buffer.
// Once the bot enters game state these stop being tapped by the connection plugin.
fn buffer_config_packets(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    for mut conn in conn_query.iter_mut() {
        if conn.state != ConnectionProtocol::Configuration {
            continue;
        }
        let tapped = conn.take_tapped_packets();
        if tapped.is_empty() {
            continue;
        }
        let mut buf = state.config_packets.lock().unwrap();
        for raw in tapped {
            buf.push(raw);
        }
    }
}

fn forward_server_to_client(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    let mut attached = state.attached.lock().unwrap();
    let Some(client) = attached.as_mut() else { return };

    if client.disconnected.load(Ordering::Relaxed) {
        info!("Vanilla client detached");
        *attached = None;
        return;
    }

    for mut conn in conn_query.iter_mut() {
        // Only forward game-state packets to the attached client
        if conn.state != ConnectionProtocol::Game {
            continue;
        }
        for raw in conn.take_tapped_packets() {
            let _ = client.clientbound_tx.send(raw);
        }
    }
}

fn forward_client_to_server(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    let mut attached = state.attached.lock().unwrap();
    let Some(client) = attached.as_mut() else { return };
    let Ok(mut conn) = conn_query.single_mut() else { return };

    // Only forward client packets when the bot is in game state
    if conn.state != ConnectionProtocol::Game {
        // drain and discard so the channel doesn't back up
        while client.serverbound_rx.try_recv().is_ok() {}
        return;
    }

    loop {
        match client.serverbound_rx.try_recv() {
            Ok(raw) => {
                if let Some(net) = conn.net_conn() {
                    if let Err(e) = net.write_raw(&raw) {
                        error!("Proxy: server write failed: {e}");
                        break;
                    }
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                *attached = None;
                break;
            }
        }
    }
}

async fn run_listener(
    bind_addr: SocketAddr,
    private_key: Arc<RsaPrivateKey>,
    public_key: Arc<RsaPublicKey>,
    client_tx: mpsc::UnboundedSender<PendingClient>,
    config_packets: Arc<Mutex<Vec<Box<[u8]>>>>,
) {
    let listener = TcpListener::bind(bind_addr).await.expect("ProxyPlugin: failed to bind");
    info!("ProxyPlugin listening on {bind_addr}");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Proxy: client from {addr}");
                let pk = private_key.clone();
                let pubk = public_key.as_ref().clone();
                let tx = client_tx.clone();
                let cfg = config_packets.clone();
                tokio::spawn(async move {
                    if let Err(e) = do_handshake(stream, pk, pubk, tx, cfg).await {
                        warn!("Proxy handshake error: {e}");
                    }
                });
            }
            Err(e) => error!("Proxy accept error: {e}"),
        }
    }
}

async fn do_handshake(
    stream: TcpStream,
    private_key: Arc<RsaPrivateKey>,
    public_key: RsaPublicKey,
    client_tx: mpsc::UnboundedSender<PendingClient>,
    config_packets: Arc<Mutex<Vec<Box<[u8]>>>>,
) -> anyhow::Result<()> {
    let (mut read, mut write) = stream.into_split();
    let mut buf = Cursor::new(Vec::new());
    let mut dec: Option<Aes128CfbDec> = None;
    let mut enc: Option<Aes128CfbEnc> = None;

    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let handshake = deserialize_packet::<ServerboundHandshakePacket>(
        &mut Cursor::new(&raw as &[u8])
    )?;

    let intention = match &handshake {
        ServerboundHandshakePacket::Intention(p) => p.intention,
    };

    if intention == ClientIntention::Status {
        return handle_status(&mut read, &mut write, &mut buf, &mut dec, &mut enc).await;
    }

    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let pkt = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;
    let (username, profile_id) = match &pkt {
        ServerboundLoginPacket::Hello(p) => (p.name.clone(), p.profile_id),
        _ => anyhow::bail!("expected Hello"),
    };

    let verify_token: [u8; 4] = rand::random();
    let pub_key_der = public_key.to_public_key_der()?.to_vec();
    let pub_key_der_for_hash = pub_key_der.clone();

    let pkt = ClientboundLoginPacket::Hello(ClientboundHello {
        server_id: "".to_string(),
        public_key: pub_key_der,
        challenge: verify_token.to_vec(),
        should_authenticate: true,
    });
    write_raw_packet(&serialize_packet(&pkt)?, &mut write, None, &mut enc).await?;

    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let pkt = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;
    let (enc_secret, enc_challenge) = match &pkt {
        ServerboundLoginPacket::Key(p) => (p.key_bytes.clone(), p.encrypted_challenge.clone()),
        _ => anyhow::bail!("expected Key"),
    };

    let shared_secret = private_key.decrypt(Pkcs1v15Encrypt, &enc_secret)?;
    let decrypted_challenge = private_key.decrypt(Pkcs1v15Encrypt, &enc_challenge)?;
    anyhow::ensure!(decrypted_challenge == verify_token, "challenge mismatch");

    use aes::cipher::KeyIvInit;
    let client_key: [u8; 16] = shared_secret.as_slice().try_into()?;
    dec = Some(Aes128CfbDec::new(&client_key.into(), &client_key.into()));
    enc = Some(Aes128CfbEnc::new(&client_key.into(), &client_key.into()));

    let server_hash = azalea_crypto::hex_digest(
        &azalea_crypto::digest_data(b"", &pub_key_der_for_hash, &shared_secret)
    );
    let url = format!(
        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}",
        username, server_hash
    );
    info!("Proxy: checking hasJoined for username='{}' hash='{}'", username, server_hash);
    let resp = reqwest::get(&url).await?;
    let status = resp.status().as_u16();
    let body = resp.text().await?;
    info!("Proxy: hasJoined status={status} body={body}");
    anyhow::ensure!(status != 204, "Mojang auth failed");
    let profile_json: serde_json::Value = serde_json::from_str(&body)?;
    let uuid = uuid::Uuid::parse_str(profile_json["id"].as_str().unwrap_or(""))
        .unwrap_or(profile_id);
    let name = profile_json["name"].as_str().unwrap_or(&username).to_string();
    info!("Proxy: authenticated {name}");

    let game_profile = azalea_auth::game_profile::GameProfile {
        uuid,
        name,
        properties: Arc::new(azalea_auth::game_profile::GameProfileProperties {
            map: Default::default(),
        }),
    };

    let pkt = ClientboundLoginPacket::LoginFinished(ClientboundLoginFinished { game_profile });
    write_raw_packet(&serialize_packet(&pkt)?, &mut write, None, &mut enc).await?;

    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let _ = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;

    // Replay all config packets the server sent to the bot during its own config phase.
    // This includes registry data, tags, etc. that the client needs before FinishConfiguration.
    let replayed = config_packets.lock().unwrap().clone();
    info!("Proxy: replaying {} config packets to client", replayed.len());
    for raw in &replayed {
        // Skip FinishConfiguration — we send that ourselves at the end
        if let Ok(pkt) = deserialize_packet::<ClientboundConfigPacket>(
            &mut Cursor::new(raw as &[u8])
        ) {
            if matches!(pkt, ClientboundConfigPacket::FinishConfiguration(_)) {
                continue;
            }
        }
        write_raw_packet(raw, &mut write, None, &mut enc).await?;
    }

    // Send finish configuration
    let finish = ClientboundConfigPacket::FinishConfiguration(ClientboundFinishConfiguration);
    write_raw_packet(&serialize_packet(&finish)?, &mut write, None, &mut enc).await?;

    // Drain client config packets until finish configuration ack
    loop {
        let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
        let pkt = deserialize_packet::<ServerboundConfigPacket>(
            &mut Cursor::new(&raw as &[u8])
        )?;
        if let ServerboundConfigPacket::FinishConfiguration(_) = pkt {
            break;
        }
    }

    info!("Proxy: config state done, entering game bridge");

    let (sb_tx, sb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (cb_tx, cb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let disconnected = Arc::new(AtomicBool::new(false));

    let disc_w = disconnected.clone();
    tokio::spawn(async move {
        client_write_task(write, enc, cb_rx, disc_w).await;
    });

    let disc_r = disconnected.clone();
    tokio::spawn(async move {
        client_read_task(read, dec, buf, sb_tx, disc_r).await;
    });

    client_tx.send(PendingClient {
        serverbound_rx: sb_rx,
        clientbound_tx: cb_tx,
        disconnected,
        client_enc_key: client_key,
    })?;

    Ok(())
}

async fn handle_status(
    read: &mut OwnedReadHalf,
    write: &mut OwnedWriteHalf,
    buf: &mut Cursor<Vec<u8>>,
    dec: &mut Option<Aes128CfbDec>,
    enc: &mut Option<Aes128CfbEnc>,
) -> anyhow::Result<()> {
    let raw = read_raw_packet(read, buf, None, dec).await?;
    let _ = deserialize_packet::<ServerboundStatusPacket>(&mut Cursor::new(&raw as &[u8]))?;

    let pkt = ClientboundStatusPacket::StatusResponse(ClientboundStatusResponse {
        description: azalea_chat::FormattedText::from("PearlBot"),
        favicon: None,
        players: Players { max: 1, online: 1, sample: vec![] },
        version: Version { name: "26.1".to_string(), protocol: PROTOCOL_VERSION },
        enforces_secure_chat: None,
    });
    write_raw_packet(&serialize_packet(&pkt)?, write, None, enc).await?;

    let raw = read_raw_packet(read, buf, None, dec).await?;
    let ping = deserialize_packet::<ServerboundStatusPacket>(&mut Cursor::new(&raw as &[u8]))?;
    if let ServerboundStatusPacket::PingRequest(p) = ping {
        let pong = ClientboundStatusPacket::PongResponse(ClientboundPongResponse {
            time: p.time,
        });
        write_raw_packet(&serialize_packet(&pong)?, write, None, enc).await?;
    }

    Ok(())
}

async fn client_write_task(
    mut write: OwnedWriteHalf,
    mut enc: Option<Aes128CfbEnc>,
    mut rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    disconnected: Arc<AtomicBool>,
) {
    while let Some(raw_packet) = rx.recv().await {
        let network_bytes = encode_to_network_packet(&raw_packet, None, &mut enc);
        if let Err(e) = write.write_all(&network_bytes).await {
            debug!("Proxy: client write ended: {e}");
            break;
        }
    }
    disconnected.store(true, Ordering::Relaxed);
}

async fn client_read_task(
    mut read: OwnedReadHalf,
    mut dec: Option<Aes128CfbDec>,
    mut buf: Cursor<Vec<u8>>,
    tx: mpsc::UnboundedSender<Box<[u8]>>,
    disconnected: Arc<AtomicBool>,
) {
    loop {
        match read_raw_packet(&mut read, &mut buf, None, &mut dec).await {
            Ok(raw) => {
                if tx.send(raw).is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!("Proxy: client read ended: {e}");
                break;
            }
        }
    }
    disconnected.store(true, Ordering::Relaxed);
}