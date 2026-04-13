use std::{ io::Cursor, net::SocketAddr, sync::{ Arc, Mutex, atomic::{ AtomicBool, Ordering } } };

use aes::Aes128;
use simdnbt::owned::{NbtCompound, NbtList, NbtTag};
use simdnbt::Mutf8String;
use azalea_core::{ entity_id::MinecraftEntityId, game_type::{ GameMode, OptionalGameType } };
use azalea_crypto::Aes128CfbDec;
use azalea_entity::{ LookDirection, Position };
use azalea_protocol::common::tags::Tags;
use azalea_protocol::{
    common::movements::{ PositionMoveRotation, RelativeMovements },
    packets::{
        ClientIntention,
        ConnectionProtocol,
        PROTOCOL_VERSION,
        common::CommonPlayerSpawnInfo,
        config::{
            ClientboundConfigPacket,
            ClientboundFinishConfiguration,
            ClientboundUpdateTags as ClientboundConfigUpdateTags,
            ServerboundConfigPacket,
        },
        game::{
            ClientboundGameEvent,
            ClientboundGamePacket,
            ClientboundLogin,
            ClientboundPlayerPosition,
            c_game_event::EventType,
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
use azalea_registry::{
    DataRegistry,
    data::{ DimensionKind, DimensionKindKey },
    identifier::Identifier,
};
use azalea_world::WorldName;
use bevy_app::prelude::*;
use bevy_ecs::prelude::*;
use rsa::{ Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey };
use tokio::{
    io::AsyncWriteExt,
    net::{ TcpListener, TcpStream, tcp::{ OwnedReadHalf, OwnedWriteHalf } },
    sync::mpsc,
};
use tracing::{ debug, error, info, warn };

use crate::{ connection::RawConnection, local_player::LocalGameMode };

pub type Aes128CfbEnc = cfb8::Encryptor<Aes128>;

#[derive(Clone, Debug)]
pub struct CachedGameState {
    pub player_id: MinecraftEntityId,
    pub game_mode: GameMode,
    pub dimension_type: DimensionKindKey,
    pub dimension: Identifier,
    pub seed: i64,
    pub position: azalea_core::position::Vec3,
    pub y_rot: f32,
    pub x_rot: f32,
}

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
        let config_locked = Arc::new(AtomicBool::new(false));
        let game_state: Arc<Mutex<Option<CachedGameState>>> = Arc::new(Mutex::new(None));
        let cached_tags: Arc<Mutex<Option<Box<[u8]>>>> = Arc::new(Mutex::new(None));
        let game_packets: Arc<Mutex<Vec<Box<[u8]>>>> = Arc::new(Mutex::new(Vec::new()));

        let state = ProxyState {
            attached: Arc::new(Mutex::new(None)),
            client_rx: Mutex::new(client_rx),
            config_packets: config_packets.clone(),
            config_locked: config_locked.clone(),
            game_state: game_state.clone(),
            cached_tags: cached_tags.clone(),
            game_packets: game_packets.clone(),
        };

        let bind_addr = self.bind_addr;
        let handle = self.tokio_handle.clone();
        std::thread::spawn(move || {
            handle.spawn(
                run_listener(
                    bind_addr,
                    private_key,
                    public_key,
                    client_tx,
                    config_packets,
                    game_state,
                    cached_tags,
                    game_packets
                )
            );
        });

        app.insert_resource(state)
            .add_systems(
                PreUpdate,
                (
                    accept_client,
                    manage_config_buffer,
                    buffer_config_packets,
                    cache_game_state,
                    forward_server_to_client,
                ).chain()
            )
            .add_systems(PostUpdate, forward_client_to_server);
    }
}

#[derive(Resource)]
pub struct ProxyState {
    pub attached: Arc<Mutex<Option<AttachedClient>>>,
    client_rx: Mutex<mpsc::UnboundedReceiver<PendingClient>>,
    pub config_packets: Arc<Mutex<Vec<Box<[u8]>>>>,
    config_locked: Arc<AtomicBool>,
    pub game_state: Arc<Mutex<Option<CachedGameState>>>,
    pub cached_tags: Arc<Mutex<Option<Box<[u8]>>>>,
    pub game_packets: Arc<Mutex<Vec<Box<[u8]>>>>,
}

pub struct PendingClient {
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
}

pub struct AttachedClient {
    pub serverbound_rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    pub clientbound_tx: mpsc::UnboundedSender<Box<[u8]>>,
    pub disconnected: Arc<AtomicBool>,
}

fn accept_client(state: Res<ProxyState>) {
    let Ok(mut rx) = state.client_rx.try_lock() else {
        return;
    };
    let Ok(pending) = rx.try_recv() else {
        return;
    };
    info!("Vanilla client attached");
    *state.attached.lock().unwrap() = Some(AttachedClient {
        serverbound_rx: pending.serverbound_rx,
        clientbound_tx: pending.clientbound_tx,
        disconnected: pending.disconnected,
    });
}

fn manage_config_buffer(state: Res<ProxyState>, conn_query: Query<&RawConnection>) {
    let Ok(conn) = conn_query.single() else {
        return;
    };
    match conn.state {
        ConnectionProtocol::Configuration => {
            if state.config_locked.load(Ordering::Relaxed) {
                state.config_packets.lock().unwrap().clear();
                state.config_locked.store(false, Ordering::Relaxed);
                info!("Proxy: config buffer cleared for reconnect");
            }
        }
        ConnectionProtocol::Game => {
            if !state.config_locked.load(Ordering::Relaxed) {
                let count = state.config_packets.lock().unwrap().len();
                if count > 0 {
                    info!("Proxy: config buffer locked with {count} packets");
                    state.config_locked.store(true, Ordering::Relaxed);
                }
            }
        }
        _ => {}
    }
}

fn buffer_config_packets(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    for mut conn in conn_query.iter_mut() {
        if
            conn.state != ConnectionProtocol::Configuration ||
            state.config_locked.load(Ordering::Relaxed)
        {
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

fn cache_game_state(
    state: Res<ProxyState>,
    query: Query<(&MinecraftEntityId, &LocalGameMode, &WorldName, &Position, &LookDirection)>
) {
    let Ok((entity_id, game_mode, world_name, position, look)) = query.single() else {
        return;
    };

    let dim_str = world_name.0.to_string();
    let dimension_type = if dim_str.contains("nether") {
        DimensionKindKey::TheNether
    } else if dim_str.contains("end") {
        DimensionKindKey::TheEnd
    } else {
        DimensionKindKey::Overworld
    };

    *state.game_state.lock().unwrap() = Some(CachedGameState {
        player_id: *entity_id,
        game_mode: game_mode.current,
        dimension_type,
        dimension: world_name.0.clone(),
        seed: 0,
        position: **position,
        y_rot: look.y_rot(),
        x_rot: look.x_rot(),
    });
}

fn forward_server_to_client(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    let mut attached = state.attached.lock().unwrap();

    for mut conn in conn_query.iter_mut() {
        if conn.state != ConnectionProtocol::Game {
            continue;
        }
        for raw in conn.take_tapped_packets() {
            // Always cache UpdateTags regardless of client attachment
            if
                let Ok(ClientboundGamePacket::UpdateTags(_)) =
                    deserialize_packet::<ClientboundGamePacket>(&mut Cursor::new(&raw as &[u8]))
            {
                *state.cached_tags.lock().unwrap() = Some(raw.clone());
            }

            if let Some(client) = attached.as_mut() {
                // Client is connected — forward live
                if !client.disconnected.load(Ordering::Relaxed) {
                    let _ = client.clientbound_tx.send(raw);
                }
            } else {
                // No client — cache for replay.
                // If the bot re-enters config mode, clear the cache since all game state
                // will be re-sent after re-config. Don't cache the StartConfiguration itself.
                if let Ok(ClientboundGamePacket::StartConfiguration(_)) =
                    deserialize_packet::<ClientboundGamePacket>(&mut Cursor::new(&raw as &[u8]))
                {
                    state.game_packets.lock().unwrap().clear();
                    info!("Proxy: cleared game packet cache (re-config)");
                } else {
                    state.game_packets.lock().unwrap().push(raw);
                }
            }
        }
    }

    if let Some(client) = attached.as_ref() {
        if client.disconnected.load(Ordering::Relaxed) {
            info!("Vanilla client detached");
            *attached = None;
        }
    }
}

fn forward_client_to_server(state: Res<ProxyState>, mut conn_query: Query<&mut RawConnection>) {
    let mut attached = state.attached.lock().unwrap();
    let Some(client) = attached.as_mut() else {
        return;
    };
    let Ok(mut conn) = conn_query.single_mut() else {
        return;
    };

    if conn.state != ConnectionProtocol::Game {
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
            Err(mpsc::error::TryRecvError::Empty) => {
                break;
            }
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
    game_state: Arc<Mutex<Option<CachedGameState>>>,
    cached_tags: Arc<Mutex<Option<Box<[u8]>>>>,
    game_packets: Arc<Mutex<Vec<Box<[u8]>>>>
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
                let gs = game_state.clone();
                let ct = cached_tags.clone();
                let gp = game_packets.clone();
                tokio::spawn(async move {
                    if let Err(e) = do_handshake(stream, pk, pubk, tx, cfg, gs, ct, gp).await {
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
    game_state: Arc<Mutex<Option<CachedGameState>>>,
    cached_tags: Arc<Mutex<Option<Box<[u8]>>>>,
    game_packets: Arc<Mutex<Vec<Box<[u8]>>>>
) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let (mut read, mut write) = stream.into_split();
    let mut buf = Cursor::new(Vec::new());
    let mut dec: Option<Aes128CfbDec> = None;
    let mut enc: Option<Aes128CfbEnc> = None;

    // Handshake
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

    // Login Hello
    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let pkt = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;
    let (username, profile_id) = match &pkt {
        ServerboundLoginPacket::Hello(p) => (p.name.clone(), p.profile_id),
        _ => anyhow::bail!("expected Hello"),
    };

    let verify_token: [u8; 4] = rand::random();
    let pub_key_der = public_key.to_public_key_der()?.to_vec();
    let pub_key_der_for_hash = pub_key_der.clone();

    write_raw_packet(
        &serialize_packet(
            &ClientboundLoginPacket::Hello(ClientboundHello {
                server_id: "".to_string(),
                public_key: pub_key_der,
                challenge: verify_token.to_vec(),
                should_authenticate: true,
            })
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // Login Key
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

    // Mojang auth
    let server_hash = azalea_crypto::hex_digest(
        &azalea_crypto::digest_data(b"", &pub_key_der_for_hash, &shared_secret)
    );
    info!("Proxy: checking hasJoined for username='{}' hash='{}'", username, server_hash);
    let resp = reqwest::get(
        format!(
            "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}",
            username,
            server_hash
        )
    ).await?;
    anyhow::ensure!(resp.status().as_u16() != 204, "Mojang auth failed");
    let body = resp.text().await?;
    let profile_json: serde_json::Value = serde_json::from_str(&body)?;
    let uuid = uuid::Uuid
        ::parse_str(profile_json["id"].as_str().unwrap_or(""))
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

    write_raw_packet(
        &serialize_packet(
            &ClientboundLoginPacket::LoginFinished(ClientboundLoginFinished { game_profile })
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // LoginAck
    let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
    let _ = deserialize_packet::<ServerboundLoginPacket>(&mut Cursor::new(&raw as &[u8]))?;

    // Config: send all registry data (deduped) + other config packets except FinishConfiguration.
    // Track which registries we actually sent so we can filter tags accordingly.
    // Load the vanilla registry manifest to know which registries we can provide ourselves
    let vanilla_manifest: serde_json::Value =
        serde_json::from_str(include_str!("vanilla_registries.json")).unwrap();
    let vanilla_registry_names: std::collections::HashSet<String> = vanilla_manifest
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let replayed = config_packets.lock().unwrap().clone();
    info!("Proxy: replaying {} config packets", replayed.len());
    let mut seen_registries = std::collections::HashSet::<String>::new();
    let mut forwarded = 0usize;
    for raw in &replayed {
        if
            let Ok(pkt) = deserialize_packet::<ClientboundConfigPacket>(
                &mut Cursor::new(raw as &[u8])
            )
        {
            match &pkt {
                ClientboundConfigPacket::FinishConfiguration(_) => {
                    continue;
                }
                ClientboundConfigPacket::UpdateTags(_) => {
                    // Skip ViaProxy's config-phase tags — we provide our own
                    // filtered tags from the game state + synthesized registries.
                    continue;
                }
                ClientboundConfigPacket::RegistryData(p) => {
                    let reg_id = p.registry_id.to_string();
                    // Skip ViaProxy's version if we have vanilla data — ViaProxy may send
                    // incompatible formats for registries that changed between versions.
                    if vanilla_registry_names.contains(&reg_id) {
                        info!("Proxy: skipping ViaProxy registry {reg_id}, using vanilla data");
                        continue;
                    }
                    if !seen_registries.insert(reg_id.clone()) {
                        continue;
                    }
                    info!("Proxy: forwarding ViaProxy registry {reg_id}");
                }
                _ => {}
            }
            write_raw_packet(raw, &mut write, None, &mut enc).await?;
            forwarded += 1;
        }
    }

    // Synthesize missing registries that the 26.1 client expects but older servers don't send.
    let synthesized = synthesize_missing_registries(&seen_registries);
    for (reg_name, entries) in &synthesized {
        let pkt = ClientboundConfigPacket::RegistryData(
            azalea_protocol::packets::config::ClientboundRegistryData {
                registry_id: reg_name.parse().unwrap(),
                entries: entries.clone(),
            },
        );
        write_raw_packet(&serialize_packet(&pkt)?, &mut write, None, &mut enc).await?;
        seen_registries.insert(reg_name.clone());
        forwarded += 1;
        info!("Proxy: synthesized {reg_name} registry");
    }

    // Send UpdateTags from game state, filtered to only registries the client knows about.
    // We keep tags for registries we explicitly sent AND tags for any built-in client registry.
    // Only filter out registries that are known to cause issues (e.g. ViaProxy artifacts).
    let tags_clone = cached_tags.lock().unwrap().clone();
    if let Some(game_tags_raw) = tags_clone {
        if
            let Ok(ClientboundGamePacket::UpdateTags(mut p)) =
                deserialize_packet::<ClientboundGamePacket>(
                    &mut Cursor::new(&game_tags_raw as &[u8])
                )
        {
            // Remove tags for registries the client didn't receive via RegistryData and that
            // aren't built-in. In practice the only problematic ones are ViaProxy artifacts
            // like "minecraft:timeline" that don't exist in the target version.
            p.tags.0.retain(|k, _| {
                let s = k.to_string();
                // Keep if we sent this registry, or if it's a vanilla built-in (starts with "minecraft:")
                // and isn't a known ViaProxy artifact.
                seen_registries.contains(&s) || (s.starts_with("minecraft:") && s != "minecraft:timeline")
            });

            // Inject tags for synthesized registries that need them
            for (reg, tags) in synthesize_missing_tags(&seen_registries, &synthesized) {
                let reg_id: Identifier = reg.parse().unwrap();
                if !p.tags.0.contains_key(&reg_id) {
                    p.tags.0.insert(reg_id, tags);
                }
            }

            let config_tags_pkt = ClientboundConfigPacket::UpdateTags(ClientboundConfigUpdateTags {
                tags: p.tags,
            });
            write_raw_packet(
                &serialize_packet(&config_tags_pkt)?,
                &mut write,
                None,
                &mut enc
            ).await?;
            forwarded += 1;
            info!("Proxy: sent filtered game tags");
        }
    } else {
        warn!("Proxy: no cached tags available");
    }
    info!("Proxy: forwarded {forwarded} config packets");

    // FinishConfiguration
    write_raw_packet(
        &serialize_packet(
            &ClientboundConfigPacket::FinishConfiguration(ClientboundFinishConfiguration)
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // Wait for client FinishConfiguration ack
    loop {
        let raw = read_raw_packet(&mut read, &mut buf, None, &mut dec).await?;
        let pkt = deserialize_packet::<ServerboundConfigPacket>(&mut Cursor::new(&raw as &[u8]))?;
        if let ServerboundConfigPacket::FinishConfiguration(_) = pkt {
            break;
        }
    }

    // Synthesize game join from cached ECS state
    let gs = game_state.lock().unwrap().clone();
    let Some(gs) = gs else {
        anyhow::bail!("bot not in game state, cannot synthesize login");
    };
    info!("Proxy: synthesizing login at {:?}", gs.position);

    let dim_protocol_id: u32 = match gs.dimension_type {
        DimensionKindKey::TheNether => 3,
        DimensionKindKey::TheEnd => 2,
        DimensionKindKey::OverworldCaves => 1,
        DimensionKindKey::Overworld | DimensionKindKey::Other(_) => 0,
    };

    write_raw_packet(
        &serialize_packet(
            &ClientboundGamePacket::Login(ClientboundLogin {
                player_id: gs.player_id,
                hardcore: false,
                levels: vec![
                    "minecraft:overworld".parse::<Identifier>().unwrap(),
                    "minecraft:the_nether".parse::<Identifier>().unwrap(),
                    "minecraft:the_end".parse::<Identifier>().unwrap()
                ],
                max_players: 100,
                chunk_radius: 8,
                simulation_distance: 8,
                reduced_debug_info: false,
                show_death_screen: true,
                do_limited_crafting: false,
                common: CommonPlayerSpawnInfo {
                    dimension_type: <DimensionKind as DataRegistry>::new_raw(dim_protocol_id),
                    dimension: gs.dimension.clone(),
                    seed: gs.seed,
                    game_type: gs.game_mode,
                    previous_game_type: OptionalGameType(None),
                    is_debug: false,
                    is_flat: false,
                    last_death_location: None,
                    portal_cooldown: 0,
                    sea_level: 63,
                },
                enforces_secure_chat: false,
            })
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // WaitForLevelChunks
    write_raw_packet(
        &serialize_packet(
            &ClientboundGamePacket::GameEvent(ClientboundGameEvent {
                event: EventType::WaitForLevelChunks,
                param: 0.0,
            })
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // Player position
    write_raw_packet(
        &serialize_packet(
            &ClientboundGamePacket::PlayerPosition(ClientboundPlayerPosition {
                id: 0,
                change: PositionMoveRotation {
                    pos: gs.position,
                    delta: azalea_core::position::Vec3::ZERO,
                    look_direction: LookDirection::new(gs.y_rot, gs.x_rot),
                },
                relative: RelativeMovements::default(),
            })
        )?,
        &mut write,
        None,
        &mut enc
    ).await?;

    // Replay all cached game packets (chunks, inventory, entities, etc.)
    // Filter out StartConfiguration packets — the bot may have gone through re-config,
    // and replaying StartConfiguration would put the client into config mode where
    // subsequent game packets get misinterpreted (packet IDs are reused across states).
    let cached_game = game_packets.lock().unwrap().drain(..).collect::<Vec<_>>();
    let mut game_replayed = 0usize;
    for raw in &cached_game {
        if let Ok(pkt) = deserialize_packet::<ClientboundGamePacket>(&mut Cursor::new(raw as &[u8])) {
            match &pkt {
                // Skip packets that would cause state transitions or conflict
                // with the synthetic login we already sent.
                ClientboundGamePacket::StartConfiguration(_) |
                ClientboundGamePacket::Login(_) |
                ClientboundGamePacket::Respawn(_) => {
                    info!("Proxy: skipping {:?} in game packet replay", std::mem::discriminant(&pkt));
                    continue;
                }
                _ => {}
            }
        }
        write_raw_packet(raw, &mut write, None, &mut enc).await?;
        game_replayed += 1;
    }
    info!("Proxy: replayed {game_replayed}/{} cached game packets", cached_game.len());

    info!("Proxy: synthetic join complete, entering game bridge");

    let (sb_tx, sb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let (cb_tx, cb_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
    let disconnected = Arc::new(AtomicBool::new(false));

    client_tx.send(PendingClient {
        serverbound_rx: sb_rx,
        clientbound_tx: cb_tx,
        disconnected: disconnected.clone(),
    })?;

    let disc_w = disconnected.clone();
    tokio::spawn(async move { client_write_task(write, enc, cb_rx, disc_w).await });

    let disc_r = disconnected.clone();
    tokio::spawn(async move { client_read_task(read, dec, buf, sb_tx, disc_r).await });

    Ok(())
}

async fn handle_status(
    read: &mut OwnedReadHalf,
    write: &mut OwnedWriteHalf,
    buf: &mut Cursor<Vec<u8>>,
    dec: &mut Option<Aes128CfbDec>,
    enc: &mut Option<Aes128CfbEnc>
) -> anyhow::Result<()> {
    let raw = read_raw_packet(read, buf, None, dec).await?;
    let _ = deserialize_packet::<ServerboundStatusPacket>(&mut Cursor::new(&raw as &[u8]))?;

    write_raw_packet(
        &serialize_packet(
            &ClientboundStatusPacket::StatusResponse(ClientboundStatusResponse {
                description: azalea_chat::FormattedText::from("PearlBot"),
                favicon: None,
                players: Players { max: 1, online: 1, sample: vec![] },
                version: Version { name: "26.1".to_string(), protocol: PROTOCOL_VERSION },
                enforces_secure_chat: None,
            })
        )?,
        write,
        None,
        enc
    ).await?;

    let raw = read_raw_packet(read, buf, None, dec).await?;
    let ping = deserialize_packet::<ServerboundStatusPacket>(&mut Cursor::new(&raw as &[u8]))?;
    if let ServerboundStatusPacket::PingRequest(p) = ping {
        write_raw_packet(
            &serialize_packet(
                &ClientboundStatusPacket::PongResponse(ClientboundPongResponse { time: p.time })
            )?,
            write,
            None,
            enc
        ).await?;
    }

    Ok(())
}

async fn client_write_task(
    mut write: OwnedWriteHalf,
    mut enc: Option<Aes128CfbEnc>,
    mut rx: mpsc::UnboundedReceiver<Box<[u8]>>,
    disconnected: Arc<AtomicBool>
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
    disconnected: Arc<AtomicBool>
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

/// Convert a serde_json::Value to a simdnbt NbtTag, following Minecraft's NbtOps conventions.
fn json_to_nbt(value: &serde_json::Value) -> NbtTag {
    match value {
        serde_json::Value::Bool(b) => NbtTag::Byte(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                NbtTag::Int(i as i32)
            } else {
                NbtTag::Double(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => NbtTag::String(s.as_str().into()),
        serde_json::Value::Array(arr) => {
            NbtTag::List(json_array_to_list(arr))
        }
        serde_json::Value::Object(map) => {
            let values: Vec<(Mutf8String, NbtTag)> = map
                .iter()
                .map(|(k, v)| (Mutf8String::from(k.as_str()), json_to_nbt(v)))
                .collect();
            NbtTag::Compound(NbtCompound::from_values(values))
        }
        serde_json::Value::Null => NbtTag::Byte(0),
    }
}

fn json_array_to_list(arr: &[serde_json::Value]) -> NbtList {
    if arr.is_empty() {
        return NbtList::Empty;
    }
    match &arr[0] {
        serde_json::Value::Object(_) => {
            let compounds: Vec<NbtCompound> = arr.iter().map(|v| {
                match json_to_nbt(v) {
                    NbtTag::Compound(c) => c,
                    _ => NbtCompound::new(),
                }
            }).collect();
            NbtList::Compound(compounds)
        }
        serde_json::Value::String(_) => {
            let strings: Vec<Mutf8String> = arr.iter().filter_map(|v| {
                v.as_str().map(Mutf8String::from)
            }).collect();
            NbtList::String(strings)
        }
        serde_json::Value::Number(_) => {
            // Check if all values are integers
            if arr.iter().all(|v| v.as_i64().is_some()) {
                let ints: Vec<i32> = arr.iter().filter_map(|v| v.as_i64().map(|i| i as i32)).collect();
                NbtList::Int(ints)
            } else {
                let doubles: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
                NbtList::Double(doubles)
            }
        }
        serde_json::Value::Bool(_) => {
            let bytes: Vec<i8> = arr.iter().map(|v| if v.as_bool().unwrap_or(false) { 1 } else { 0 }).collect();
            NbtList::Byte(bytes)
        }
        _ => NbtList::Empty,
    }
}

fn json_to_compound(value: &serde_json::Value) -> NbtCompound {
    match json_to_nbt(value) {
        NbtTag::Compound(c) => c,
        _ => NbtCompound::new(),
    }
}

/// Parses the bundled vanilla 26.1 registry data and returns entries for any registry
/// not already in `seen_registries`. This handles all registries that ViaProxy might
/// not provide when translating from older server versions.
fn synthesize_missing_registries(
    seen_registries: &std::collections::HashSet<String>,
) -> Vec<(String, Vec<(Identifier, Option<NbtCompound>)>)> {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("vanilla_registries.json")).unwrap();

    let mut result = Vec::new();
    if let serde_json::Value::Object(registries) = &manifest {
        for (reg_name, entries) in registries {
            if seen_registries.contains(reg_name) {
                continue;
            }
            if let serde_json::Value::Object(entries_map) = entries {
                let parsed: Vec<(Identifier, Option<NbtCompound>)> = entries_map
                    .iter()
                    .map(|(name, data)| {
                        (name.parse().unwrap(), Some(json_to_compound(data)))
                    })
                    .collect();
                result.push((reg_name.clone(), parsed));
            }
        }
    }
    result
}

/// Parses the bundled vanilla 26.1 tag data and injects tags for any registry
/// that we synthesized. Tags reference entries by protocol ID (index in the entries list).
fn synthesize_missing_tags(
    seen_registries: &std::collections::HashSet<String>,
    synthesized_registries: &[(String, Vec<(Identifier, Option<NbtCompound>)>)],
) -> Vec<(String, Vec<Tags>)> {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("vanilla_tags.json")).unwrap();

    let mut result = Vec::new();
    if let serde_json::Value::Object(tag_registries) = &manifest {
        for (reg_name, tag_entries) in tag_registries {
            // Only inject tags for registries we synthesized
            let synth = synthesized_registries.iter().find(|(n, _)| n == reg_name);
            if synth.is_none() && seen_registries.contains(reg_name) {
                continue;
            }

            if let serde_json::Value::Object(tags_map) = tag_entries {
                // Build name→index lookup for entries in this registry
                let entry_index: std::collections::HashMap<String, i32> = if let Some((_, entries)) = synth {
                    entries.iter().enumerate().map(|(i, (id, _))| (id.to_string(), i as i32)).collect()
                } else {
                    continue;
                };

                let tags: Vec<Tags> = tags_map
                    .iter()
                    .map(|(tag_name, values)| {
                        let elements: Vec<i32> = values
                            .as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|v| {
                                let s = v.as_str()?;
                                if s.starts_with('#') {
                                    None // Skip tag references, they need recursive resolution
                                } else {
                                    entry_index.get(s).copied()
                                }
                            })
                            .collect();
                        Tags { name: tag_name.parse().unwrap(), elements }
                    })
                    .collect();
                result.push((reg_name.clone(), tags));
            }
        }
    }
    result
}
