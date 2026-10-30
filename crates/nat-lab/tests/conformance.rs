//! Conformance suite: both engines implement the declared `NatSpec`
//! behavior.
//!
//! One test per behavior claim, each run twice: against the deterministic
//! simulator under paused time, and against the loopback lab over real
//! sockets on real time. The behavior bodies read once against the
//! harness's `Engine` surface; only the engine setup differs.

// A test binary's child modules resolve next to the root file, so the
// harness module names its own path to stay inside the conformance folder.
#[path = "conformance/harness.rs"]
mod harness;

use std::{
    collections::HashSet,
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};

use harness::{Engine, LabEng, SimEng, assert_silent, claim_released, recv_from};
use nat_lab::{Allocation, FilterClass, MappingBehavior, NatSpec, UdpIo};

/// How long a non-delivery assertion waits before it declares silence.
const NON_DELIVERY: Duration = Duration::from_millis(300);

/// One narrow-range spec, so the lab's port window discovery stays instant.
/// The step-one increment is the walk the cone presets use.
fn spec(mapping: MappingBehavior, filtering: FilterClass) -> NatSpec {
    NatSpec {
        mapping,
        allocation: Allocation::Increment { step: 1 },
        filtering,
        port_range: 30_000..30_040,
        hairpin: true,
    }
}

/// Builds a 20-byte STUN binding request carrying `tid`.
fn binding_request(tid: [u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&0x0001_u16.to_be_bytes());
    request[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
    request[8..20].copy_from_slice(&tid);
    request
}

/// Decodes the XOR-MAPPED-ADDRESS of one binding reply.
fn xor_mapped(reply: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    let cookie = 0x2112_a442_u32.to_be_bytes();
    if reply.len() < 32
        || u16::from_be_bytes([reply[0], reply[1]]) != 0x0101
        || reply[4..8] != cookie
        || reply[8..20] != tid[..]
        || u16::from_be_bytes([reply[20], reply[21]]) != 0x0020
        || reply[25] != 0x01
    {
        return None;
    }
    let port = u16::from_be_bytes([reply[26], reply[27]]) ^ 0x2112;
    let ip = [
        reply[28] ^ cookie[0],
        reply[29] ^ cookie[1],
        reply[30] ^ cookie[2],
        reply[31] ^ cookie[3],
    ];
    Some(SocketAddr::from((ip, port)))
}

/// Builds a binding request carrying CHANGE-REQUEST with the given flags.
fn change_request(tid: [u8; 12], change_ip: bool, change_port: bool) -> Vec<u8> {
    let mut request = binding_request(tid).to_vec();
    // One attribute: four bytes of header, four of flags.
    request[2..4].copy_from_slice(&8u16.to_be_bytes());
    request.extend_from_slice(&0x0003_u16.to_be_bytes());
    request.extend_from_slice(&4u16.to_be_bytes());
    let mut flags = 0u32;
    if change_ip {
        flags |= 0x0004;
    }
    if change_port {
        flags |= 0x0002;
    }
    request.extend_from_slice(&flags.to_be_bytes());
    request
}

/// Decodes one MAPPED-ADDRESS-shaped attribute (RESPONSE-ORIGIN 0x802b or
/// OTHER-ADDRESS 0x802c), which stays in the clear.
fn plain_address(reply: &[u8], attr: u16) -> Option<SocketAddr> {
    if reply.len() < 20 {
        return None;
    }
    let msg_len = u16::from_be_bytes([reply[2], reply[3]]) as usize;
    let mut at = 20;
    while at + 12 <= 20 + msg_len && at + 12 <= reply.len() {
        let ty = u16::from_be_bytes([reply[at], reply[at + 1]]);
        let len = u16::from_be_bytes([reply[at + 2], reply[at + 3]]) as usize;
        if ty == attr && len == 8 && reply[at + 5] == 0x01 {
            let port = u16::from_be_bytes([reply[at + 6], reply[at + 7]]);
            let ip = [reply[at + 8], reply[at + 9], reply[at + 10], reply[at + 11]];
            return Some(SocketAddr::from((ip, port)));
        }
        at += 4 + len;
    }
    None
}

/// The three discovery destinations of one responder grid plus the
/// OTHER-ADDRESS the primary socket advertises: the queried primary, its
/// port partner on the same IP, the same port on the other IP, and the
/// both-flags corner.
async fn discovery_targets(e: &impl Engine) -> (SocketAddr, SocketAddr, SocketAddr, SocketAddr) {
    let primaries = e.stun_addrs().await;
    let others = e.stun_other_addrs().await;
    assert!(!primaries.is_empty(), "the engine exposes STUN addresses");
    assert!(
        !others.is_empty(),
        "the engine exposes discovery alternates"
    );
    let primary = primaries[0];
    let alt_port = primaries
        .iter()
        .copied()
        .find(|a| a.ip() == primary.ip() && a.port() != primary.port())
        .expect("the primary IP holds a second port");
    let alt_ip = others
        .iter()
        .copied()
        .find(|a| a.port() == primary.port())
        .expect("the other IP answers on the primary port");
    let both = others
        .iter()
        .copied()
        .find(|a| a.port() == alt_port.port())
        .expect("the other IP answers on the alternate port");
    (primary, alt_port, alt_ip, both)
}

/// One client socket sends to two destinations, and both destinations
/// observe the same source address off one mapping.
async fn cone_mapping_reuses_one_port_across_destinations(e: impl Engine) {
    let d1 = e.public_socket().await.expect("d1 binds");
    let d2 = e.public_socket().await.expect("d2 binds");
    let client = e.client().await.expect("client binds");

    client
        .send_to(b"one", d1.local_addr().expect("d1 addr"))
        .await
        .expect("send one");
    client
        .send_to(b"two", d2.local_addr().expect("d2 addr"))
        .await
        .expect("send two");

    let (payload1, from1) = recv_from(&d1).await;
    let (payload2, from2) = recv_from(&d2).await;
    assert_eq!(payload1, b"one");
    assert_eq!(payload2, b"two");
    assert_eq!(from1, from2, "both destinations see one public address");
    e.wait_mappings(1).await;
    assert_eq!(e.mapping_count(), 1, "one mapping serves both destinations");
    let (_, ext) = e.snapshot()[0];
    assert_eq!(
        from1, ext,
        "the observed address is the mapping's external address"
    );
}

/// Two destinations in send order observe the window base, then the base
/// plus one step.
async fn sequential_mapping_walks_one_step_per_destination(e: impl Engine) {
    let d1 = e.public_socket().await.expect("d1 binds");
    let d2 = e.public_socket().await.expect("d2 binds");
    let client = e.client().await.expect("client binds");

    client
        .send_to(b"one", d1.local_addr().expect("d1 addr"))
        .await
        .expect("send one");
    client
        .send_to(b"two", d2.local_addr().expect("d2 addr"))
        .await
        .expect("send two");

    let (_, from1) = recv_from(&d1).await;
    let (_, from2) = recv_from(&d2).await;
    let base = e.port_window().start;
    assert_eq!(from1.port(), base, "the first destination reads the base");
    assert_eq!(from2.port(), base + 2, "the second reads one step past it");
    e.wait_mappings(2).await;
    assert_eq!(e.mapping_count(), 2);
}

/// Two ports of one destination address share one mapping; a second
/// destination address opens its own mapping one step ahead.
async fn address_sequential_shares_one_mapping_per_destination_address(e: impl Engine) {
    let d1 = e.public_socket().await.expect("d1 binds");
    let d2 = e.public_socket().await.expect("d2 binds");
    let client = e.client().await.expect("client binds");

    client
        .send_to(b"a", d1.local_addr().expect("d1 addr"))
        .await
        .expect("send a");
    client
        .send_to(b"b", d2.local_addr().expect("d2 addr"))
        .await
        .expect("send b");
    e.wait_mappings(1).await;
    assert_eq!(e.mapping_count(), 1, "one address holds one mapping");

    let d3 = e.foreign_socket().await.expect("d3 binds");
    client
        .send_to(b"c", d3.local_addr().expect("d3 addr"))
        .await
        .expect("send c");
    e.wait_mappings(2).await;
    assert_eq!(
        e.mapping_count(),
        2,
        "the second address opens its own mapping"
    );

    let (_, from1) = recv_from(&d1).await;
    let (_, from2) = recv_from(&d2).await;
    let (_, from3) = recv_from(&d3).await;
    assert_eq!(
        from1, from2,
        "the address's ports share one external address"
    );
    let base = e.port_window().start;
    assert_eq!(from1.port(), base);
    assert_eq!(
        from3.port(),
        base + 2,
        "the second address sits one step ahead"
    );
}

/// Ten live mappings over a ten-port range all hold distinct ports inside
/// the allocation window.
async fn random_mappings_hold_distinct_ports(e: impl Engine) {
    let mut dests = Vec::new();
    for _ in 0..10 {
        dests.push(e.public_socket().await.expect("destination binds"));
    }
    let client = e.client().await.expect("client binds");
    for dest in &dests {
        client
            .send_to(b"x", dest.local_addr().expect("dest addr"))
            .await
            .expect("send");
    }
    e.wait_mappings(10).await;
    assert_eq!(e.mapping_count(), 10);

    let window = e.port_window();
    let ports: HashSet<u16> = e
        .snapshot()
        .into_iter()
        .map(|(_, ext)| ext.port())
        .collect();
    assert_eq!(ports.len(), 10, "every mapping holds its own port");
    assert!(
        ports.iter().all(|port| window.contains(port)),
        "every port stays inside the allocation window"
    );
}

/// An unsolicited stranger on a foreign IP delivers to the mapping's
/// external address under endpoint-independent filtering.
async fn endpoint_independent_filter_admits_an_unsolicited_stranger(e: impl Engine) {
    let dest = e.public_socket().await.expect("dest binds");
    let client = e.client().await.expect("client binds");
    client
        .send_to(b"hi", dest.local_addr().expect("dest addr"))
        .await
        .expect("mapping opens");
    e.wait_mappings(1).await;
    let (_, ext) = e.snapshot()[0];

    let stranger = e.foreign_socket().await.expect("stranger binds");
    stranger
        .send_to(b"knock", ext)
        .await
        .expect("stranger sends");
    let (payload, from) = recv_from(&client).await;
    assert_eq!(payload, b"knock");
    assert_eq!(
        from,
        stranger.local_addr().expect("stranger addr"),
        "the datagram crossed the mapping from the stranger"
    );
}

/// Under address-dependent filtering, a stranger on an already-sent IP
/// passes and a stranger on a foreign IP is dropped.
async fn address_dependent_filter_splits_by_source_ip(e: impl Engine) {
    let dest = e.public_socket().await.expect("dest binds");
    let client = e.client().await.expect("client binds");
    client
        .send_to(b"hi", dest.local_addr().expect("dest addr"))
        .await
        .expect("mapping opens");
    e.wait_mappings(1).await;
    let (_, ext) = e.snapshot()[0];

    let same_ip = e.public_socket().await.expect("same-ip stranger binds");
    same_ip.send_to(b"pass", ext).await.expect("same-ip send");
    let (payload, from) = recv_from(&client).await;
    assert_eq!(payload, b"pass");
    assert_eq!(from, same_ip.local_addr().expect("stranger addr"));

    let foreign = e.foreign_socket().await.expect("foreign stranger binds");
    foreign.send_to(b"drop", ext).await.expect("foreign send");
    assert_silent(&client, NON_DELIVERY).await;
    e.wait_filter_drops(1).await;
    if let Some(drops) = e.filter_drops() {
        assert_eq!(drops, 1, "the rejected datagram is counted");
    }
}

/// Under address-and-port-dependent filtering, an unsolicited stranger is
/// dropped and the mapped destination still passes.
async fn address_port_dependent_filter_admits_only_sent_destinations(e: impl Engine) {
    let friend = e.public_socket().await.expect("friend binds");
    let client = e.client().await.expect("client binds");
    client
        .send_to(b"hi", friend.local_addr().expect("friend addr"))
        .await
        .expect("mapping opens");
    e.wait_mappings(1).await;
    let (_, ext) = e.snapshot()[0];

    let stranger = e.public_socket().await.expect("stranger binds");
    stranger
        .send_to(b"evil", ext)
        .await
        .expect("stranger sends");
    assert_silent(&client, NON_DELIVERY).await;
    e.wait_filter_drops(1).await;
    if let Some(drops) = e.filter_drops() {
        assert_eq!(drops, 1, "the rejected datagram is counted");
    }

    friend.send_to(b"ok", ext).await.expect("friend sends");
    let (payload, from) = recv_from(&client).await;
    assert_eq!(payload, b"ok");
    assert_eq!(from, friend.local_addr().expect("friend addr"));
}

/// A binding request to every STUN address draws a reply whose
/// XOR-MAPPED-ADDRESS is the address destination sockets observe.
async fn stun_responder_reports_the_mapped_external_address(e: impl Engine) {
    let addrs = e.stun_addrs().await;
    assert!(!addrs.is_empty(), "the engine exposes STUN addresses");
    let dest = e.public_socket().await.expect("dest binds");
    let client = e.client().await.expect("client binds");

    let tid = [0x2a; 12];
    let request = binding_request(tid);
    let mut mapped = HashSet::new();
    for addr in &addrs {
        client
            .send_to(&request, *addr)
            .await
            .expect("binding request sends");
        let (reply, from) = recv_from(&client).await;
        assert_eq!(from, *addr, "the reply comes from the queried server");
        mapped.insert(xor_mapped(&reply, &tid).expect("reply decodes"));
    }
    assert_eq!(
        mapped.len(),
        1,
        "every server reports the same mapped address"
    );
    let ext = mapped.into_iter().next().expect("one mapped address");

    client
        .send_to(b"ping", dest.local_addr().expect("dest addr"))
        .await
        .expect("send");
    let (_, from) = recv_from(&dest).await;
    assert_eq!(from, ext, "destinations observe the address STUN reported");
}

/// Dropping the client socket releases its mappings: the count drains to
/// zero and the peak keeps what existed.
async fn socket_drop_releases_mappings_and_keeps_the_peak(e: impl Engine) {
    let dest = e.public_socket().await.expect("dest binds");
    {
        let client = e.client().await.expect("client binds");
        client
            .send_to(b"x", dest.local_addr().expect("dest addr"))
            .await
            .expect("mapping opens");
        e.wait_mappings(1).await;
        assert_eq!(e.mapping_count(), 1);
    }
    e.wait_drained().await;
    assert_eq!(e.mapping_count(), 0, "the drop released the mapping");
    assert_eq!(e.peak_mappings(), 1, "the peak records what existed");
}

/// Declares one behavior claim on both engines: the simulator under paused
/// time and the lab on real time. Each engine seeds itself with its test
/// name, so a failure reproduces.
macro_rules! conformance {
    ($sim:ident, $lab:ident, $spec:expr, $behavior:ident) => {
        #[tokio::test(start_paused = true)]
        async fn $sim() {
            $behavior(SimEng::new(stringify!($sim), $spec)).await;
        }
        #[tokio::test]
        async fn $lab() {
            $behavior(LabEng::new(stringify!($lab), $spec).await).await;
        }
    };
}

conformance!(
    sim_cone_mapping_reuses_one_port_across_destinations,
    lab_cone_mapping_reuses_one_port_across_destinations,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    cone_mapping_reuses_one_port_across_destinations
);

conformance!(
    sim_sequential_mapping_walks_one_step_per_destination,
    lab_sequential_mapping_walks_one_step_per_destination,
    NatSpec {
        mapping: MappingBehavior::AddressPortDependent,
        allocation: Allocation::Increment { step: 2 },
        filtering: FilterClass::AddressDependent,
        port_range: 30_000..30_040,
        hairpin: true,
    },
    sequential_mapping_walks_one_step_per_destination
);

conformance!(
    sim_address_sequential_shares_one_mapping_per_destination_address,
    lab_address_sequential_shares_one_mapping_per_destination_address,
    NatSpec {
        mapping: MappingBehavior::AddressDependent,
        allocation: Allocation::Increment { step: 2 },
        filtering: FilterClass::AddressDependent,
        port_range: 30_000..30_040,
        hairpin: true,
    },
    address_sequential_shares_one_mapping_per_destination_address
);

conformance!(
    sim_random_mappings_hold_distinct_ports,
    lab_random_mappings_hold_distinct_ports,
    NatSpec {
        mapping: MappingBehavior::AddressPortDependent,
        allocation: Allocation::Random,
        filtering: FilterClass::AddressDependent,
        port_range: 30_000..30_010,
        hairpin: true,
    },
    random_mappings_hold_distinct_ports
);

conformance!(
    sim_endpoint_independent_filter_admits_an_unsolicited_stranger,
    lab_endpoint_independent_filter_admits_an_unsolicited_stranger,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    endpoint_independent_filter_admits_an_unsolicited_stranger
);

conformance!(
    sim_address_dependent_filter_splits_by_source_ip,
    lab_address_dependent_filter_splits_by_source_ip,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::AddressDependent
    ),
    address_dependent_filter_splits_by_source_ip
);

conformance!(
    sim_address_port_dependent_filter_admits_only_sent_destinations,
    lab_address_port_dependent_filter_admits_only_sent_destinations,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::AddressPortDependent
    ),
    address_port_dependent_filter_admits_only_sent_destinations
);

conformance!(
    sim_stun_responder_reports_the_mapped_external_address,
    lab_stun_responder_reports_the_mapped_external_address,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    stun_responder_reports_the_mapped_external_address
);

conformance!(
    sim_socket_drop_releases_mappings_and_keeps_the_peak,
    lab_socket_drop_releases_mappings_and_keeps_the_peak,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    socket_drop_releases_mappings_and_keeps_the_peak
);

conformance!(
    sim_ei_mapping_with_random_allocation_holds_one_port_per_socket,
    lab_ei_mapping_with_random_allocation_holds_one_port_per_socket,
    NatSpec::random_eif(30_000..30_010),
    ei_mapping_with_random_allocation_holds_one_port_per_socket
);

conformance!(
    sim_preserve_allocation_mirrors_the_internal_port_then_walks,
    lab_preserve_allocation_mirrors_the_internal_port_then_walks,
    NatSpec::preserved(FilterClass::AddressDependent)
        .with_mapping(MappingBehavior::AddressPortDependent),
    preserve_allocation_mirrors_the_internal_port_then_walks
);

conformance!(
    sim_discovery_ei_mapping_reports_one_address_for_every_destination,
    lab_discovery_ei_mapping_reports_one_address_for_every_destination,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    discovery_ei_mapping_reports_one_address_for_every_destination
);

conformance!(
    sim_discovery_ad_mapping_splits_by_destination_address,
    lab_discovery_ad_mapping_splits_by_destination_address,
    spec(
        MappingBehavior::AddressDependent,
        FilterClass::AddressDependent
    ),
    discovery_ad_mapping_splits_by_destination_address
);

conformance!(
    sim_discovery_apd_mapping_allocates_per_destination,
    lab_discovery_apd_mapping_allocates_per_destination,
    spec(
        MappingBehavior::AddressPortDependent,
        FilterClass::AddressDependent
    ),
    discovery_apd_mapping_allocates_per_destination
);

conformance!(
    sim_change_request_reply_follows_the_flags,
    lab_change_request_reply_follows_the_flags,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    ),
    change_request_reply_follows_the_flags
);

conformance!(
    sim_change_request_reply_from_an_unsent_port_is_filtered,
    lab_change_request_reply_from_an_unsent_port_is_filtered,
    spec(
        MappingBehavior::AddressPortDependent,
        FilterClass::AddressPortDependent
    ),
    change_request_reply_from_an_unsent_port_is_filtered
);

conformance!(
    sim_hairpin_loops_a_client_back_to_its_sibling,
    lab_hairpin_loops_a_client_back_to_its_sibling,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::AddressPortDependent
    ),
    hairpin_loops_a_client_back_to_its_sibling
);

conformance!(
    sim_hairpin_disabled_drops_the_loop,
    lab_hairpin_disabled_drops_the_loop,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent
    )
    .with_hairpin(false),
    hairpin_disabled_drops_the_loop
);

conformance!(
    sim_cgnat_sibling_loopback_crosses_the_chain,
    lab_cgnat_sibling_loopback_crosses_the_chain,
    spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::AddressDependent
    ),
    cgnat_sibling_loopback_crosses_the_chain
);

/// Endpoint-independent mapping with random allocation: one unpredictable
/// port per socket, shared by every destination. The old single-axis API
/// could not express the pair — its random shape forced a fresh mapping
/// per destination.
async fn ei_mapping_with_random_allocation_holds_one_port_per_socket(e: impl Engine) {
    let d1 = e.public_socket().await.expect("d1 binds");
    let d2 = e.public_socket().await.expect("d2 binds");
    let d3 = e.public_socket().await.expect("d3 binds");
    let c1 = e.client().await.expect("c1 binds");
    let c2 = e.client().await.expect("c2 binds");

    for dest in [&d1, &d2, &d3] {
        c1.send_to(b"a", dest.local_addr().expect("dest addr"))
            .await
            .expect("c1 sends");
    }
    let (_, a1) = recv_from(&d1).await;
    let (_, a2) = recv_from(&d2).await;
    let (_, a3) = recv_from(&d3).await;
    assert_eq!(a1, a2, "the second destination reuses c1's mapping");
    assert_eq!(a2, a3, "the third destination reuses c1's mapping");

    for dest in [&d1, &d2, &d3] {
        c2.send_to(b"b", dest.local_addr().expect("dest addr"))
            .await
            .expect("c2 sends");
    }
    let (_, b1) = recv_from(&d1).await;
    let (_, b2) = recv_from(&d2).await;
    let (_, b3) = recv_from(&d3).await;
    assert_eq!(b1, b2, "the second destination reuses c2's mapping");
    assert_eq!(b2, b3, "the third destination reuses c2's mapping");

    assert_ne!(
        a1, b1,
        "the random draws hand the two sockets distinct ports"
    );
    e.wait_mappings(2).await;
    assert_eq!(e.mapping_count(), 2, "one mapping per socket in total");
    let window = e.port_window();
    assert!(
        window.contains(&a1.port()) && window.contains(&b1.port()),
        "both draws stay inside the allocation window"
    );
}

/// Preserve allocation mirrors the client's internal port while it is
/// free; the socket's next mapping loses that race and falls into the
/// sequential walk through the window.
async fn preserve_allocation_mirrors_the_internal_port_then_walks(e: impl Engine) {
    let d1 = e.public_socket().await.expect("d1 binds");
    let d2 = e.public_socket().await.expect("d2 binds");
    let d3 = e.public_socket().await.expect("d3 binds");
    let client = e.client().await.expect("client binds");
    let internal = client.local_addr().expect("client addr").port();

    client
        .send_to(b"one", d1.local_addr().expect("d1 addr"))
        .await
        .expect("send one");
    e.wait_mappings(1).await;
    let (_, ext1) = e.snapshot()[0];
    assert_eq!(
        ext1.port(),
        internal,
        "the free internal port is mirrored as the external port"
    );

    // The next two mappings want the same mirror and lose the race: the
    // first mapping holds the port, so the walk takes over.
    client
        .send_to(b"two", d2.local_addr().expect("d2 addr"))
        .await
        .expect("send two");
    client
        .send_to(b"three", d3.local_addr().expect("d3 addr"))
        .await
        .expect("send three");
    e.wait_mappings(3).await;
    let base = e.port_window().start;
    let mut ports: Vec<u16> = e
        .snapshot()
        .into_iter()
        .map(|(_, ext)| ext.port())
        .collect();
    ports.sort_unstable();
    let mut expected = vec![base, base + 1, internal];
    expected.sort_unstable();
    assert_eq!(
        ports, expected,
        "the lost mirrors walk the window base upward"
    );
}

/// RFC 5780-style discovery: one client socket probes the primary, its
/// port partner, and the other IP. An endpoint-independent mapping
/// reports one mapped address everywhere.
async fn discovery_ei_mapping_reports_one_address_for_every_destination(e: impl Engine) {
    let (primary, alt_port, alt_ip, _) = discovery_targets(&e).await;
    let client = e.client().await.expect("client binds");
    let mut mapped = Vec::new();
    for (i, target) in [primary, alt_port, alt_ip].into_iter().enumerate() {
        let tid = [0x40 + u8::try_from(i).expect("three targets"); 12];
        client
            .send_to(&binding_request(tid), target)
            .await
            .expect("request sends");
        let (reply, from) = recv_from(&client).await;
        assert_eq!(from, target, "the reply leaves the queried socket");
        assert_eq!(
            plain_address(&reply, 0x802b),
            Some(from),
            "RESPONSE-ORIGIN names the actual source"
        );
        mapped.push(xor_mapped(&reply, &tid).expect("reply decodes"));
    }
    assert!(
        mapped.windows(2).all(|w| w[0] == w[1]),
        "EI mapping reuses one port for every destination: {mapped:?}"
    );
}

/// Discovery over an address-dependent mapping: the same-IP destinations
/// share one mapped address and the other IP opens its own.
async fn discovery_ad_mapping_splits_by_destination_address(e: impl Engine) {
    let (primary, alt_port, alt_ip, _) = discovery_targets(&e).await;
    let client = e.client().await.expect("client binds");
    let mut mapped = Vec::new();
    for (i, target) in [primary, alt_port, alt_ip].into_iter().enumerate() {
        let tid = [0x50 + u8::try_from(i).expect("three targets"); 12];
        client
            .send_to(&binding_request(tid), target)
            .await
            .expect("request sends");
        let (reply, from) = recv_from(&client).await;
        assert_eq!(from, target, "the reply leaves the queried socket");
        mapped.push(xor_mapped(&reply, &tid).expect("reply decodes"));
    }
    assert_eq!(
        mapped[0], mapped[1],
        "the same-IP destination reuses the mapping"
    );
    assert_ne!(mapped[1], mapped[2], "the other IP opens its own mapping");
}

/// Discovery over an address-and-port-dependent mapping: every
/// destination reads its own mapped address.
async fn discovery_apd_mapping_allocates_per_destination(e: impl Engine) {
    let (primary, alt_port, alt_ip, _) = discovery_targets(&e).await;
    let client = e.client().await.expect("client binds");
    let mut mapped = Vec::new();
    for (i, target) in [primary, alt_port, alt_ip].into_iter().enumerate() {
        let tid = [0x60 + u8::try_from(i).expect("three targets"); 12];
        client
            .send_to(&binding_request(tid), target)
            .await
            .expect("request sends");
        let (reply, from) = recv_from(&client).await;
        assert_eq!(from, target, "the reply leaves the queried socket");
        mapped.push(xor_mapped(&reply, &tid).expect("reply decodes"));
    }
    assert_ne!(
        mapped[0], mapped[1],
        "the port partner gets its own mapping"
    );
    assert_ne!(mapped[1], mapped[2], "the other IP gets its own mapping");
    assert_ne!(mapped[0], mapped[2], "every destination stands alone");
}

/// CHANGE-REQUEST reroutes the reply across the grid, and the reply names
/// its actual source plus the OTHER-ADDRESS.
async fn change_request_reply_follows_the_flags(e: impl Engine) {
    let (primary, alt_port, alt_ip, both) = discovery_targets(&e).await;
    let client = e.client().await.expect("client binds");

    // CHANGE-PORT: the reply leaves the port partner on the same IP.
    let tid = [0x71; 12];
    client
        .send_to(&change_request(tid, false, true), primary)
        .await
        .expect("request sends");
    let (reply, from) = recv_from(&client).await;
    assert_eq!(
        from, alt_port,
        "CHANGE-PORT moves the reply to the port partner"
    );
    assert_eq!(
        plain_address(&reply, 0x802b),
        Some(alt_port),
        "RESPONSE-ORIGIN names the actual source"
    );
    assert_eq!(
        plain_address(&reply, 0x802c),
        Some(both),
        "OTHER-ADDRESS names the both-flags corner"
    );

    // CHANGE-IP: the reply leaves the same port on the other IP.
    let tid = [0x72; 12];
    client
        .send_to(&change_request(tid, true, false), primary)
        .await
        .expect("request sends");
    let (reply, from) = recv_from(&client).await;
    assert_eq!(from, alt_ip, "CHANGE-IP moves the reply to the other IP");
    assert_eq!(
        plain_address(&reply, 0x802b),
        Some(alt_ip),
        "RESPONSE-ORIGIN names the actual source"
    );

    // Both flags: the reply leaves the diagonal corner.
    let tid = [0x73; 12];
    client
        .send_to(&change_request(tid, true, true), primary)
        .await
        .expect("request sends");
    let (reply, from) = recv_from(&client).await;
    assert_eq!(from, both, "both flags move the reply to the other address");
    assert_eq!(
        plain_address(&reply, 0x802b),
        Some(both),
        "RESPONSE-ORIGIN names the actual source"
    );
}

/// Under address-and-port-dependent filtering, the CHANGE-PORT reply
/// leaves a source the mapping never sent to and dies at the filter,
/// while the directly addressed alternate still answers.
async fn change_request_reply_from_an_unsent_port_is_filtered(e: impl Engine) {
    let (primary, alt_port, ..) = discovery_targets(&e).await;
    let client = e.client().await.expect("client binds");

    // The queried socket answers and opens the mapping.
    let tid = [0x81; 12];
    client
        .send_to(&binding_request(tid), primary)
        .await
        .expect("request sends");
    let (_, from) = recv_from(&client).await;
    assert_eq!(from, primary);

    // The CHANGE-PORT reply would leave the port partner, a source the
    // mapping never sent to: the filter drops it.
    let tid = [0x82; 12];
    client
        .send_to(&change_request(tid, false, true), primary)
        .await
        .expect("request sends");
    assert_silent(&client, NON_DELIVERY).await;
    e.wait_filter_drops(1).await;
    if let Some(drops) = e.filter_drops() {
        assert_eq!(drops, 1, "the cross-socket reply is counted as filtered");
    }

    // The responder's other socket answers when addressed directly: that
    // destination holds its own mapping.
    let tid = [0x83; 12];
    client
        .send_to(&binding_request(tid), alt_port)
        .await
        .expect("request sends");
    let (_, from) = recv_from(&client).await;
    assert_eq!(from, alt_port, "the directly queried alternate answers");
}

/// Two clients behind one NAT: a datagram one sends to the other's
/// external address loops back through the target mapping (RFC 4787 §6),
/// arriving as if from outside with the sender's external address as the
/// source. The target mapping's filter applies to the looped source: B's
/// early answer toward A is dropped because A has not yet sent to B's
/// external, and the drop counts as filtered; once A has, the loop passes.
async fn hairpin_loops_a_client_back_to_its_sibling(e: impl Engine) {
    let dest = e.public_socket().await.expect("dest binds");
    let scratch = dest.local_addr().expect("dest addr");
    let a = e.client().await.expect("a binds");
    let b = e.client().await.expect("b binds");

    // Both mappings open against a scratch destination.
    b.send_to(b"b", scratch).await.expect("b sends");
    a.send_to(b"a", scratch).await.expect("a sends");
    e.wait_mappings(2).await;
    let snapshot = e.snapshot();
    let ext_of = |local: SocketAddr| {
        snapshot
            .iter()
            .find(|(candidate, _)| *candidate == local)
            .map(|(_, ext)| *ext)
            .expect("mapping in snapshot")
    };
    let ext_a = ext_of(a.local_addr().expect("a addr"));
    let ext_b = ext_of(b.local_addr().expect("b addr"));
    assert_ne!(ext_a, ext_b, "two clients hold distinct mappings");

    // B answers toward A's external before A ever sent there: the loop is
    // filtered at A's mapping and counted.
    b.send_to(b"early", ext_a).await.expect("b sends");
    assert_silent(&a, NON_DELIVERY).await;
    e.wait_filter_drops(1).await;
    if let Some(drops) = e.filter_drops() {
        assert_eq!(drops, 1, "the filtered loop is counted");
    }

    // A sends to B's learned external. B's mapping already sent to A's
    // external through the filtered attempt, so the loop passes and B
    // reads A's external address as the source. The explicit hairpin path
    // delivers once: the private-destination emission cannot re-cross the
    // NAT scan.
    a.send_to(b"hello", ext_b).await.expect("a sends");
    let (payload, from) = recv_from(&b).await;
    assert_eq!(payload, b"hello");
    assert_eq!(
        from, ext_a,
        "the looped datagram carries A's external address"
    );
    assert_silent(&b, NON_DELIVERY).await;
}

/// With hairpinning disabled, a datagram sent to the sibling's external
/// address is dropped after the translation: silence at the sibling, the
/// drop counted, and the sender's mapping still open like a real
/// no-loopback NAT that emitted toward its WAN.
async fn hairpin_disabled_drops_the_loop(e: impl Engine) {
    let dest = e.public_socket().await.expect("dest binds");
    let scratch = dest.local_addr().expect("dest addr");
    let a = e.client().await.expect("a binds");
    let b = e.client().await.expect("b binds");
    b.send_to(b"b", scratch).await.expect("b sends");
    a.send_to(b"a", scratch).await.expect("a sends");
    e.wait_mappings(2).await;
    let snapshot = e.snapshot();
    let ext_b = snapshot
        .iter()
        .find(|(local, _)| *local == b.local_addr().expect("b addr"))
        .map(|(_, ext)| *ext)
        .expect("b's mapping in snapshot");

    a.send_to(b"loop", ext_b).await.expect("a sends");
    assert_silent(&b, NON_DELIVERY).await;
    e.wait_hairpin_drops(1).await;
    if let Some(drops) = e.hairpin_drops() {
        assert_eq!(drops, 1, "the disabled loop is counted");
    }
    assert!(
        e.snapshot()
            .iter()
            .any(|(local, _)| *local == a.local_addr().expect("a addr")),
        "the sender's mapping survives the disabled loop"
    );
}

/// Sends one binding request through `client`'s NAT chain and returns the
/// XOR-MAPPED address the responder reports: the true external address,
/// whatever the chain of NATs assigned.
async fn stun_external<E: Engine, S: UdpIo>(e: &E, client: &S) -> SocketAddr {
    let primary = e.stun_addrs().await.remove(0);
    let tid = [0x3a; 12];
    client
        .send_to(&binding_request(tid), primary)
        .await
        .expect("binding request sends");
    let (reply, _) = recv_from(client).await;
    xor_mapped(&reply, &tid).expect("reply decodes")
}

/// The CGNAT shape: the engine under test is the outer carrier NAT, and
/// two inner cone NATs ride it through [`Engine::spawn_nested`]. Each
/// client learns its true external address through its own chain via
/// STUN; A's datagram to B's learned address hairpins at the outer,
/// crosses both inner NATs, and reaches B carrying A's learned external
/// address as the source. The outer's filter applies to the loop: B's
/// early datagram toward A is dropped because A has not yet sent to B's
/// external, and once A has, the reply passes both directions.
async fn cgnat_sibling_loopback_crosses_the_chain(e: impl Engine) {
    let inner = spec(
        MappingBehavior::EndpointIndependent,
        FilterClass::EndpointIndependent,
    );
    let ea = e.spawn_nested("cgnat_sibling_a", inner.clone()).await;
    let eb = e.spawn_nested("cgnat_sibling_b", inner).await;
    let a = ea.client().await.expect("a binds");
    let b = eb.client().await.expect("b binds");

    let ext_a = stun_external(&ea, &a).await;
    let ext_b = stun_external(&eb, &b).await;
    assert_ne!(ext_a, ext_b, "the outer NAT separates the two chains");

    // B's early datagram toward A's external is filtered at the outer:
    // A's uplink mapping has not sent to B's external yet.
    b.send_to(b"early", ext_a).await.expect("b sends");
    assert_silent(&a, NON_DELIVERY).await;
    e.wait_filter_drops(1).await;
    if let Some(drops) = e.filter_drops() {
        assert_eq!(drops, 1, "the outer filter drops the premature loop");
    }

    // A's datagram to B's learned address crosses both NATs and arrives
    // with A's learned external as the source, exactly once: the looped
    // delivery is injected as a private-destination datagram, so no NAT
    // scan re-translates or duplicates it.
    a.send_to(b"hello", ext_b).await.expect("a sends");
    let (payload, from) = recv_from(&b).await;
    assert_eq!(payload, b"hello");
    assert_eq!(from, ext_a, "the loop carries A's learned external address");
    assert_silent(&b, NON_DELIVERY).await;

    // The reverse direction now passes: each uplink mapping has sent to
    // the sibling's external through the earlier crossings.
    b.send_to(b"reply", ext_a).await.expect("b sends");
    let (payload, from) = recv_from(&a).await;
    assert_eq!(payload, b"reply");
    assert_eq!(
        from, ext_b,
        "the reply carries B's learned external address"
    );

    // The chains release together: closing the inner clients walks the
    // Byes up through both layers.
    drop(a);
    drop(b);
    ea.wait_drained().await;
    eb.wait_drained().await;
    e.wait_drained().await;
    assert_eq!(e.mapping_count(), 0, "every layer drained");
}

/// The simulator keeps a closed socket's mapping in the table for the
/// expiry window and releases it after.
#[tokio::test(start_paused = true)]
async fn sim_mapping_expiry_keeps_translation_for_the_window_then_releases() {
    let e = SimEng::new(
        "sim_mapping_expiry_keeps_translation_for_the_window_then_releases",
        spec(
            MappingBehavior::EndpointIndependent,
            FilterClass::EndpointIndependent,
        ),
    );
    e.set_expiry(Duration::from_secs(30));
    let dest = e.public_socket().await.expect("dest binds");
    let ext = {
        let client = e.client().await.expect("client binds");
        client
            .send_to(b"x", dest.local_addr().expect("dest addr"))
            .await
            .expect("mapping opens");
        e.wait_mappings(1).await;
        e.snapshot()[0].1
    };

    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(e.mapping_count(), 1, "the mapping outlives its socket");
    assert_eq!(
        e.snapshot()[0].1,
        ext,
        "the translation entry stays in place"
    );

    tokio::time::sleep(Duration::from_secs(31)).await;
    assert_eq!(e.mapping_count(), 0, "the expiry released the mapping");
    assert_eq!(e.peak_mappings(), 1, "the peak records what existed");
}

/// The lab keeps a closed socket's mapping translating for the expiry
/// window: a socket rebound at the closed port still receives, and a
/// released external address lands datagrams on whoever claims it.
#[tokio::test]
async fn lab_mapping_expiry_keeps_translation_for_the_window_then_releases() {
    let e = LabEng::new(
        "lab_mapping_expiry_keeps_translation_for_the_window_then_releases",
        spec(
            MappingBehavior::EndpointIndependent,
            FilterClass::EndpointIndependent,
        ),
    )
    .await;
    e.set_expiry(Duration::from_millis(1500));
    let dest = e.public_socket().await.expect("dest binds");
    let (ext, local_port) = {
        let client = e.client().await.expect("client binds");
        client
            .send_to(b"x", dest.local_addr().expect("dest addr"))
            .await
            .expect("mapping opens");
        e.wait_mappings(1).await;
        let ext = e.snapshot()[0].1;
        let port = client.local_addr().expect("client addr").port();
        (ext, port)
    };

    // The rebound socket stands in for the peer the mapping still points
    // at, so a delivery in the window proves the translation lives.
    let reborn = e.client_at(local_port).await;
    let stranger = e.public_socket().await.expect("stranger binds");
    stranger
        .send_to(b"late", ext)
        .await
        .expect("stranger sends");
    let (payload, from) = recv_from(&reborn).await;
    assert_eq!(
        payload, b"late",
        "the mapping still translates in the window"
    );
    assert_eq!(from, stranger.local_addr().expect("stranger addr"));

    e.wait_drained().await;
    assert_eq!(e.mapping_count(), 0, "the expiry released the mapping");
    assert_eq!(e.peak_mappings(), 1);

    // Once the released mapping's socket closed, the external address
    // delivers straight to whoever claims it.
    let probe = claim_released(SocketAddrV4::new(e.public_ip(), ext.port())).await;
    let late = e.public_socket().await.expect("late stranger binds");
    late.send_to(b"gone", ext).await.expect("late send");
    let (payload, from) = recv_from(&probe).await;
    assert_eq!(
        payload, b"gone",
        "the released mapping no longer intercepts"
    );
    assert_eq!(from, late.local_addr().expect("late addr"));
}
