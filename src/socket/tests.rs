use super::*;

/// Electing the winner must return while the events channel is stuffed
/// and undrained: the receive task drops events instead of blocking in
/// send, so cancellation always reaches it.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn elect_returns_with_a_full_event_channel() {
    use std::time::Duration;

    let net = nat_lab::sim::Net::seeded("pool_full_channel");
    // The smallest max_sockets holds the scaled capacity at its floor.
    let cfg = PunchConfig {
        max_sockets: 64,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");

    // More packets than the channel capacity, pumped while nobody drains.
    let sender_host = net.public_host();
    let sender = sender_host
        .bind(Family::V4.any_addr())
        .await
        .expect("sender binds");
    for _ in 0..100 {
        sender.send_to(b"stuff", target).await.expect("send");
    }
    // Let the router and the receive task deliver the burst.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The receiver stays alive through the election, which rules out a
    // closed channel as the reason the task finishes.
    let elected = tokio::time::timeout(Duration::from_secs(1), pool.elect(Family::V4, 0)).await;
    drop(rx);
    elected
        .expect("elect returns despite the stuffed channel")
        .expect("winner socket hands over");
}

/// Repeated sends past an exhausted budget must keep failing: a lost
/// rollback would wrap the counter to a huge positive value and let
/// every later send through.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn exhausted_budget_stays_exhausted() {
    let net = nat_lab::sim::Net::seeded("pool_budget_stays_exhausted");
    let cfg = PunchConfig {
        packet_budget: 2,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");

    for _ in 0..2 {
        pool.send(Family::V4, 0, b"x", target).await.expect("send");
    }
    for _ in 0..10 {
        assert!(matches!(
            pool.send(Family::V4, 0, b"x", target).await,
            Err(PunchError::BudgetExhausted)
        ));
    }
    assert_eq!(pool.sent(), 2);
    pool.shutdown().await;
}

/// A send that fails after the budget reservation must return its unit,
/// so a follow-up valid send still goes out.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn failed_send_refunds_the_budget() {
    let net = nat_lab::sim::Net::seeded("pool_budget_refund");
    let cfg = PunchConfig {
        packet_budget: 1,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");

    // The out-of-range index fails after the reservation and refunds.
    let err = pool.send(Family::V4, 9, b"x", target).await.unwrap_err();
    assert!(matches!(
        err,
        PunchError::Internal("send index past the pool group")
    ));

    pool.send(Family::V4, 0, b"x", target)
        .await
        .expect("valid send");
    assert_eq!(pool.sent(), 1);

    // The successful send spent the last unit.
    assert!(matches!(
        pool.send(Family::V4, 0, b"x", target).await,
        Err(PunchError::BudgetExhausted)
    ));
    pool.shutdown().await;
}

/// A pool whose binds all failed must stay bounded: with no live socket
/// the destination admission check would otherwise pass on every send
/// and grow the table without limit.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn an_empty_pool_admits_no_destination() {
    let net = nat_lab::sim::Net::seeded("pool_no_sockets");
    let cfg = PunchConfig {
        max_mappings: 1,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 0, 0)
        .await
        .expect("pool binds empty");
    let target = SocketAddr::from(([203, 0, 113, 9], 40000));
    for _ in 0..4 {
        assert!(matches!(
            pool.send(Family::V4, 0, b"x", target).await,
            Err(PunchError::ConntrackExhausted)
        ));
    }
    assert_eq!(pool.sent(), 0);
    pool.shutdown().await;
}

/// A pool whose every bind failed fails at bind with the last error as
/// its source, so the session names the real cause instead of surfacing
/// a stopped stream later.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn all_failed_binds_fail_fast_with_their_cause() {
    struct Failing;
    impl UdpFactory for Failing {
        type Socket = nat_lab::sim::SimSocket;

        async fn bind(&self, _addr: SocketAddr) -> io::Result<Self::Socket> {
            Err(io::Error::other("simulated descriptor exhaustion"))
        }
    }

    let err = SocketPool::bind(&Failing, &PunchConfig::default(), 2, 1)
        .await
        .map(|_| ())
        .expect_err("a pool that bound nothing fails");
    match err {
        PunchError::BindFailed { source } => assert!(
            source
                .to_string()
                .contains("simulated descriptor exhaustion"),
            "bind failure carries the real cause, got {source}"
        ),
        other => panic!("expected BindFailed, got {other:?}"),
    }
}

/// Targets that cannot be a punch peer never leave the host, whatever
/// the peer signaled. Loopback carries no such restriction, because
/// the NAT lab and the smoke tests run the engine over it.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn unusable_targets_are_rejected() {
    use std::net::Ipv6Addr;

    let net = nat_lab::sim::Net::seeded("pool_target_policy");
    let cfg = PunchConfig::default();
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");

    let bad = [
        SocketAddr::from(([0, 0, 0, 0], 40000)),
        SocketAddr::from(([224, 0, 0, 1], 40000)),
        SocketAddr::from(([255, 255, 255, 255], 40000)),
        SocketAddr::from(([203, 0, 113, 9], 0)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 40000)),
        SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 40000)),
    ];
    for target in bad {
        let err = pool.send(Family::V4, 0, b"x", target).await.unwrap_err();
        assert!(
            matches!(&err, PunchError::UnusableTarget { target: t, .. } if *t == target),
            "target {target} rejected with {err:?}"
        );
    }
    assert_eq!(pool.sent(), 0);

    // Loopback on both families stays a valid destination.
    pool.send(
        Family::V4,
        0,
        b"x",
        SocketAddr::from(([127, 0, 0, 1], 40000)),
    )
    .await
    .expect("v4 loopback sends");
    pool.send(
        Family::V4,
        0,
        b"x",
        SocketAddr::from((Ipv6Addr::LOCALHOST, 40000)),
    )
    .await
    .expect("v6 loopback sends");
    assert_eq!(pool.sent(), 2);
    pool.shutdown().await;
}

/// Refresh queries never take a conntrack slot: the answer is matched
/// to the querying socket, so a full destination table still leaves
/// the data-plane path exactly as bounded as before.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn refresh_sends_skip_the_conntrack_table() {
    let net = nat_lab::sim::Net::seeded("pool_refresh_conntrack");
    let cfg = PunchConfig {
        max_mappings: 1,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");

    // The one allowed destination slot goes to a data-plane target.
    pool.send(Family::V4, 0, b"x", target)
        .await
        .expect("data-plane send");

    // The refresh server is host-configured and conntrack-exempt.
    let server = SocketAddr::from(([203, 0, 113, 30], 3478));
    pool.send_refresh(0, b"q", server)
        .await
        .expect("refresh send");
    assert_eq!(pool.sent(), 2, "refresh counts in the pool stats");

    let other = SocketAddr::from(([203, 0, 113, 9], 40000));
    assert!(matches!(
        pool.send(Family::V4, 0, b"x", other).await,
        Err(PunchError::ConntrackExhausted)
    ));
    pool.shutdown().await;
}

/// The refresh quota is a hard bound: past it every query fails without
/// touching the data-plane budget.
#[cfg(feature = "test-util")]
#[tokio::test(start_paused = true)]
async fn refresh_quota_runs_out() {
    let net = nat_lab::sim::Net::seeded("pool_refresh_quota");
    let cfg = PunchConfig::default();
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let server = SocketAddr::from(([203, 0, 113, 30], 3478));
    for _ in 0..REFRESH_BUDGET {
        pool.send_refresh(0, b"q", server)
            .await
            .expect("quota covers the query");
    }
    assert_eq!(pool.sent(), REFRESH_BUDGET);
    assert!(matches!(
        pool.send_refresh(0, b"q", server).await,
        Err(PunchError::BudgetExhausted)
    ));
    // The data-plane budget stayed whole.
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");
    pool.send(Family::V4, 0, b"x", target)
        .await
        .expect("data-plane budget untouched by refresh");
    pool.shutdown().await;
}

/// Concurrent senders must never overshoot the budget. The reserve is
/// one atomic step per unit, so racing callers cannot read a wrapped
/// counter and slip past an exhausted budget.
#[cfg(feature = "test-util")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sends_never_overshoot_the_budget() {
    const BUDGET: u32 = 32;
    let net = nat_lab::sim::Net::seeded("pool_budget_concurrent");
    let cfg = PunchConfig {
        packet_budget: BUDGET,
        packets_per_sec: 1_000_000,
        ..PunchConfig::default()
    };
    let pool_host = net.public_host();
    let (pool, _rx) = SocketPool::bind(&pool_host, &cfg, 1, 0)
        .await
        .expect("pool binds");
    let target = pool
        .socket(Family::V4, 0)
        .expect("one socket bound")
        .local_addr()
        .expect("sim socket has an address");
    let pool = Arc::new(pool);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = Arc::clone(&pool);
        tasks.push(tokio::spawn(async move {
            let mut wins = 0;
            loop {
                match pool.send(Family::V4, 0, b"x", target).await {
                    Ok(()) => wins += 1,
                    Err(PunchError::BudgetExhausted) => break,
                    Err(e) => panic!("unexpected send error: {e}"),
                }
            }
            wins
        }));
    }
    let mut spent = 0;
    for t in tasks {
        spent += t.await.expect("sender task finished");
    }
    assert_eq!(spent, BUDGET, "exactly the budget went out");
    assert_eq!(pool.sent(), BUDGET);

    let pool = Arc::try_unwrap(pool).ok().expect("tasks released the pool");
    pool.shutdown().await;
}
