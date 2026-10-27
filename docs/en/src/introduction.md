# Introduction

punch-hole establishes a direct UDP path between two peers that sit behind NAT devices. The library classifies both NATs, agrees on a punching strategy with the peer, executes it, and returns a plain `tokio::net::UdpSocket`.

Two design decisions shape everything else.

**The host owns the signaling.** Peer discovery and the control channel stay with the host application. The library emits opaque frames, the host forwards them to the peer over its own transport, and the frames that come back go straight into the library. A system that already runs its own RPC or tunnel protocol adds hole punching as a feature on top of what it has.

**The deliverable is a raw socket.** A successful session returns one standard UDP socket with no wrapper attached. The business layer decides what runs on top, whether that is QUIC, KCP, Noise, or a private protocol.

## Principles

Four principles govern every decision in the code.

- **Bring your own signaling.** The library ships zero server code and zero client code for signaling. The host decides how frames reach the peer.
- **Two roles replace identities.** A session has an Initiator and a Responder. The only identity-like value is the per-attempt nonce that tags data-plane packets.
- **Raw socket delivery.** Every socket the session opened besides the winner closes before the call returns, so ports and descriptors stay clean.
- **Fail fast.** Every phase carries a deadline and the session carries a hard wall-clock limit. Failures return a typed error that names the phase.

## What the host takes on

The library covers one attempt. The host decides everything around it:

- an ordered, authenticated channel for signaling frames,
- the retry policy across attempts,
- the fallback to a relay when a punch fails,
- the protocol that runs on the delivered socket.

[Getting started](getting-started.md) walks through each of these.

## About this book

The book serves two audiences at once, and the parts are ordered so a newcomer can read straight through.

1. **Understanding UDP hole punching** teaches the problem. It builds the NAT picture from zero up to the birthday attack, so every library decision lands on familiar ground.
2. **Using the library** walks the API, the signaling bridge, and the host responsibilities.
3. **Reference** specifies the architecture, the wire protocol, resource limits, configuration, and the test system, and closes with the current limits of the library.

The book exists in English and Chinese. The button in the toolbar switches between them, chapter for chapter.
