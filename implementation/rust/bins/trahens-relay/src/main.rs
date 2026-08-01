// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

use codec_m2::{Candidate, Control, Discover, Envelope, Message, MessageType};
use node_runtime::p1::{offer_label, wrap_candidate, OFFER_LABEL_WINDOW};
use node_runtime::{
    drain_in_precedence_order, drain_links, event_channel, parse_hex, spawn_link, structured_event,
    write_link_metrics, CliArgs, Clock, LinkConfig, LinkEvent, LinkMetrics, NodeQueueBudget,
    RemoteInputDrops,
};
use protocol_registry::{
    ERROR_INTERNAL, ERROR_MALFORMED, ERROR_RESOURCE_EXHAUSTED, ERROR_STATE_VIOLATION,
    ERROR_TIMEOUT, LIMIT_MAX_CANDIDATE_LAYERS, LIMIT_MAX_FANOUT_CLASS, SUITE_R1,
};
use rendezvous_r1::suite::{require_network_provider, EligibilitySuite, R1Suite};
use state_machine::{Event, IngressAdmission, Phase, RouteTable};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
use trahens_crypto::{blind_public, initialize, random_nonzero_16, random_scalar, SecretBytes};

/// One forwarded child of a branch. Core v1.5 section 5 requires every child
/// to receive independently replaced context, so each carries its own label,
/// blinding factor, and discovery nonce.
///
/// Both 32-byte fields are key material and neither may be copied casually.
/// The blinding factor derives the child's reply key. The discovery nonce
/// became a key when offer labels started being derived from it: anyone
/// holding it can compute the labels a child will answer on, so it is what
/// keeps successive labels unlinkable to an observer. It is confidential to
/// this hop, travels only inside the adjacent authenticated link, and is
/// never reused across children or branches. `SecretBytes` wipes both on
/// drop, and because it is not `Clone` neither is this type, so the route
/// table holds exactly one copy of each.
struct RelayChild {
    link_index: usize,
    child_label: [u8; 16],
    blinding_factor: SecretBytes<32>,
    child_discovery_nonce: SecretBytes<32>,
}

/// What a label this relay knows resolves to.
///
/// Both kinds answer the same question — which branch is this? — and control
/// resolution never cares which kind it found, so they share one namespace.
/// Two maps meant every lookup site had to know in advance which to try, and
/// the candidate path ended up registering a label it had just resolved from
/// the other one.
#[derive(Clone, Copy)]
enum LabelBinding {
    /// A branch token minted for a child in a DISCOVER, or the token a child
    /// answers control on. Resolves to the branch and no further.
    Branch { parent_label: [u8; 16] },
    /// A label reserved for one of a child's offers, derived from the
    /// discovery nonce that child was given so both ends compute the same
    /// sequence without it appearing as a pattern on the wire. Resolves to the
    /// branch and to which child, which is what makes a COMMIT selective. A
    /// sliding window keeps live state small while the total per child stays
    /// bounded by the registry's response ceiling.
    Offer {
        parent_label: [u8; 16],
        child_index: usize,
        index: u16,
    },
}

impl LabelBinding {
    fn parent_label(self) -> [u8; 16] {
        match self {
            Self::Branch { parent_label } | Self::Offer { parent_label, .. } => parent_label,
        }
    }
}

/// One CANDIDATE this relay forwarded upstream.
///
/// Every returned offer gets its own tentative selector, so the initiator can
/// name the exact chain it chose. Addressing COMMIT with the branch token
/// instead would name the branch but not which child answered, and the relay
/// would have to guess — in practice by taking the first arrival, which is
/// rarely the candidate the initiator selects.
#[derive(Clone)]
struct TentativeOffer {
    parent_label: [u8; 16],
    child_index: usize,
    /// Token the child accepts control on: its own tentative selector, or its
    /// branch token when the child is a gateway.
    child_selector: [u8; 16],
}

/// Not `Clone`: it owns `parent_discovery_nonce`, which derives the labels
/// this relay answers its own parent on, and every child's key material.
struct RelayRoute {
    parent_label: [u8; 16],
    children: Vec<RelayChild>,
    /// Index of the child named by the COMMIT that arrived. Control traffic
    /// follows that child; until a COMMIT arrives there is nothing to forward.
    committed_child: Option<usize>,
    /// Tentative selector the initiator committed to. Upstream control is
    /// rewritten to it so the initiator recognises its own route.
    committed_selector: Option<[u8; 16]>,
    /// How many offers this branch has already forwarded upstream, which fixes
    /// the next parent-facing label to derive.
    offers_forwarded: u16,
    incoming_reply_public: [u8; 32],
    depth: u8,
    parent_discovery_nonce: SecretBytes<32>,
    generation: u32,
}

/// What a branch looks like to code that routes control messages.
///
/// Control forwarding needs labels, link indices, and the committed child; it
/// never needs key material. Copying this out of the route table lets the
/// borrow end before the table is mutated, which is what the old
/// `RelayRoute::clone` was for — except that clone also duplicated every
/// blinding factor and discovery nonce, once per control message.
#[derive(Clone)]
struct RouteView {
    parent_label: [u8; 16],
    generation: u32,
    committed_child: Option<usize>,
    committed_selector: Option<[u8; 16]>,
    children: Vec<ChildView>,
}

/// The non-secret half of a [`RelayChild`].
#[derive(Clone, Copy)]
struct ChildView {
    link_index: usize,
    child_label: [u8; 16],
}

impl RelayRoute {
    fn view(&self) -> RouteView {
        RouteView {
            parent_label: self.parent_label,
            generation: self.generation,
            committed_child: self.committed_child,
            committed_selector: self.committed_selector,
            children: self
                .children
                .iter()
                .map(|child| ChildView {
                    link_index: child.link_index,
                    child_label: child.child_label,
                })
                .collect(),
        }
    }
}

/// Failure teardown returned along the reverse path.
///
/// `messages-v1.5.md` separates three teardowns: CANCEL is advisory, CLOSE is
/// orderly, and ABORT is failure. E1 section 12 has a relay that cannot
/// reserve route capacity, or cannot find its tentative state, release what it
/// holds by abort. Dropping such a COMMIT silently, as this did, leaves the
/// initiator waiting out a deadline for a route that already failed.
///
/// The body is empty: the relay holds no route secret for either end, so there
/// is nothing it could seal, and section 8's uniform failure behaviour means
/// it must not distinguish why beyond the message type itself.
fn abort_control(label: [u8; 16], generation: u32) -> Envelope {
    Envelope {
        suite_id: SUITE_R1,
        message: Message::Control(Control {
            message_type: MessageType::Abort,
            local_label: label,
            generation,
            expiry_class: 1,
            protected_body: vec![0_u8],
        }),
    }
}

fn forward_control(message: Control, label: [u8; 16]) -> Envelope {
    Envelope {
        suite_id: SUITE_R1,
        message: Message::Control(Control {
            local_label: label,
            ..message
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_route(
    parent: [u8; 16],
    routes: &mut HashMap<[u8; 16], RelayRoute>,
    labels: &mut HashMap<[u8; 16], LabelBinding>,
    tentatives: &mut HashMap<[u8; 16], TentativeOffer>,
    states: &mut RouteTable,
    event: Event,
    now_ms: u64,
) {
    if routes.remove(&parent).is_some() {
        let _ = states.apply(parent, event, now_ms);
    }
    // Every label that resolved to this branch goes with it, whichever kind it
    // was, along with the tentative selectors this relay handed upstream.
    labels.retain(|_, binding| binding.parent_label() != parent);
    tentatives.retain(|_, offer| offer.parent_label != parent);
}

/// Reclaim every branch whose deadline has passed.
///
/// `event-lifecycle-profile-e1.md` section 9 requires expiry to be local and
/// non-blocking, and section 2 ranks it above every message sharing the same
/// timestamp. It therefore runs once per loop iteration, before any event is
/// processed: driving it only from an idle channel lets continuous traffic
/// keep expired state usable indefinitely.
fn reclaim_expired(
    now_ms: u64,
    routes: &mut HashMap<[u8; 16], RelayRoute>,
    labels: &mut HashMap<[u8; 16], LabelBinding>,
    tentatives: &mut HashMap<[u8; 16], TentativeOffer>,
    states: &mut RouteTable,
) -> usize {
    let expired: Vec<[u8; 16]> = routes
        .keys()
        .filter(|label| {
            states
                .get(label)
                .is_none_or(|state| state.expires_at_ms <= now_ms)
        })
        .copied()
        .collect();
    let count = expired.len();
    for label in expired {
        cleanup_route(
            label,
            routes,
            labels,
            tentatives,
            states,
            Event::Timeout,
            now_ms,
        );
    }
    // A state entry can outlive its route map entry, so sweep the table too.
    states.expire(now_ms);
    count
}

fn collect_stopped(
    receiver: &std::sync::mpsc::Receiver<LinkEvent>,
    expected: usize,
) -> Vec<(u32, LinkMetrics)> {
    let mut output = Vec::new();
    while output.len() < expected {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(LinkEvent::Stopped { peer_id, metrics }) => output.push((peer_id, metrics)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    output
}

fn run() -> Result<(), Box<dyn Error>> {
    initialize()?;
    let args = CliArgs::parse()?;
    let node_id = args.u32("id")?;
    let upstream_id = args.u32("upstream-id")?;
    let epoch = args.u32("epoch")?;
    // Which T2 schedule profile this node runs. The mandatory P1 path is
    // fixed; adaptive renegotiates its rate and is therefore outside the
    // fixed-trace claim, which is a claim about a constant cadence.
    let schedule_profile = args.optional("schedule-profile", "fixed").to_owned();
    let adaptive = match schedule_profile.as_str() {
        "fixed" => false,
        "adaptive" => true,
        other => {
            return Err(format!("unknown --schedule-profile: {other}").into());
        }
    };
    let timeout_ms = args.u64_or("timeout-ms", 30_000)?;
    let metrics_path = args.optional("metrics", "relay-metrics.json").to_owned();

    let (event_sender, event_receiver) = event_channel();
    // One budget shared by the upstream link and every child: the node-global
    // cell ceiling is a property of the process, not of any one link.
    let budget = NodeQueueBudget::new();
    let upstream = spawn_link(
        LinkConfig {
            local_id: node_id,
            peer_id: upstream_id,
            bind: args.socket("upstream-bind")?,
            peer: args.socket("upstream-peer")?,
            base_key: parse_hex::<32>(args.required("upstream-key")?)?,
            epoch,
            adaptive,
        },
        event_sender.clone(),
        budget.clone(),
    )?;
    // Children are numbered: --downstream-id / -bind / -peer / -key describe
    // child 0, and --downstream-id-N and friends describe child N. Core v1.5
    // section 5 requires every forwarded child to get independently replaced
    // context, so each child has its own link, label, and blinding factor.
    let mut downstream: Vec<(u32, node_runtime::LinkHandle)> = Vec::new();
    for child in 0..LIMIT_MAX_FANOUT_CLASS {
        let suffix = if child == 0 {
            String::new()
        } else {
            format!("-{child}")
        };
        if !args.flag(&format!("downstream-id{suffix}")) {
            continue;
        }
        let peer_id = args.u32(&format!("downstream-id{suffix}"))?;
        downstream.push((
            peer_id,
            spawn_link(
                LinkConfig {
                    local_id: node_id,
                    peer_id,
                    bind: args.socket(&format!("downstream-bind{suffix}"))?,
                    peer: args.socket(&format!("downstream-peer{suffix}"))?,
                    base_key: parse_hex::<32>(args.required(&format!("downstream-key{suffix}"))?)?,
                    epoch,
                    adaptive,
                },
                event_sender.clone(),
                budget.clone(),
            )?,
        ));
    }
    drop(event_sender);
    if downstream.is_empty() {
        return Err("a relay needs at least one downstream child".into());
    }

    let mut states = RouteTable::default();
    let mut routes: HashMap<[u8; 16], RelayRoute> = HashMap::new();
    // Every label this relay can resolve, of either kind.
    let mut labels: HashMap<[u8; 16], LabelBinding> = HashMap::new();
    // Selector handed upstream for one returned offer -> which child it came
    // from. This is what lets a COMMIT name one chain out of several.
    let mut tentatives: HashMap<[u8; 16], TentativeOffer> = HashMap::new();
    let mut drops = RemoteInputDrops::new();
    // Checked rather than assumed: a research-only provider on the wire would
    // otherwise be a silent misconfiguration, with the run still looking
    // healthy. See ADR 0038 for why C1 is not one of the options.
    let eligibility = R1Suite;
    require_network_provider(&eligibility)
        .map_err(|_| "eligibility provider is not permitted on the network")?;
    let mut admission = IngressAdmission::new();
    let clock = Clock::start();
    let deadline = clock.now_ms().saturating_add(timeout_ms);
    let mut cleanup_started: Option<Instant> = None;
    // Any terminal control: CLOSE for a completed route, CANCEL or ABORT for
    // one released because the initiator selected a different chain.
    let mut observed_terminal = false;
    let mut transport_failed: Option<u32> = None;
    let mut cancelled_subtrees = 0_u64;
    let mut aborts_sent = 0_u64;

    // Events that arrive together share a local timestamp, so they are drained
    // as a batch, ordered by E1 section 2 precedence, and then consumed one at
    // a time. Processing straight from the channel would let scheduling decide
    // whether a cancellation or a delayed candidate wins.
    let mut ordered: VecDeque<LinkEvent> = VecDeque::new();
    while clock.now_ms() < deadline {
        // Expiry runs before every event, not only when the channel is idle.
        reclaim_expired(
            clock.now_ms(),
            &mut routes,
            &mut labels,
            &mut tentatives,
            &mut states,
        );
        let next = match ordered.pop_front() {
            Some(event) => Ok(event),
            None => event_receiver.recv_timeout(Duration::from_millis(100)),
        };
        let event = match next {
            Ok(value) => {
                if ordered.is_empty() {
                    let batch = drain_in_precedence_order(&event_receiver, value);
                    ordered.extend(batch);
                    match ordered.pop_front() {
                        Some(first) => first,
                        None => continue,
                    }
                } else {
                    value
                }
            }
            // Expiry already ran at the top of the iteration; an idle channel
            // just means there is nothing else to do this tick.
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        match event {
            LinkEvent::Message {
                peer_id, envelope, ..
            } if peer_id == upstream_id => match envelope.message {
                Message::Discover(discover) => {
                    if routes.contains_key(&discover.branch_token) {
                        drops.record("relay", ERROR_STATE_VIOLATION, "discover_duplicate_token");
                        continue;
                    }
                    if discover.hop_remaining == 0
                        || usize::from(discover.depth) >= LIMIT_MAX_CANDIDATE_LAYERS
                    {
                        drops.record(
                            "relay",
                            ERROR_RESOURCE_EXHAUSTED,
                            "discover_propagation_limit",
                        );
                        continue;
                    }
                    // E1 section 10: the per-ingress-peer bucket is charged
                    // before any cryptographic work or branch allocation, so a
                    // fresh-branch flood costs the relay a table lookup rather
                    // than a scalar multiplication.
                    if !admission.admit(epoch, upstream_id, clock.now_ms()) {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "ingress_token_bucket");
                        continue;
                    }
                    let fanout = usize::from(discover.fanout_class)
                        .clamp(1, downstream.len().min(LIMIT_MAX_FANOUT_CLASS));
                    let Ok(parent_discovery_nonce) =
                        <[u8; 32]>::try_from(discover.discovery_field.as_slice())
                    else {
                        drops.record("relay", ERROR_MALFORMED, "discover_nonce_length");
                        continue;
                    };
                    let depth = discover.depth.saturating_add(1);
                    let expires_at_ms = clock
                        .now_ms()
                        .saturating_add(Phase::Discovering.lifetime_ms());
                    // A peer exhausting the route table is admission
                    // pressure, not a relay fault: drop this DISCOVER.
                    if states
                        .begin(discover.branch_token, upstream_id, 0, expires_at_ms)
                        .is_err()
                    {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "route_table_limit");
                        continue;
                    }

                    let mut children = Vec::with_capacity(fanout);
                    for link_index in 0..fanout {
                        let factor = random_scalar()?;
                        // The reply public key is remote input: an invalid
                        // point drops the DISCOVER rather than killing us.
                        let Ok(child_public) = blind_public(&discover.reply_public_key, &factor)
                        else {
                            drops.record("relay", ERROR_MALFORMED, "discover_reply_public_key");
                            break;
                        };
                        let child_label = random_nonzero_16()?;
                        // eligibility-suite-interface-v1.md: lifecycle code
                        // depends on the suite interface, not a concrete
                        // scheme, and each child gets its own fresh field.
                        let Ok(child_field) = eligibility.transform(&discover.discovery_field)
                        else {
                            drops.record("relay", ERROR_MALFORMED, "discovery_field_transform");
                            break;
                        };
                        let Ok(child_discovery_nonce) =
                            <[u8; 32]>::try_from(child_field.as_slice())
                        else {
                            drops.record("relay", ERROR_INTERNAL, "discovery_field_width");
                            break;
                        };
                        labels.insert(
                            child_label,
                            LabelBinding::Branch {
                                parent_label: discover.branch_token,
                            },
                        );
                        let forwarded = downstream[link_index].1.send(Envelope {
                            suite_id: SUITE_R1,
                            message: Message::Discover(Discover {
                                branch_token: child_label,
                                hop_remaining: discover.hop_remaining.saturating_sub(1),
                                fanout_class: discover.fanout_class,
                                expiry_class: discover.expiry_class,
                                depth,
                                reply_public_key: child_public,
                                discovery_field: child_discovery_nonce.to_vec(),
                            }),
                        });
                        if forwarded.is_err() {
                            drops.record(
                                "relay",
                                ERROR_RESOURCE_EXHAUSTED,
                                "downstream_queue_full",
                            );
                            break;
                        }
                        // Reserve the first labels this child may answer on.
                        // The child derives the same values from the nonce it
                        // just received, so an offer arriving under one of them
                        // resolves to this branch and this child.
                        for index in 0..OFFER_LABEL_WINDOW {
                            let label = offer_label(&child_discovery_nonce, index)?;
                            labels.insert(
                                label,
                                LabelBinding::Offer {
                                    parent_label: discover.branch_token,
                                    child_index: link_index,
                                    index,
                                },
                            );
                        }
                        children.push(RelayChild {
                            link_index,
                            child_label,
                            blinding_factor: SecretBytes(factor),
                            child_discovery_nonce: SecretBytes(child_discovery_nonce),
                        });
                    }
                    if children.is_empty() {
                        cleanup_route(
                            discover.branch_token,
                            &mut routes,
                            &mut labels,
                            &mut tentatives,
                            &mut states,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        continue;
                    }
                    routes.insert(
                        discover.branch_token,
                        RelayRoute {
                            parent_label: discover.branch_token,
                            children,
                            committed_child: None,
                            committed_selector: None,
                            offers_forwarded: 0,
                            incoming_reply_public: discover.reply_public_key,
                            depth,
                            parent_discovery_nonce: SecretBytes(parent_discovery_nonce),
                            generation: 0,
                        },
                    );
                }
                Message::Control(control) => {
                    // Control from upstream names either a tentative selector
                    // handed out with a returned offer, or, before any offer
                    // came back, the branch token itself (a CANCEL of a branch
                    // that never produced a candidate).
                    let selected = tentatives.get(&control.local_label).cloned();
                    let parent_label = match &selected {
                        Some(offer) => offer.parent_label,
                        None if routes.contains_key(&control.local_label) => control.local_label,
                        None => continue,
                    };
                    let Some(route) = routes.get(&parent_label).map(RelayRoute::view) else {
                        continue;
                    };
                    if control.generation != route.generation {
                        continue;
                    }
                    // Once committed, control follows the committed chain; a
                    // selector for a losing sibling is no longer routable.
                    let onward = selected.clone().or_else(|| {
                        route.committed_child.and_then(|index| {
                            route.committed_selector.and_then(|selector| {
                                tentatives.get(&selector).cloned().map(|mut offer| {
                                    offer.child_index = index;
                                    offer
                                })
                            })
                        })
                    });
                    match control.message_type {
                        MessageType::Commit => {
                            // event-lifecycle-profile-e1.md:142 — an exact
                            // duplicate COMMIT MUST be discarded or processed
                            // idempotently, never treated as fatal.
                            if states
                                .apply(route.parent_label, Event::CommitAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record("relay", ERROR_STATE_VIOLATION, "commit_transition");
                                let _ = upstream
                                    .send(abort_control(control.local_label, route.generation));
                                aborts_sent += 1;
                                continue;
                            }
                            let Some(offer) = selected else {
                                // A COMMIT addressed to the branch rather than
                                // to one returned offer does not say which
                                // child was chosen, so it cannot be forwarded.
                                drops.record("relay", ERROR_STATE_VIOLATION, "commit_unselective");
                                let _ = upstream
                                    .send(abort_control(control.local_label, route.generation));
                                aborts_sent += 1;
                                continue;
                            };
                            let Some(child) = route.children.get(offer.child_index) else {
                                drops.record("relay", ERROR_STATE_VIOLATION, "commit_child_gone");
                                let _ = upstream
                                    .send(abort_control(control.local_label, route.generation));
                                aborts_sent += 1;
                                continue;
                            };
                            let child_link = child.link_index;
                            let chosen = offer.child_index;
                            if let Some(entry) = routes.get_mut(&parent_label) {
                                entry.committed_child = Some(chosen);
                                entry.committed_selector = Some(control.local_label);
                            }
                            if downstream[child_link]
                                .1
                                .send(forward_control(control, offer.child_selector))
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_RESOURCE_EXHAUSTED,
                                    "downstream_queue_full",
                                );
                            }
                            // The initiator has chosen, so every other subtree
                            // this branch opened is now off route and must be
                            // released rather than left to its own expiry.
                            let losers: Vec<TentativeOffer> = tentatives
                                .values()
                                .filter(|other| {
                                    other.parent_label == parent_label
                                        && other.child_index != chosen
                                })
                                .cloned()
                                .collect();
                            for loser in losers {
                                if let Some(child) = route.children.get(loser.child_index) {
                                    let _ = downstream[child.link_index].1.send(Envelope {
                                        suite_id: SUITE_R1,
                                        message: Message::Control(Control {
                                            message_type: MessageType::Cancel,
                                            local_label: loser.child_selector,
                                            generation: route.generation,
                                            expiry_class: 1,
                                            protected_body: vec![0_u8],
                                        }),
                                    });
                                }
                                tentatives.retain(|_, offer| {
                                    offer.parent_label != parent_label
                                        || offer.child_index != loser.child_index
                                });
                                // Every label bound to the losing child goes,
                                // including the one it answered on, so nothing
                                // from that subtree resolves any more.
                                labels.retain(|_, binding| {
                                    !matches!(binding, LabelBinding::Offer { parent_label: p, child_index: c, .. }
                                        if *p == parent_label && *c == loser.child_index)
                                });
                                cancelled_subtrees += 1;
                            }
                        }
                        MessageType::RendezvousOpen => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Ready)
                            {
                                if let Some((child, selector)) = onward.as_ref().and_then(|offer| {
                                    route
                                        .children
                                        .get(offer.child_index)
                                        .map(|child| (child, offer.child_selector))
                                }) {
                                    if downstream[child.link_index]
                                        .1
                                        .send(forward_control(control, selector))
                                        .is_err()
                                    {
                                        drops.record(
                                            "relay",
                                            ERROR_RESOURCE_EXHAUSTED,
                                            "downstream_queue_full",
                                        );
                                    }
                                }
                            }
                        }
                        MessageType::Data => {
                            if states.get(&route.parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                states.apply(
                                    route.parent_label,
                                    Event::DataAccepted,
                                    clock.now_ms(),
                                )?;
                                if let Some((child, selector)) = onward.as_ref().and_then(|offer| {
                                    route
                                        .children
                                        .get(offer.child_index)
                                        .map(|child| (child, offer.child_selector))
                                }) {
                                    if downstream[child.link_index]
                                        .1
                                        .send(forward_control(control, selector))
                                        .is_err()
                                    {
                                        drops.record(
                                            "relay",
                                            ERROR_RESOURCE_EXHAUSTED,
                                            "downstream_queue_full",
                                        );
                                    }
                                }
                            }
                        }
                        MessageType::Close | MessageType::Cancel | MessageType::Abort => {
                            // A cancellation before selection has no committed
                            // child, so it releases every subtree this branch
                            // opened rather than only one.
                            let targets: Vec<([u8; 16], usize)> = match &onward {
                                Some(offer) => vec![(offer.child_selector, offer.child_index)],
                                None => route
                                    .children
                                    .iter()
                                    .enumerate()
                                    .map(|(index, child)| (child.child_label, index))
                                    .collect(),
                            };
                            for (selector, index) in targets {
                                if let Some(child) = route.children.get(index) {
                                    if downstream[child.link_index]
                                        .1
                                        .send(forward_control(control.clone(), selector))
                                        .is_err()
                                    {
                                        drops.record(
                                            "relay",
                                            ERROR_RESOURCE_EXHAUSTED,
                                            "downstream_queue_full",
                                        );
                                    }
                                }
                            }
                            cleanup_started = Some(Instant::now());
                            observed_terminal = true;
                            let event = if control.message_type == MessageType::Close {
                                Event::CloseAccepted
                            } else {
                                Event::CancelAccepted
                            };
                            cleanup_route(
                                route.parent_label,
                                &mut routes,
                                &mut labels,
                                &mut tentatives,
                                &mut states,
                                event,
                                clock.now_ms(),
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::Message {
                peer_id, envelope, ..
            } if downstream.iter().any(|(id, _)| *id == peer_id) => match envelope.message {
                Message::Candidate(candidate) => {
                    let candidate_token = candidate.candidate_token;
                    // The child answers on a label derived from the discovery
                    // nonce this relay gave it, so the label names the branch
                    // and the child even though the child chose which one.
                    // Only an offer label makes a candidate routable: it names
                    // the child as well as the branch. A plain branch token
                    // does not, and a candidate arriving under one is not ours
                    // to forward.
                    let Some(LabelBinding::Offer {
                        parent_label,
                        child_index: slot_child,
                        index: slot_index,
                    }) = labels.get(&candidate_token).copied()
                    else {
                        continue;
                    };
                    if !routes.contains_key(&parent_label) {
                        continue;
                    }
                    if usize::from(candidate.layer_count) > LIMIT_MAX_CANDIDATE_LAYERS {
                        cleanup_route(
                            parent_label,
                            &mut routes,
                            &mut labels,
                            &mut tentatives,
                            &mut states,
                            Event::CancelAccepted,
                            clock.now_ms(),
                        );
                        continue;
                    }
                    // The candidate arrived on one specific child, so it must
                    // be unwrapped with that child's blinding factor and nonce.
                    // Those are key material, so they are read through a borrow
                    // that ends with this block rather than copied out of the
                    // table with the rest of the route.
                    let child_index = slot_child;
                    let wrapped = {
                        let Some(route) = routes.get(&parent_label) else {
                            continue;
                        };
                        let Some(child) = route.children.get(child_index) else {
                            drops.record("relay", ERROR_STATE_VIOLATION, "candidate_unknown_child");
                            continue;
                        };
                        // After selection the branch follows one child; an
                        // offer returning through a losing sibling is off
                        // route.
                        if route
                            .committed_child
                            .is_some_and(|chosen| chosen != child_index)
                        {
                            drops.record("relay", ERROR_STATE_VIOLATION, "candidate_after_commit");
                            continue;
                        }
                        // The candidate blob is remote input; a wrap failure
                        // drops the candidate rather than terminating the relay.
                        let Ok(wrapped) = wrap_candidate(
                            &route.incoming_reply_public,
                            route.depth,
                            child.blinding_factor.0,
                            child.child_label,
                            route.parent_label,
                            route.parent_discovery_nonce.0,
                            child.child_discovery_nonce.0,
                            candidate.candidate_blob,
                        ) else {
                            drops.record("relay", ERROR_MALFORMED, "candidate_blob_wrap");
                            continue;
                        };
                        wrapped
                    };
                    if states
                        .apply(parent_label, Event::CandidateAccepted, clock.now_ms())
                        .is_err()
                    {
                        drops.record("relay", ERROR_STATE_VIOLATION, "candidate_transition");
                        continue;
                    }
                    // Each returned offer travels upstream under its own
                    // tentative selector, so a later COMMIT names one chain
                    // rather than just the branch. The child accepts control
                    // on the token it used, which is its own selector when the
                    // child is a relay and its branch token when it is a
                    // gateway.
                    let Some(entry) = routes.get_mut(&parent_label) else {
                        continue;
                    };
                    let Ok(tentative) =
                        offer_label(&entry.parent_discovery_nonce.0, entry.offers_forwarded)
                    else {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "offer_response_limit");
                        continue;
                    };
                    entry.offers_forwarded = entry.offers_forwarded.saturating_add(1);
                    // Slide the child's window on by one so a later offer still
                    // has a reserved label.
                    let next_slot = slot_index.saturating_add(OFFER_LABEL_WINDOW);
                    let next_label = entry.children.get(child_index).and_then(|child| {
                        offer_label(&child.child_discovery_nonce.0, next_slot).ok()
                    });
                    tentatives.insert(
                        tentative,
                        TentativeOffer {
                            parent_label,
                            child_index,
                            child_selector: candidate_token,
                        },
                    );
                    // Downstream control for this chain arrives under the same
                    // label the offer did, which is already bound, so nothing
                    // needs registering for it.
                    if let Some(label) = next_label {
                        labels.insert(
                            label,
                            LabelBinding::Offer {
                                parent_label,
                                child_index,
                                index: next_slot,
                            },
                        );
                    }
                    if upstream
                        .send(Envelope {
                            suite_id: SUITE_R1,
                            message: Message::Candidate(Candidate {
                                candidate_token: tentative,
                                expiry_class: candidate.expiry_class,
                                layer_count: candidate.layer_count.saturating_add(1),
                                candidate_blob: wrapped,
                            }),
                        })
                        .is_err()
                    {
                        drops.record("relay", ERROR_RESOURCE_EXHAUSTED, "upstream_queue_full");
                    }
                }
                Message::Control(control) => {
                    let Some(parent_label) = labels
                        .get(&control.local_label)
                        .map(|binding| binding.parent_label())
                    else {
                        continue;
                    };
                    let Some(route) = routes.get(&parent_label).map(RelayRoute::view) else {
                        continue;
                    };
                    if control.generation != route.generation {
                        continue;
                    }
                    // Upstream, this route is known by the selector the
                    // initiator committed to; before a COMMIT the branch token
                    // is all either side has.
                    let upstream_label = route.committed_selector.unwrap_or(parent_label);
                    match control.message_type {
                        MessageType::Ready => {
                            if states
                                .apply(parent_label, Event::ReadyAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record("relay", ERROR_STATE_VIOLATION, "ready_transition");
                                continue;
                            }
                            if upstream
                                .send(forward_control(control, upstream_label))
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_RESOURCE_EXHAUSTED,
                                    "upstream_queue_full",
                                );
                            }
                        }
                        MessageType::RendezvousResult => {
                            if states
                                .apply(parent_label, Event::CapabilityAccepted, clock.now_ms())
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_STATE_VIOLATION,
                                    "rendezvous_result_transition",
                                );
                                continue;
                            }
                            if upstream
                                .send(forward_control(control, upstream_label))
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_RESOURCE_EXHAUSTED,
                                    "upstream_queue_full",
                                );
                            }
                        }
                        MessageType::Data => {
                            if states.get(&parent_label).map(|state| state.phase)
                                == Some(Phase::Open)
                            {
                                let _ =
                                    states.apply(parent_label, Event::DataAccepted, clock.now_ms());
                                if upstream
                                    .send(forward_control(control, upstream_label))
                                    .is_err()
                                {
                                    drops.record(
                                        "relay",
                                        ERROR_RESOURCE_EXHAUSTED,
                                        "upstream_queue_full",
                                    );
                                }
                            }
                        }
                        MessageType::Close | MessageType::Cancel | MessageType::Abort => {
                            if upstream
                                .send(forward_control(control.clone(), upstream_label))
                                .is_err()
                            {
                                drops.record(
                                    "relay",
                                    ERROR_RESOURCE_EXHAUSTED,
                                    "upstream_queue_full",
                                );
                            }
                            cleanup_started = Some(Instant::now());
                            observed_terminal = true;
                            cleanup_route(
                                parent_label,
                                &mut routes,
                                &mut labels,
                                &mut tentatives,
                                &mut states,
                                Event::CloseAccepted,
                                clock.now_ms(),
                            );
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            LinkEvent::TransmissionFailed { peer_id } => {
                // Retry exhaustion must terminate the run cleanly: reclaim
                // every route, then fall through to the shared cleanup and
                // metrics path so the harness can observe live_routes == 0.
                structured_event(
                    "relay",
                    "transport_failure",
                    &[
                        ("peer", peer_id.to_string()),
                        ("error_id", ERROR_TIMEOUT.to_string()),
                    ],
                );
                transport_failed = Some(peer_id);
                cleanup_started.get_or_insert_with(Instant::now);
                break;
            }
            LinkEvent::SecurityEvent {
                peer_id,
                error_id,
                detail,
            } => {
                structured_event(
                    "relay",
                    "security_event",
                    &[
                        ("peer", peer_id.to_string()),
                        ("error_id", error_id.to_string()),
                        ("detail", detail.to_owned()),
                    ],
                );
            }
            _ => {}
        }
        if observed_terminal && routes.is_empty() {
            // Drain in-flight T1 state instead of sleeping a fixed interval.
            let mut handles: Vec<&node_runtime::LinkHandle> = vec![&upstream];
            handles.extend(downstream.iter().map(|(_, link)| link));
            drain_links(&handles, &event_receiver);
            break;
        }
    }

    // One cleanup funnel for every exit, planned or not: release the forward
    // and reverse maps for each branch, then reclaim anything left in the
    // route table so no exit path can strand state.
    let remaining: Vec<[u8; 16]> = routes.keys().copied().collect();
    for label in remaining {
        cleanup_route(
            label,
            &mut routes,
            &mut labels,
            &mut tentatives,
            &mut states,
            Event::Timeout,
            clock.now_ms(),
        );
    }
    states.reclaim_all(Event::Timeout, clock.now_ms());
    let link_count = downstream.len() + 1;
    // Read before shutdown, which consumes each handle.
    let lifecycle_lost =
        upstream.lifecycle_lost() || downstream.iter().any(|(_, link)| link.lifecycle_lost());
    upstream.shutdown()?;
    for (_, link) in downstream {
        link.shutdown()?;
    }
    let metrics = collect_stopped(&event_receiver, link_count);
    let cleanup_ms = cleanup_started
        .map(|value| value.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0);
    write_link_metrics(
        &metrics_path,
        "relay",
        states.live_routes(),
        cleanup_ms,
        &drops,
        states.peaks(),
        &metrics,
    )?;
    structured_event(
        "relay",
        "stopped",
        &[
            ("live_routes", states.live_routes().to_string()),
            ("route_map", routes.len().to_string()),
            ("token_bucket_drops", admission.rejected().to_string()),
            ("cancelled_subtrees", cancelled_subtrees.to_string()),
            ("aborts_sent", aborts_sent.to_string()),
            ("id", node_id.to_string()),
        ],
    );
    if lifecycle_lost {
        return Err(format!(
            "relay {node_id} lost a link event; its view of the link is incomplete"
        )
        .into());
    }
    if let Some(peer_id) = transport_failed {
        // State is already reclaimed and metrics are written; the non-zero
        // exit reports the outcome without stranding remote state.
        return Err(format!("T1 retry budget exhausted for peer {peer_id}").into());
    }
    if !observed_terminal {
        return Err(format!("relay {node_id} timed out before cleanup").into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("trahens-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_abort_is_a_bare_failure_teardown() {
        // messages-v1.5.md separates three teardowns and ABORT is the failure
        // one. A relay that cannot honour a COMMIT sends it instead of
        // dropping the message, which used to leave the initiator waiting out
        // a deadline for a route that had already failed.
        let envelope = abort_control([0x41; 16], 3);
        assert_eq!(envelope.suite_id, SUITE_R1);
        let Message::Control(control) = envelope.message else {
            panic!("abort_control must produce a control message");
        };
        assert_eq!(control.message_type, MessageType::Abort);
        assert_eq!(control.local_label, [0x41; 16]);
        assert_eq!(control.generation, 3, "it answers the COMMIT it refuses");
        assert_eq!(control.expiry_class, 1);

        // The body carries no reason. A relay holds no route secret for either
        // end, so it could not seal one, and Core section 8 requires uniform
        // failure behaviour: the message type is the whole signal.
        assert_eq!(control.protected_body, vec![0_u8]);
    }

    #[test]
    fn a_route_view_carries_no_key_material() -> Result<(), Box<dyn Error>> {
        // Control forwarding needs labels and link indices, never secrets.
        // Cloning the whole route to get them duplicated every blinding factor
        // and discovery nonce once per control message, and those copies were
        // never wiped. The view is what control paths take instead.
        let parent = [0x61; 16];
        let route = RelayRoute {
            parent_label: parent,
            children: vec![
                RelayChild {
                    link_index: 2,
                    child_label: [0x62; 16],
                    blinding_factor: SecretBytes([9; 32]),
                    child_discovery_nonce: SecretBytes([8; 32]),
                },
                RelayChild {
                    link_index: 5,
                    child_label: [0x63; 16],
                    blinding_factor: SecretBytes([7; 32]),
                    child_discovery_nonce: SecretBytes([6; 32]),
                },
            ],
            committed_child: Some(1),
            committed_selector: Some([0x64; 16]),
            offers_forwarded: 2,
            incoming_reply_public: [1; 32],
            depth: 3,
            parent_discovery_nonce: SecretBytes([5; 32]),
            generation: 0,
        };

        let view = route.view();
        assert_eq!(view.parent_label, parent);
        assert_eq!(view.committed_child, Some(1));
        assert_eq!(view.children.len(), 2);
        assert_eq!(view.children[1].link_index, 5);
        assert_eq!(view.children[1].child_label, [0x63; 16]);

        // The view is Clone precisely because it holds nothing secret; the
        // route is not, so the table keeps one copy of each nonce and factor.
        let copied = view.clone();
        assert_eq!(copied.children[0].link_index, 2);

        // The labels a child may answer on come from its nonce, so the nonce
        // is a key: knowing it is enough to compute them.
        let expected = offer_label(&route.children[0].child_discovery_nonce.0, 0)?;
        assert_ne!(expected, [0_u8; 16]);
        assert_ne!(
            expected,
            offer_label(&route.children[1].child_discovery_nonce.0, 0)?,
            "different children never share a label"
        );
        Ok(())
    }

    #[test]
    fn every_offer_on_a_branch_gets_its_own_selector() -> Result<(), Box<dyn Error>> {
        // Two children answer the same branch. Each offer must reach the
        // initiator under a distinct label, or a COMMIT names the branch
        // without naming which child answered and the relay has to guess.
        let parent = [0x51; 16];
        let nonces = [[0x61_u8; 32], [0x62_u8; 32]];
        let mut labels: HashMap<[u8; 16], LabelBinding> = HashMap::new();
        for (child_index, nonce) in nonces.iter().enumerate() {
            for index in 0..OFFER_LABEL_WINDOW {
                labels.insert(
                    offer_label(nonce, index)?,
                    LabelBinding::Offer {
                        parent_label: parent,
                        child_index,
                        index,
                    },
                );
            }
        }

        // Each child answers on the first label reserved for it, and the relay
        // resolves that label back to the branch and the child.
        for (child_index, nonce) in nonces.iter().enumerate() {
            let answered = offer_label(nonce, 0)?;
            let LabelBinding::Offer {
                parent_label,
                child_index: bound_child,
                ..
            } = *labels
                .get(&answered)
                .ok_or("a child's reserved label must resolve")?
            else {
                return Err("a reserved offer label must bind to a child".into());
            };
            assert_eq!(parent_label, parent);
            assert_eq!(bound_child, child_index);
        }

        // The labels are distinct across children and across offers, and no
        // two share a prefix the way a counter or an XOR of the branch token
        // would.
        let mut all: Vec<[u8; 16]> = labels.keys().copied().collect();
        all.sort_unstable();
        let total = all.len();
        all.dedup();
        assert_eq!(all.len(), total, "every reserved label is distinct");
        assert_eq!(total, 2 * usize::from(OFFER_LABEL_WINDOW));
        Ok(())
    }

    #[test]
    fn a_commit_names_one_chain_and_releases_the_siblings() -> Result<(), Box<dyn Error>> {
        // The initiator can select a candidate other than the first to arrive.
        // The selector it commits to must resolve to that child, and the other
        // subtrees must be released rather than left running to their own
        // expiry.
        let parent = [0x71; 16];
        let mut tentatives: HashMap<[u8; 16], TentativeOffer> = HashMap::new();
        let first_arrival = [0x81; 16];
        let chosen = [0x82; 16];
        tentatives.insert(
            first_arrival,
            TentativeOffer {
                parent_label: parent,
                child_index: 0,
                child_selector: [0x91; 16],
            },
        );
        tentatives.insert(
            chosen,
            TentativeOffer {
                parent_label: parent,
                child_index: 1,
                child_selector: [0x92; 16],
            },
        );

        // COMMIT arrives on the second offer's selector, not the first's.
        let selected = tentatives
            .get(&chosen)
            .cloned()
            .ok_or("the committed selector must resolve")?;
        assert_eq!(selected.child_index, 1, "the later arrival was chosen");
        assert_eq!(selected.child_selector, [0x92; 16]);

        let losers: Vec<TentativeOffer> = tentatives
            .values()
            .filter(|other| {
                other.parent_label == parent && other.child_index != selected.child_index
            })
            .cloned()
            .collect();
        assert_eq!(losers.len(), 1, "exactly one subtree is off route");
        assert_eq!(losers[0].child_index, 0);
        Ok(())
    }

    #[test]
    fn forward_control_rewrites_the_label_and_nothing_else() {
        let incoming = Control {
            message_type: MessageType::Commit,
            local_label: [0xaa; 16],
            generation: 9,
            expiry_class: 3,
            protected_body: vec![1, 2, 3],
        };

        let envelope = forward_control(incoming.clone(), [0xbb; 16]);

        assert_eq!(envelope.suite_id, SUITE_R1);
        let Message::Control(forwarded) = envelope.message else {
            panic!("forward_control must produce a control message");
        };
        // The child label is branch-local: rewriting it is the whole point of
        // the hop, and every other field must survive untouched.
        assert_eq!(forwarded.local_label, [0xbb; 16]);
        assert_eq!(forwarded.message_type, incoming.message_type);
        assert_eq!(forwarded.generation, incoming.generation);
        assert_eq!(forwarded.expiry_class, incoming.expiry_class);
        assert_eq!(forwarded.protected_body, incoming.protected_body);
    }

    #[test]
    fn forward_control_does_not_reuse_the_incoming_label() {
        let incoming = Control {
            message_type: MessageType::Ready,
            local_label: [0x11; 16],
            generation: 1,
            expiry_class: 1,
            protected_body: Vec::new(),
        };

        let envelope = forward_control(incoming, [0x22; 16]);

        let Message::Control(forwarded) = envelope.message else {
            panic!("forward_control must produce a control message");
        };
        assert_ne!(forwarded.local_label, [0x11; 16]);
    }

    #[test]
    fn cleanup_route_drops_both_directions() {
        let parent = [0x01; 16];
        let child = [0x02; 16];
        let mut routes = HashMap::new();
        let mut labels = HashMap::new();
        let mut tentatives = HashMap::new();
        routes.insert(
            parent,
            RelayRoute {
                parent_label: parent,
                children: vec![RelayChild {
                    link_index: 0,
                    child_label: child,
                    blinding_factor: SecretBytes([7; 32]),
                    child_discovery_nonce: SecretBytes([0; 32]),
                }],
                committed_child: None,
                committed_selector: None,
                offers_forwarded: 0,
                incoming_reply_public: [0; 32],
                depth: 1,
                parent_discovery_nonce: SecretBytes([0; 32]),
                generation: 1,
            },
        );
        labels.insert(
            child,
            LabelBinding::Branch {
                parent_label: parent,
            },
        );
        let mut states = RouteTable::default();

        cleanup_route(
            parent,
            &mut routes,
            &mut labels,
            &mut tentatives,
            &mut states,
            Event::CloseAccepted,
            0,
        );

        assert!(routes.is_empty(), "parent mapping must be removed");
        assert!(labels.is_empty(), "the child's label must be released");
    }

    #[test]
    fn cleanup_releases_every_child_of_a_fanned_out_branch() {
        // With fan-out the branch has several reverse mappings, and cancelling
        // it must release all of them or a later candidate would resolve to a
        // route that no longer exists.
        let parent = [0x11; 16];
        let mut routes = HashMap::new();
        let mut labels = HashMap::new();
        let mut tentatives = HashMap::new();
        let children: Vec<RelayChild> = (0..3)
            .map(|index| RelayChild {
                link_index: index,
                child_label: [index as u8 + 1; 16],
                blinding_factor: SecretBytes([7; 32]),
                child_discovery_nonce: SecretBytes([0; 32]),
            })
            .collect();
        for child in &children {
            labels.insert(
                child.child_label,
                LabelBinding::Branch {
                    parent_label: parent,
                },
            );
        }
        routes.insert(
            parent,
            RelayRoute {
                parent_label: parent,
                children,
                committed_child: Some(1),
                committed_selector: None,
                offers_forwarded: 0,
                incoming_reply_public: [0; 32],
                depth: 1,
                parent_discovery_nonce: SecretBytes([0; 32]),
                generation: 1,
            },
        );
        let mut states = RouteTable::default();

        cleanup_route(
            parent,
            &mut routes,
            &mut labels,
            &mut tentatives,
            &mut states,
            Event::CancelAccepted,
            0,
        );

        assert!(routes.is_empty());
        assert!(labels.is_empty(), "every child label is released");
    }

    #[test]
    fn reclaim_expired_releases_lapsed_branches_and_spares_live_ones() -> Result<(), Box<dyn Error>>
    {
        // The relay now sweeps before every event rather than only when the
        // channel falls idle, so this is the sweep a busy relay depends on.
        let lapsed = [0x21; 16];
        let live = [0x22; 16];
        let mut routes = HashMap::new();
        let mut labels = HashMap::new();
        let mut tentatives = HashMap::new();
        let mut states = RouteTable::default();

        for (label, child, deadline) in [(lapsed, [0x31_u8; 16], 100_u64), (live, [0x32; 16], 900)]
        {
            states.begin(label, 1, 0, deadline)?;
            labels.insert(
                child,
                LabelBinding::Branch {
                    parent_label: label,
                },
            );
            routes.insert(
                label,
                RelayRoute {
                    parent_label: label,
                    children: vec![RelayChild {
                        link_index: 0,
                        child_label: child,
                        blinding_factor: SecretBytes([7; 32]),
                        child_discovery_nonce: SecretBytes([0; 32]),
                    }],
                    committed_child: None,
                    committed_selector: None,
                    offers_forwarded: 0,
                    incoming_reply_public: [0; 32],
                    depth: 1,
                    parent_discovery_nonce: SecretBytes([0; 32]),
                    generation: 0,
                },
            );
        }

        assert_eq!(
            reclaim_expired(500, &mut routes, &mut labels, &mut tentatives, &mut states,),
            1
        );
        assert!(!routes.contains_key(&lapsed), "the lapsed branch is gone");
        assert!(routes.contains_key(&live), "the live branch is untouched");
        assert!(
            !labels.contains_key(&[0x31; 16]),
            "its child label goes with it"
        );
        assert_eq!(states.live_routes(), 1);

        // A second sweep at the same instant is a no-op, so running it every
        // iteration costs nothing.
        assert_eq!(
            reclaim_expired(500, &mut routes, &mut labels, &mut tentatives, &mut states,),
            0
        );
        Ok(())
    }

    #[test]
    fn cleanup_route_is_idempotent_for_unknown_labels() {
        let mut routes: HashMap<[u8; 16], RelayRoute> = HashMap::new();
        // Every label this relay can resolve, of either kind.
        let mut labels: HashMap<[u8; 16], LabelBinding> = HashMap::new();
        let mut tentatives: HashMap<[u8; 16], TentativeOffer> = HashMap::new();
        let mut states = RouteTable::default();

        cleanup_route(
            [0xff; 16],
            &mut routes,
            &mut labels,
            &mut tentatives,
            &mut states,
            Event::CloseAccepted,
            0,
        );

        assert!(routes.is_empty());
        assert!(labels.is_empty());
    }
}
