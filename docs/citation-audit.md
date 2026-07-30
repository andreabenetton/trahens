# Citation and claim audit

This file maps external claims in the current paper and specifications to primary sources. It does not treat a citation as proof that the complete Trahens composition is secure.

## Anonymity systems

### Sphinx2009

George Danezis and Ian Goldberg, **“Sphinx: A Compact and Provably Secure Mix Format,”** IEEE Symposium on Security and Privacy, 2009, pp. 269-282.

Used for: compact per-hop transformed mix packets, reply support, formal mix-packet context, and the multiplicative-blinding pattern. Trahens does not inherit the Sphinx proof for its custom reply format.

### HORNET2015

Chen Chen, Daniele Enrico Asoni, David Barrera, George Danezis, and Adrian Perrig, **“HORNET: High-speed Onion Routing at the Network Layer,”** ACM CCS 2015, pp. 1441-1454.

Used for: high-speed anonymous forwarding and fast-path state comparison.

### TARANET2018

Chen Chen, Daniele Enrico Asoni, Adrian Perrig, David Barrera, George Danezis, and Carmela Troncoso, **“TARANET: Traffic-Analysis Resistant Anonymity at the Network Layer,”** IEEE EuroS&P 2018, pp. 137-152.

Used for: setup mixing, coordinated constant-rate transmission, and the distinction between content protection and traffic-analysis resistance.

### Loopix2017

Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, and George Danezis, **“The Loopix Anonymity System,”** 26th USENIX Security Symposium, 2017, pp. 1199-1216.

Used for: stochastic mixing and cover traffic.

## Universal re-encryption and receiver anonymity

### GolleEtAl2004

Philippe Golle, Markus Jakobsson, Ari Juels, and Paul Syverson, **“Universal Re-encryption for Mixnets,”** CT-RSA 2004, LNCS 2964, pp. 163-178.

Used for: ciphertext transformation without the recipient public key and the C1 negative-control construction family.

### CanettiEtAl2003

Ran Canetti, Hugo Krawczyk, and Jesper Buus Nielsen, **“Relaxing Chosen-Ciphertext Security,”** CRYPTO 2003, LNCS 2729, pp. 565-582.

Used for: replayable chosen-ciphertext security.

### BellareEtAl2001

Mihir Bellare, Alexandra Boldyreva, Anand Desai, and David Pointcheval, **“Key-Privacy in Public-Key Encryption,”** ASIACRYPT 2001, LNCS 2248, pp. 566-582, DOI `10.1007/3-540-45682-1_33`.

Used for: recipient/key privacy context and the explicit statement that uniform public-key blinding does not by itself prove unlinkability of encrypted reply layers.

### PrabhakaranRosulek2007

Manoj Prabhakaran and Mike Rosulek, **“Rerandomizable RCCA Encryption,”** CRYPTO 2007, LNCS 4622, pp. 517-534.

Used for: rerandomizable RCCA encryption and the distinction between rerandomization and realized receiver anonymity.

### Wang2021

Yong Wang, Rui Chen, Guomin Yang, Xinyi Huang, Bin Wang, and Moti Yung, **“Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved,”** CRYPTO 2021, LNCS 12828, pp. 270-300, DOI `10.1007/978-3-030-84259-8_10`; full version IACR ePrint 2021/862.

Used for: the receiver-anonymous rerandomizable RCCA target and the exact k=2 source-to-code audit. The Trahens audit concerns only the project's literal representative-level transcription of the cited equations. It is presented as an implementation/interpretation mismatch, not as a refutation of the paper's generic framework or any author-confirmed interpretation.

### BanfiMaurerRitsch2023

Fabio Banfi, Ueli Maurer, and Silvia Ritsch, **“On the Security of Universal Re-Encryption,”** IACR ePrint 2023/1165.

Used for: minimal URE security properties, unlinkability/anonymity separation, and composable application-level reasoning.

### DowlingEtAl2022

Benjamin Dowling, Eduard Hauck, Doreen Riepel, and Paul Rösler, **“Strongly Anonymous Ratcheted Key Exchange,”** ASIACRYPT 2022; full version IACR ePrint 2022/1187.

Used for: updatable and randomizable public-key encryption. The paper's key-and-ciphertext update interface is discussed as related work and is not represented as a ciphertext-only same-recipient URE interface.

## Rendezvous architecture

### TorRendV3Overview

The Tor Project, **“Tor Rendezvous Specification - Version 3: Protocol Overview,”** Tor Specifications, section 13.2.

Used for: separation among service descriptors, introduction points, and rendezvous points.

### TorRendV3Introduction

The Tor Project, **“The Introduction Protocol,”** Tor Specifications, section 13.4.

Used for: introduction-point mediation, replay considerations, and fixed-maximum padding discussion.

### TorRendV3Rendezvous

The Tor Project, **“The Rendezvous Protocol,”** Tor Specifications, section 13.5.

Used for: client/service circuits joining at a rendezvous point and one-use rendezvous-cookie precedent. Trahens R1 is not a Tor protocol and does not inherit Tor's security analysis.

### DP5

George Danezis, Nikita Borisov, and Ian Goldberg, **“Privacy-Preserving Presence Sharing,”** Proceedings on Privacy Enhancing Technologies 2015(2), pp. 4-24, DOI `10.1515/popets-2015-0008`.

Used for: the architectural precedent that private presence and rendezvous-oriented directory systems expose explicit replica, update, and lookup assumptions. D1 does not claim DP5 compatibility or inherit its proof.

### RFC9458

Martin Thomson and Christopher A. Wood, **“Oblivious HTTP,”** RFC 9458, January 2024, DOI `10.17487/RFC9458`.

Used for: the weaker D1 mode that separates client source address from request content under a relay/gateway non-collusion assumption. OHTTP is not private information retrieval and does not hide the decoded lookup handle from the gateway.

## Transport recovery and scheduling

### RFC6298

Vern Paxson, Mark Allman, Jerry Chu, and Matt Sargent, **“Computing TCP's Retransmission Timer,”** RFC 6298, June 2011.

Used for: the smoothed RTT/RTTVAR update order, variance margin, retransmission ambiguity rule, and bounded exponential RTO backoff. Trahens T1 uses the estimator structure for one adjacent-link message transmission; it is not TCP.

### RFC6675

Ethan Blanton, Mark Allman, Lili Wang, Ilpo Järvinen, Markku Kojo, and Yoshifumi Nishida, **“A Conservative Loss Recovery Algorithm Based on Selective Acknowledgment (SACK) for TCP,”** RFC 6675, August 2012.

Used for: conservative retransmission of missing material based on selective acknowledgement. T1 uses a finite fragment bitmap rather than a TCP byte-stream scoreboard.

### RFC9002

Jana Iyengar and Ian Swett, **“QUIC Loss Detection and Congestion Control,”** RFC 9002, May 2021.

Used for: acknowledgement-based loss detection, acknowledgement delay, timer/probe structure, and the explicit distinction between recovery and congestion control. T1 does not claim QUIC compatibility and does not yet adopt its end-to-end congestion controller.

TARANET and Loopix, listed above, are also cited at the scheduler discussion. They motivate constant-rate shaping and stochastic mixing/cover-traffic comparisons respectively; neither result is attributed to T1.

### RFC5681

Mark Allman, Vern Paxson, and Ethan Blanton, **“TCP Congestion Control,”** RFC 5681, September 2009.

Used for: the general requirement that a sender bound injected traffic and avoid inappropriate bursts under uncertain path capacity. T2 is adjacent-link, cell-based, and quantized; it is not TCP and does not copy TCP congestion-window semantics.

### ShreedharVarghese1995

M. Shreedhar and George Varghese, **“Efficient Fair Queueing Using Deficit Round Robin,”** ACM SIGCOMM 1995, pp. 231-242, DOI `10.1145/217382.217453`.

Used for: the deficit-round-robin service structure. T2 specializes it to equal-size encrypted cells and local policy weights.

### JainChiuHawe1984

Raj Jain, Dah-Ming Chiu, and William Hawe, **“A Quantitative Measure of Fairness and Discrimination for Resource Allocation in Shared Computer Systems,”** DEC Research Report TR-301, September 1984.

Used for: the normalized throughput fairness index reported in the T2 model.

### Gilbert1960 and Elliott1963

E. N. Gilbert, **“Capacity of a Burst-Noise Channel,”** Bell System Technical Journal, vol. 39, no. 5, 1960, pp. 1253-1265, DOI `10.1002/j.1538-7305.1960.tb03959.x`; and E. O. Elliott, **“Estimates of Error Rates for Codes on Burst-Noise Channels,”** Bell System Technical Journal, vol. 42, no. 5, 1963, pp. 1977-1997, DOI `10.1002/j.1538-7305.1963.tb00955.x`.

Used for: the two-state burst-loss stress model. The repository does not claim that this model describes any particular deployment.

### JuarezEtAl2016

Marc Juarez, Mohsen Imani, Mike Perry, Claudia Diaz, and Matthew Wright, **“Toward an Efficient Website Fingerprinting Defense,”** ESORICS 2016, LNCS 9878, pp. 27-46, DOI `10.1007/978-3-319-45744-4_2`.

Used for: the caution that adaptive padding and release policies remain classifier- and workload-dependent and may retain fingerprints. T2 therefore treats adaptive rate changes as observable evidence rather than claiming activity hiding.

## Standards and retained primitives

- RFC 2119 and RFC 8174: normative requirement language.
- RFC 9180: HPKE structure and context-binding discipline; Trahens reply KEM is not claimed to be RFC 9180 HPKE and does not inherit a receiver-anonymity theorem.
- RFC 9496: `ristretto255` encodings and group abstraction.
- RFC 5869: the Extract-then-Expand structure. C1 v2 uses one Extract and one 44-byte Expand, split into key and nonce.
- RFC 8439: ChaCha20-Poly1305.
- RFC 8032: Ed25519.

## Repository-originated results

The following are not attributed to external papers:

- R1 endpoint-independent service-query nonce and one-time capability state machine;
- the deterministic R1 literal-marker experiment;
- the proof that multiplicative reply-key blinding makes the public key exactly uniform after one honest relay;
- the production/test API separation that makes deterministic reply ephemerals unavailable to normal callers;
- the C1 ratio-tag implementation and integrated regression result;
- the exact counterexample to the project transcription and exhaustive small-chain checker;
- M2/W2 encodings, fragmentation, reassembly, and route lifecycle;
- T1 DATA/ACK/CHAFF framing, adjacent-link transmission identifiers, bounded selective recovery, and retry ciphertext vectors;
- T2 SCHEDULE framing, finite rate menus, hysteresis, weighted equal-cell service, admission, and overload rules;
- fixed/adaptive/work-conserving congestion, leakage, burst-loss, fairness, and multi-link correlation measurements;
- all simulator performance, bandwidth, queue, delay, and cleanup measurements.

Each such result is accompanied by executable artifacts or tests. None is described as a cryptographic proof.

## Multi-link traffic analysis and active probing

### DeepCorr2018

Milad Nasr, Alireza Bahramali, and Amir Houmansadr, **“DeepCorr: Strong Flow Correlation Attacks on Tor Using Deep Learning,”** ACM CCS 2018, pp. 1962-1976, DOI `10.1145/3243734.3243824`.

Used for: the ability of learned classifiers to correlate encrypted flows from timing observations and the warning that a transparent statistical classifier is only a lower-bound rejection test.

### RAPTOR2015

Yixin Sun, Anne Edmundson, Laurent Vanbever, Oscar Li, Jennifer Rexford, Mung Chiang, and Prateek Mittal, **“RAPTOR: Routing Attacks on Privacy in Tor,”** 24th USENIX Security Symposium, 2015, pp. 271-286.

Used for: routing-position and multi-link observation as attack surfaces outside a single protected relay or link.

### Dropmark2018

Florentin Rochet and Olivier Pereira, **“Dropping on the Edge: Flexibility and Traffic Confirmation in Onion Routing Protocols,”** Proceedings on Privacy Enhancing Technologies 2018(2), pp. 27-46, DOI `10.1515/popets-2018-0011`.

Used for: active traffic confirmation and the distinction between traffic manipulation and cryptographic forgery.

### DUSTER2019

Alessandro Iacovazzi, David Frassinelli, and Yuval Elovici, **“The DUSTER Attack: Tor Onion Service Attribution Based on Flow Watermarking,”** RAID 2019, pp. 213-225.

Used for: active flow watermarking and downstream pattern detection.

### WangEtAl2014

Tao Wang, Xiang Cai, Rishab Nithyanand, Rob Johnson, and Ian Goldberg, **“Effective Attacks and Provable Defenses for Website Fingerprinting,”** 23rd USENIX Security Symposium, 2014, pp. 143-157.

Used for: deterministic shaping defenses and their bandwidth-latency trade-offs. Trahens does not claim to reproduce the paper's defense or proof model.

### NasrEtAl2021

Milad Nasr, Alireza Bahramali, Amir Houmansadr, and Amin Asgharian, **“Blind Adversarial Network Perturbations,”** 30th USENIX Security Symposium, 2021, pp. 2705-2722.

Used for: the warning that attacks may transfer without direct knowledge of the evaluated classifier.

### CherubinJansenTroncoso2022

Giovanni Cherubin, Rob Jansen, and Carmela Troncoso, **“Online Website Fingerprinting: Evaluating Website Fingerprinting Attacks on Tor in the Real World,”** 31st USENIX Security Symposium, 2022, pp. 753-770.

Used for: online and real-world evaluation conditions beyond a closed deterministic model.

### GTT23

Rob Jansen, Ryan Wails, and Aaron Johnson, **“GTT23: Toward Realistic Website Fingerprinting Evaluation,”** arXiv:2404.07892, 2024.

Used for: realistic trace-generation and evaluation concerns. This preprint is cited as related methodology, not as evidence for a Trahens privacy claim.

### RealityCheck2026

Mahdi Shadbeh, Kaveh Khajavi, and Tao Wang, **“A Reality Check on Website Fingerprinting,”** arXiv:2603.07412, 2026 preprint.

Used for: the gap between laboratory classifier results and realistic deployment assumptions. The paper identifies it as a preprint.

### ActiveFlowMark2026

Z. Fan et al., **“ActiveFlowMark: Robust Active Flow Marking Against Encrypted Traffic,”** arXiv:2605.05887, 2026 preprint.

Used for: current active-flow modulation context. The paper identifies it as a preprint and does not attribute its claims to the Trahens T3 probe model.

## Additional repository-originated T3 results

The following current-paper results are generated by the repository and are not attributed to the cited external papers:

- the exact per-link super-epoch budget contract;
- the fixed, adaptive, and hybrid trace generators;
- the four-link route-label workload;
- the transparent standardized nearest-centroid classifier;
- the boundary-alignment and lagged-correlation measurements;
- the bounded positive-demand probe and threshold rule;
- all reported route-classification, probe-detection, queue, delivery, budget, and cleanup values.

The citations establish relevant prior attacks, defenses, and evaluation concerns. They do not prove the Trahens composition secure or insecure.

## T4 packet-level evaluation sources

### JansenHopper2012

Rob Jansen and Nicholas Hopper, **“Shadow: Running Tor in a Box for Accurate and Efficient Experimentation,”** Network and Distributed System Security Symposium, 2012.

Used for: the need for controlled, reproducible, large-scale anonymity-system experimentation and the distinction between a small deterministic falsification harness and a validated network simulator. Trahens T4 does not claim to implement or reproduce Shadow.

### JansenEtAl2012Model

Rob Jansen, Kevin Bauer, Nicholas Hopper, and Roger Dingledine, **“Methodically Modeling the Tor Network,”** 5th Workshop on Cyber Security Experimentation and Test, USENIX Association, 2012.

Used for: the requirement to expose and justify topology, traffic, capacity, queue, timing, and workload assumptions rather than treating a simulation result as deployment evidence.

### ZanderMurdoch2008

Sebastian Zander and Steven J. Murdoch, **“An Improved Clock-skew Measurement Technique for Revealing Hidden Services,”** 17th USENIX Security Symposium, 2008, pp. 211-225.

Used for: the treatment of clock skew, network jitter, and timestamp quantisation as distinct effects in remote timing observations. T4 uses a simplified affine observer clock and does not reproduce the paper's hidden-service attack.

### WailsEtAl2018Tempest

Ryan Wails, Yixin Sun, Aaron Johnson, Mung Chiang, and Prateek Mittal, **“Tempest: Temporal Dynamics in Anonymity Systems,”** Proceedings on Privacy Enhancing Technologies, 2018(3), pp. 22-42, DOI 10.1515/popets-2018-0019.

Used for: the requirement to evaluate route changes and other temporal dynamics as privacy variables rather than only availability events.

### Open-world sources

The existing WangEtAl2014, HayesDanezis2016, CherubinJansenTroncoso2022, GTT23, and RealityCheck2026 entries are used at the point where T4 distinguishes monitored recall, unknown false positives, disjoint unknown calibration/testing routes, and the limits of laboratory classifiers.

### Active-delay sources

The existing Dropmark, DUSTER, DeepCorr, throughput-fingerprinting, and ActiveFlowMark entries are used where T4 defines and limits its bounded selective-delay experiment. T4's transparent phase/lag detector is repository-originated and is not attributed to those systems.

## Additional repository-originated T4 results

The following results and constructions originate in this repository:

- the four-link deterministic packet-event emulator;
- access and shared-bottleneck serialization rules;
- the affine observer-clock implementation and deterministic clock parameters;
- the online exact-budget scheduler;
- the monitored, unknown-calibration, and unknown-test route split;
- the standardized nearest-centroid open-world classifier and threshold rule;
- the route-churn implementation;
- the bounded selective-delay pulse and detector;
- all T4 delivery, delay, queue, budget, cleanup, open-world, and detector measurements.

External citations establish relevant methodological risks and prior attacks. They do not validate the T4 implementation or prove a Trahens privacy property.
