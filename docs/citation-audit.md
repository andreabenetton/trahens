# Citation and claim audit

This file maps external claims in the current paper and specifications to primary sources. It does not treat a citation as proof that the complete Trahens composition is secure.

## Anonymity systems

### Sphinx2009

George Danezis and Ian Goldberg, **“Sphinx: A Compact and Provably Secure Mix Format,”** IEEE Symposium on Security and Privacy, 2009, pp. 269-282.

Used for: compact per-hop transformed mix packets, reply support, and formal mix-packet context.

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

Used for: recipient/key privacy context.

### PrabhakaranRosulek2007

Manoj Prabhakaran and Mike Rosulek, **“Rerandomizable RCCA Encryption,”** CRYPTO 2007, LNCS 4622, pp. 517-534.

Used for: rerandomizable RCCA encryption and the distinction between rerandomization and realized receiver anonymity.

### Wang2021

Yong Wang, Rui Chen, Guomin Yang, Xinyi Huang, Bin Wang, and Moti Yung, **“Receiver-Anonymity in Rerandomizable RCCA-Secure Cryptosystems Resolved,”** CRYPTO 2021, LNCS 12828, pp. 270-300, DOI `10.1007/978-3-030-84259-8_10`; full version IACR ePrint 2021/862.

Used for: the receiver-anonymous rerandomizable RCCA target and the exact k=2 source-to-code audit. The Trahens counterexample concerns only the literal finite-field interpretation implemented from the cited equations. It is not presented as a refutation of the paper's generic framework or an author-confirmed corrected interpretation.

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
- RFC 9180: HPKE structure and context-binding discipline; Trahens reply KEM is not claimed to be RFC 9180 HPKE.
- RFC 9496: `ristretto255` encodings and group abstraction.
- RFC 5869: HKDF.
- RFC 8439: ChaCha20-Poly1305.
- RFC 8032: Ed25519.

## Repository-originated results

The following are not attributed to external papers:

- R1 endpoint-independent service-query nonce and one-time capability state machine;
- the deterministic R1 literal-marker experiment;
- the C1 ratio-tag implementation and integrated regression result;
- the exact finite-field counterexample and exhaustive small-chain checker;
- M2/W2 encodings, fragmentation, reassembly, and route lifecycle;
- T1 DATA/ACK/CHAFF framing, adjacent-link transmission identifiers, bounded selective recovery, and retry ciphertext vectors;
- T2 SCHEDULE framing, finite rate menus, hysteresis, weighted equal-cell service, admission, and overload rules;
- fixed/adaptive/work-conserving congestion, leakage, burst-loss, fairness, and multi-link correlation measurements;
- all simulator performance, bandwidth, queue, delay, and cleanup measurements.

Each such result is accompanied by executable artifacts or tests. None is described as a cryptographic proof.
