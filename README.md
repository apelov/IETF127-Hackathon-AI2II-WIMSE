# IETF 127 WIMSE + OAuth + Agent Call-Chain Interop Harness

This repository contains the complete implementation, loopback packet captures (`.pcap`), structured decision journals (`.jsonl`), partner traces (`P1–P8`), and **AI2II** verification bundles (`inbound` and `chain`) from the **IETF 127 Hackathon WIMSE Interop**.

## Key Documentation Index

- **[`TEST_RESULTS_SUMMARY.md`](TEST_RESULTS_SUMMARY.md)** — Executive summary table of all tested suites, implementations, scenarios, and results (**85/85 passing cases + 9/9 rejected negative PCAP mutants**).
- **[`SCENARIOS_AND_AUTHORS.md`](SCENARIOS_AND_AUTHORS.md)** — Complete contributor & implementation table (**AgentMaurice**, **RICH**, **Redthread Security**, **MintID**, **OmniArx**, **Cred**), normative Internet-Drafts & RFCs, AI model provenance table (AI2II Rule L4), and full catalog of all 3 test suites:
  - **Suite 1 (`inbound` cell):** 34 WIMSE inbound cases (`A2–A13j`, `C2–C12b`, `IN4–IN15`) against local **AgentMaurice** (`:5050`).
  - **Suite 2 (`chain` cell):** 19 3-Agent, 2-Domain call-chain (`Agent 1: Maurice -> Agent 2: RICH Coordinator -> Agent 3: RICH Research Sub-Agent -> File Tool`) and mid-transaction revocation / attack cases (`B_CHAIN`, `C5–C10`, `D1–D7`) across `:5050–5063`.
  - **Suite 3 (`chain` cell + partner traces):** Extended partner scenarios `P1–P8` (`ietf127-wimse-scenario/1`) — loopback HTTP cases on `:5064` (`P2` simulated with Redthread's code; `P7` and `P8` mocked with fixed answers) plus trace verification of Redthread `P1–P6`, MintID live `mintid-testnet-3` non-revocation proofs, OmniArx `P7` approval display vectors, and Cred `P8` pre-release vs post-release bearer revocation boundaries.
- **Continuation:** a joint cross-domain agent payment scenario with OpenA2A (Abdel Fane) and AEP (Anton) is on branch `feature/opena2a-wimse-aep` ([`specs/OPENA2A_WIMSE_AEP_SPEC.md`](specs/OPENA2A_WIMSE_AEP_SPEC.md)). It is not part of the hackathon results above: its OpenA2A gate and AEP verifier are prototype stand-ins written here, and runs with the partners' own components are pending.
- **[`EVIDENCE.md`](EVIDENCE.md)** — Exact SHA-256 digests, packet counts, and `tshark` one-liners for all committed `.pcap` captures, negative PCAP mutants, and `.jsonl` journals.
- **[`scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md`](scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md)** — Sanitized technical summary of the multi-party design and trace-verification discussions across `P1–P8`.
- **[`workpackages/WP09-live-redthread-and-mintid-testnet.md`](workpackages/WP09-live-redthread-and-mintid-testnet.md)** — **Future TODO specification** for running Redthread (source location to be provided by Ben Le) and `mintid` (`deploy/networks.json` `testnet` profile: `issuer`, `verifier`, `relay`, `rpc.testnet.mintid.net:443`) to run `P1–P6` and positive/negative `P2` ZK non-revocation proofs live end-to-end.
- **[`VERIFY.md`](VERIFY.md)** — Detailed manual walkthrough for inspecting individual cases and logs.

---

## Quick Reproduction (Fresh Git Clone)

Anyone cloning this repository can verify all committed PCAP captures (`inbound` and `chain`), AI2II evidence bundles (`SHA256SUMS` + `verdict.json`), all 9 negative mutant PCAP rejections, and `P1–P8` partner manifests with a single command (requires only Python 3 and `tshark`):

```sh
./reproduce.sh
```

The AI2II `wire` harness is vendored directly in `wire/`, and `reproduce.sh` automatically creates `.venv` (installing `requirements.txt`) and generates ephemeral test keys in `keys/` if missing.

---

## Exploring Captures in Wireshark (`dissectors/wimse.lua`)

A custom Lua post-dissector in [`dissectors/wimse.lua`](dissectors/wimse.lua) automatically binds loopback ports `5050–5064` to HTTP, tags packets with `[Case: <ID>]` in the Info column, and base64url-decodes WIMSE `Workload-Identity-Token` (WIT), `Workload-Proof-Token` (WPT), OAuth `Txn-Token`, `Authorization: Bearer` tokens, and RFC 9421 `Signature-Input` parameters into a collapsible **IETF WIMSE & OAuth Agent Call Chain** protocol tree.

To install it permanently into your personal Wireshark Lua plugins directory (macOS / Linux):

```sh
mkdir -p ~/.local/lib/wireshark/plugins
cp dissectors/wimse.lua ~/.local/lib/wireshark/plugins/wimse.lua
```

Or pass it on demand to `wireshark` or `tshark`:

```sh
wireshark -X lua_script:dissectors/wimse.lua validation/bundle-inbound/inbound/capture.pcap
wireshark -X lua_script:dissectors/wimse.lua validation/bundle-chain/chain/capture.pcap
tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-chain/chain/capture.pcap -Y 'wimse.test_case == "B_CHAIN"' -O wimse
```

Useful Wireshark display filters:
- `wimse.test_case == "B_CHAIN"` — filter by scenario/case ID (`A2`, `C12`, `B_CHAIN`, `C7`, `P2_BEFORE_EFFECT`, `P7_R2`, `P8_BEFORE_RELEASE`, etc.)
- `wimse.wit.sub contains "rich.ietf127.example"` — filter by workload identity URI
- `wimse.wpt.wth` — show requests carrying a WPT proof
- `wimse.sig.wimse_aud` — show requests signed with RFC 9421 HTTP Message Signatures
- `wimse.txn.id == "<uuid>"` — trace a single transaction ID across all agent hops (`Agent 1 -> Agent 2 -> Agent 3 -> Tool`)

---

## Live Capture Setup (with Local AgentMaurice)

To re-run the live packet captures against a local **AgentMaurice** instance:

1. **Install AgentMaurice** (`~/.local/bin/maurice`, no Docker or account required; supports macOS Apple Silicon, Linux `x86_64`/`arm64`, Windows `x64`) by following [https://agentmaurice.ai/en/install.md](https://agentmaurice.ai/en/install.md), or give your AI coding agent this prompt:

   ```text
   Install Maurice by following https://agentmaurice.ai/en/install.md, then verify that you can use it.
   ```

2. Ensure `/etc/hosts` maps the test trust domain to loopback (`127.0.0.1 maurice.ietf127.example`), generate the ephemeral test keys, and patch the WIMSE configuration:

```sh
python3 setup/gen_keys.py
python3 setup/patch_config.py
```

`patch_config.py` backs up the existing `~/.maurice/one/config/standalone.yaml` before replacing its trailing `wimse:` block.

3. Run both cells (`inbound` and `chain`) live via `./reproduce.sh --live`, or invoke the vendored `wire` runner directly on a clean git working tree:

```sh
PYTHONPATH=. .venv/bin/python -m wire run interop.yaml --cell inbound --out /tmp/wimse-bundle-inbound
PYTHONPATH=. .venv/bin/python -m wire run interop.yaml --cell chain --out /tmp/wimse-bundle-chain
PYTHONPATH=. .venv/bin/python -m wire summarize validation
```

---

## Current Verification Status (2026-11-14)

Both AI2II cells (`inbound` and `chain`) are **PASS**:

```text
PASS	inbound	458453327d36	validation/bundle-inbound/inbound
PASS	chain	8f8441e4af00	validation/bundle-chain/chain
```

- **`inbound` (`validation/bundle-inbound/inbound/`):** 34/34 cases passed against `bin/maurice` (sha256 `36f92fe8...`), verified by `checkers/observes_wimse.py` (NVIDIA Nemotron Ultra), rejecting all 3 negative mutants (`unrelated.pcap`, `request_only.pcap`, `forbidden_fetch.pcap`).
- **`chain` (`validation/bundle-chain/chain/`):** 19/19 3-agent cross-domain call-chain & attack cases (`:5050–5063`) + 10 `P2/P7/P8` loopback cases on `:5064` (2 simulated, 2 replayed, 6 mocked; see `TEST_RESULTS_SUMMARY.md`) passed, verified by `checkers/observes_chain.py` and `checkers/observes_p1_p8.py`, rejecting all 6 negative mutants (`chain_unrelated.pcap`, `chain_request_only.pcap`, `chain_leaked_txn.pcap`, `p1_p8_unrelated.pcap`, `p1_p8_request_only.pcap`, `p1_p8_missing_before_effect.pcap`).

## Contributing

Pull requests are welcome, including results from your own implementation. See [`CONTRIBUTING.md`](CONTRIBUTING.md); every pull request is checked by `./reproduce.sh` on GitHub.

## License

Work by Alexander Pelov is available under either the [Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at your option. Files contributed by Redthread Security, MintID, OmniArx, Cred and others remain credited to them and are not relicensed; see [`NOTICE`](NOTICE).
