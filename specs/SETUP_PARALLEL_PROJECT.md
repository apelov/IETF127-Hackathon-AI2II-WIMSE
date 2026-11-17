# Parallel Project Setup: OpenA2A + WIMSE (AI2II) + AEP

This guide provides the exact terminal commands and steps to launch a clean, isolated parallel workspace for the Abdel Fane / OpenA2A collaboration without conflicting with the ongoing WIMSE hackathon work.

---

## Quick Run (Automated)

Run the included setup script from your current repository root:

```bash
./setup/setup_parallel_project.sh
cd ../opena2a-wimse-aep
agy
```

---

## Manual Steps & Terminal Commands

If you prefer to run the commands step-by-step:

```bash
# 1. Create a clean, isolated git worktree in a parallel directory
git worktree add ../opena2a-wimse-aep -b feature/opena2a-wimse-aep
cd ../opena2a-wimse-aep

# 2. Create the specs and assets directories
mkdir -p specs assets

# 3. Copy the specification and architecture diagram from this repo
#    (WIMSE_REPO is the path of your IETF127-Hackathon-AI2II-WIMSE checkout)
cp "$WIMSE_REPO"/specs/OPENA2A_WIMSE_AEP_SPEC.md specs/OPENA2A_WIMSE_AEP_SPEC.md
cp "$WIMSE_REPO"/assets/opena2a-wimse-aep-architecture.jpg assets/opena2a-wimse-aep-architecture.jpg

# 4. Launch an agent in the new workspace
agy
```

---

## Initial Prompt to Give to the Parallel Agent

Once `agy` starts in `../opena2a-wimse-aep`, paste this prompt:

> "Read `specs/OPENA2A_WIMSE_AEP_SPEC.md`. We are collaborating with Abdel Fane (OpenA2A) and Anton (AEP) on a cross-domain agent payment flow for Thursday 11:30 (Continental 7).
> Our responsibility is the WIMSE AI2II cross-domain bridge (Scenario 1 legitimate payment and Scenario 2 prompt injection containment).
> Implement the file-exchange harness producing `handover/wimse_ai2ii/` containing `capture_scenario1.pcap`, `decision-journal.jsonl`, `verdict.json`, and `jwks.json` per Section 4 of the spec."

---

## Deliverables Generated in the Parallel Workspace

Per the specification in [`specs/OPENA2A_WIMSE_AEP_SPEC.md`](OPENA2A_WIMSE_AEP_SPEC.md):

- `handover/wimse_ai2ii/capture_scenario1.pcap`
- `handover/wimse_ai2ii/decision-journal.jsonl`
- `handover/wimse_ai2ii/verdict.json`
- `handover/wimse_ai2ii/jwks.json`
- `checkers/observes_payment.py`
