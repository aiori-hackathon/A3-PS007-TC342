# PS-007 Implementation Plan

## Phase 1 — Offline software prototype
- [x] RA allowlist logic
- [x] NDP time-window threshold
- [x] Demo-token validation
- [x] Short-lived tenant-scoped pseudonyms
- [x] JSON report
- [x] Unit tests
- [ ] Run tests on the team's Windows laptop and preserve genuine output

## Phase 2 — IPv6 testbed (required by mentor methodology)
1. Use an isolated Linux VM or approved network-emulation environment.
2. Create one IPv6 LAN and five emulated IoT nodes.
3. Enable IPv6 temporary addresses where supported and document how address rotation is observed.
4. Capture normal RA/NDP baseline traffic.
5. Add a collector for actual RA/NDP packets and map normalized events into the monitor.
6. Test only in the isolated lab: (a) rogue RA, (b) abnormal NDP rate.
7. Confirm the collector and the detector distinguish the two scenarios.

## Phase 3 — Evaluation
- Prepare labeled benign and attack event sets.
- Count true positives, false positives, true negatives, and false negatives.
- Calculate detection and false-positive rates.
- Test session expiry repeatedly.
- Verify the same device does not receive a shared stable pseudonym across tenant contexts.
- Measure latency and resource use; include actual observations only.

## Phase 4 — Evidence and submission
- Keep commands, test output, configuration, test dataset, and JSON reports.
- Document limitations and environment versions.
- Check the official AIORI-3 rubric for the exact required deliverables.
