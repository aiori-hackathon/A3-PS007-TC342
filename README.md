# HackHive PS-007 — Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

**Team:** HackHive  
**Team code:** A3-PS007-TC342  
**Problem statement:** PS-007  
**Institute:** BMS College of Engineering

## What this package does

This beginner-friendly Python package implements an **offline simulation** of the PS-007 monitoring logic:

- Models five IoT devices plus an unauthorized router source.
- Simulates authenticated events using demo tokens (not production authentication).
- Uses tenant-scoped, short-lived random pseudonyms.
- Detects unauthorized Router Advertisement (RA) events.
- Detects abnormal NDP event rates in a configurable time window.
- Rejects events with invalid demo tokens.
- Checks pseudonym renewal after expiry and tenant-scoped pseudonym separation.
- Produces a JSON report and includes unit tests.

**Important limitation:** this package does not create an actual IPv6 LAN, emulate real network interfaces, rotate OS IPv6 addresses, or capture live packets. It is the offline software prototype and test harness. The official method asks for one IPv6 LAN with five emulated devices; that network stage must still be set up and tested separately before claiming full completion.

## Windows 10/11 — step by step

1. Install Python 3.11+ from https://www.python.org/downloads/windows/. During setup, check **Add Python to PATH**.
2. Extract the ZIP into a folder, e.g. `Documents\HackHive_PS007`.
3. Open that folder in Visual Studio Code, or open File Explorer in the folder.
4. In VS Code choose **Terminal → New Terminal**. Alternatively, click the File Explorer address bar, type `cmd`, and press Enter.
5. Check Python:
   ```powershell
   py --version
   ```
6. Run the built-in simulation:
   ```powershell
   py monitor.py
   ```
7. Run the tests:
   ```powershell
   py -m unittest -v
   ```
8. Open `reports\alerts.json` to inspect the generated report.
9. Optional: use a JSON input file:
   ```powershell
   py monitor.py --input sample_events.json --output reports\sample-report.json
   ```
10. Optional: change NDP threshold/window/session TTL:
   ```powershell
   py monitor.py --threshold 4 --window 10 --ttl 30
   ```

If `py` does not work, try replacing `py` with `python`.

## Two required attack scenarios represented

1. **Rogue RA:** a simulated RA from `rogue-router`, which is not in the `AUTHORIZED_ROUTERS` allowlist, should create a `rogue_ra` alert.
2. **Abnormal NDP burst:** repeated NDP events from `device-3` inside the configured 10-second window should create an `abnormal_ndp_rate` alert.

These are simulated events, not actual packets.

## Test and evaluation plan

Run `py -m unittest -v`. Tests check rogue-RA detection, NDP-burst detection, rejection of a wrong token, session expiry, tenant-scoped pseudonyms, and threshold validation.

For the real testbed, record results in a separate results table. Do not claim metrics until you run the tests and record observed outcomes.

Suggested metrics:
- Detection rate = true positives / (true positives + false negatives) × 100%
- False-positive rate = false positives / (false positives + true negatives) × 100%
- Detection latency = alert timestamp − injected event timestamp, where applicable
- Pseudonym expiry success = sessions renewed after expiry / expiry trials × 100%
- Resource overhead: process CPU and memory measured during repeated runs

## Suggested repository layout

```text
A3-PS007-TC342/
├── monitor.py
├── test_monitor.py
├── sample_events.json
├── requirements.txt
├── README.md
└── reports/
    └── alerts.json   # generated after running
```

## What remains before claiming the full PS-007 task is complete

- Build an isolated IPv6 LAN with five emulated devices (for example, a Linux VM and an appropriate network-emulation environment).
- Generate and capture real RA/NDP traffic only inside that authorized lab.
- Integrate the packet collector with the monitoring pipeline.
- Exercise the two required attacks in the isolated testbed.
- Evaluate detection rate, false positives, pseudonym expiry, and cross-tenant non-correlation using observed data.
- Record environment, commands, outputs, and limitations.

Never run rogue-router or traffic-flood tests on a campus, home, or public network. Use only an isolated lab you control or have permission to test.
