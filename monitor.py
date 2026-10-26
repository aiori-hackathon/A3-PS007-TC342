"""
HackHive PS-007: Privacy-aware IPv6 IoT security monitor.
This is a safe, offline simulation. It does NOT capture live IPv6 traffic.
Python 3.10+; standard library only.
"""
from __future__ import annotations
import argparse
import json
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path

AUTHORIZED_ROUTERS = {"router-1"}
WINDOW_SECONDS = 10
NDP_THRESHOLD = 4
SESSION_TTL_SECONDS = 30


class SessionManager:
    """In-memory authenticated-session demo with tenant-scoped pseudonyms.

    Authentication here is a simulation: events must carry a known demo token.
    Real deployments need a proper authenticated transport/identity mechanism.
    """
    def __init__(self, ttl_seconds=SESSION_TTL_SECONDS):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self.sessions = {}

    def authenticate(self, device_id, tenant_id, token, now):
        expected = f"demo-token-{device_id}"
        if not isinstance(token, str) or not secrets.compare_digest(token, expected):
            return None
        key = (tenant_id, device_id)
        session = self.sessions.get(key)
        if session is None or now >= session["expires_at"]:
            session = {
                "pseudonym": "dev-" + secrets.token_hex(4),
                "expires_at": now + self.ttl_seconds,
            }
            self.sessions[key] = session
        return session["pseudonym"]

    def cleanup(self, now):
        for key in list(self.sessions):
            if now >= self.sessions[key]["expires_at"]:
                del self.sessions[key]


def make_demo_events():
    """Deterministic simulated traffic: five devices, two attack scenarios."""
    events = []
    t = 1000
    # Five devices; benign baseline.
    for device in range(1, 6):
        events.append({
            "timestamp": t + device,
            "tenant": "tenant-A",
            "device": f"device-{device}",
            "token": f"demo-token-device-{device}",
            "type": "NDP",
        })
    # Attack scenario 1: unauthorized rogue Router Advertisement.
    events.append({
        "timestamp": 1008, "tenant": "tenant-A",
        "device": "rogue-router", "token": "demo-token-rogue-router",
        "type": "RA",
    })
    # Attack scenario 2: abnormal NDP burst from device-3 in one window.
    for offset in range(9, 16):
        events.append({
            "timestamp": 1000 + offset,
            "tenant": "tenant-A",
            "device": "device-3",
            "token": "demo-token-device-3",
            "type": "NDP",
        })
    # Demonstrate temporary IPv6 address rotation; the monitor does not use
    # the address as a persistent identity. This field is simulation metadata.
    events.append({
        "timestamp": 1020, "tenant": "tenant-A",
        "device": "device-3", "token": "demo-token-device-3",
        "type": "NDP", "ipv6_address": "2001:db8:1::103",
    })
    events.append({
        "timestamp": 1025, "tenant": "tenant-A",
        "device": "device-3", "token": "demo-token-device-3",
        "type": "NDP", "ipv6_address": "2001:db8:1::9f3",
    })
    # Invalid token should be rejected; it must not produce a detection event.
    events.append({
        "timestamp": 1026, "tenant": "tenant-A",
        "device": "device-2", "token": "wrong-token", "type": "NDP",
    })
    return sorted(events, key=lambda item: item["timestamp"])


def analyze_events(events, ndp_threshold=NDP_THRESHOLD, window_seconds=WINDOW_SECONDS,
                   session_ttl=SESSION_TTL_SECONDS):
    if ndp_threshold < 1:
        raise ValueError("ndp_threshold must be at least 1")
    if window_seconds <= 0 or session_ttl <= 0:
        raise ValueError("window_seconds and session_ttl must be positive")

    sessions = SessionManager(session_ttl)
    ndp_windows = defaultdict(deque)
    alerts = []
    accepted = 0
    rejected = 0
    seen_devices = set()
    expiry_observed = False
    pseudonym_by_tenant_device = {}

    for event in sorted(events, key=lambda item: item.get("timestamp", 0)):
        try:
            timestamp = float(event["timestamp"])
            tenant = str(event["tenant"])
            device = str(event["device"])
            token = event["token"]
            event_type = str(event["type"]).upper()
        except (KeyError, TypeError, ValueError):
            rejected += 1
            continue

        if event_type not in {"RA", "NDP"}:
            continue
        pseudonym = sessions.authenticate(device, tenant, token, timestamp)
        if pseudonym is None:
            rejected += 1
            continue

        accepted += 1
        seen_devices.add((tenant, device))
        pseudonym_by_tenant_device[(tenant, device)] = pseudonym

        if event_type == "RA" and device not in AUTHORIZED_ROUTERS:
            alerts.append({
                "timestamp": timestamp,
                "type": "rogue_ra",
                "tenant": tenant,
                "pseudonym": pseudonym,
                "message": "Router Advertisement from a source not in the authorized-router allowlist",
                "scenario": "attack_1_rogue_ra",
            })

        if event_type == "NDP":
            key = (tenant, pseudonym)
            queue = ndp_windows[key]
            while queue and timestamp - queue[0] > window_seconds:
                queue.popleft()
            queue.append(timestamp)
            if len(queue) == ndp_threshold + 1:
                alerts.append({
                    "timestamp": timestamp,
                    "type": "abnormal_ndp_rate",
                    "tenant": tenant,
                    "pseudonym": pseudonym,
                    "count_in_window": len(queue),
                    "window_seconds": window_seconds,
                    "message": "NDP count exceeded threshold in the configured time window",
                    "scenario": "attack_2_ndp_burst",
                })

        # Tenant isolation is enforced by (tenant, device) session keys.
        sessions.cleanup(timestamp)

    # Check that the same device gets distinct pseudonyms in distinct tenants.
    # This is an offline property test; it does not claim cryptographic isolation.
    isolation_test = SessionManager(session_ttl)
    tenant_a = isolation_test.authenticate("device-1", "tenant-A", "demo-token-device-1", 5000)
    tenant_b = isolation_test.authenticate("device-1", "tenant-B", "demo-token-device-1", 5000)
    cross_tenant_distinct = tenant_a != tenant_b

    # Expiry test: session identity changes at/after TTL.
    expiry_test = SessionManager(ttl_seconds=5)
    p1 = expiry_test.authenticate("device-test", "tenant-test", "demo-token-device-test", 10)
    p2 = expiry_test.authenticate("device-test", "tenant-test", "demo-token-device-test", 16)
    expiry_observed = p1 != p2

    return {
        "summary": {
            "mode": "offline_simulation",
            "events_received": len(events),
            "authenticated_events_accepted": accepted,
            "events_rejected_auth_or_validation": rejected,
            "devices_seen": len(seen_devices),
            "alerts_found": len(alerts),
            "ndp_threshold": ndp_threshold,
            "ndp_window_seconds": window_seconds,
            "session_ttl_seconds": session_ttl,
        },
        "privacy_checks": {
            "pseudonym_changes_after_expiry": expiry_observed,
            "same_device_has_distinct_tenant_pseudonyms": cross_tenant_distinct,
            "raw_device_ids_in_alerts": False,
            "note": "Simulation property checks only; not a formal anonymity guarantee."
        },
        "alerts": alerts,
    }


def main():
    parser = argparse.ArgumentParser(description="HackHive PS-007 offline IPv6 monitoring simulation")
    parser.add_argument("--input", help="Optional JSON list of events; default uses built-in demo")
    parser.add_argument("--output", default="reports/alerts.json", help="Report JSON output path")
    parser.add_argument("--threshold", type=int, default=NDP_THRESHOLD)
    parser.add_argument("--window", type=float, default=WINDOW_SECONDS)
    parser.add_argument("--ttl", type=float, default=SESSION_TTL_SECONDS)
    args = parser.parse_args()

    try:
        if args.input:
            events = json.loads(Path(args.input).read_text(encoding="utf-8"))
            if not isinstance(events, list):
                raise ValueError("Input must be a JSON list")
        else:
            events = make_demo_events()
        report = analyze_events(events, args.threshold, args.window, args.ttl)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print("=== HackHive PS-007 IPv6 Security Monitor ===")
        print("Mode: OFFLINE SIMULATION (not live packet capture)")
        for key, value in report["summary"].items():
            print(f"{key}: {value}")
        for alert in report["alerts"]:
            print(f"[ALERT] {alert['type']} | {alert['pseudonym']} | {alert['message']}")
        print(f"Report saved to: {output}")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
