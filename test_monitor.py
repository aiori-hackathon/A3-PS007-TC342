import unittest
from monitor import analyze_events, make_demo_events
from monitor import SessionManager


class PS007Tests(unittest.TestCase):
    def test_demo_has_five_devices(self):
        report = analyze_events(make_demo_events())
        self.assertEqual(report["summary"]["devices_seen"], 6)  # includes rogue router

    def test_rogue_ra_detected(self):
        report = analyze_events(make_demo_events())
        self.assertTrue(any(a["type"] == "rogue_ra" for a in report["alerts"]))

    def test_ndp_burst_detected(self):
        report = analyze_events(make_demo_events())
        self.assertTrue(any(a["type"] == "abnormal_ndp_rate" for a in report["alerts"]))

    def test_wrong_token_rejected(self):
        events = [{"timestamp": 1, "tenant": "t", "device": "device-1",
                   "token": "wrong", "type": "NDP"}]
        report = analyze_events(events)
        self.assertEqual(report["summary"]["authenticated_events_accepted"], 0)
        self.assertEqual(report["summary"]["events_rejected_auth_or_validation"], 1)

    def test_pseudonym_expiry(self):
        manager = SessionManager(ttl_seconds=5)
        first = manager.authenticate("device-1", "tenant-A", "demo-token-device-1", 10)
        same = manager.authenticate("device-1", "tenant-A", "demo-token-device-1", 12)
        renewed = manager.authenticate("device-1", "tenant-A", "demo-token-device-1", 16)
        self.assertEqual(first, same)
        self.assertNotEqual(first, renewed)

    def test_tenant_scoping(self):
        manager = SessionManager()
        a = manager.authenticate("device-1", "tenant-A", "demo-token-device-1", 10)
        b = manager.authenticate("device-1", "tenant-B", "demo-token-device-1", 10)
        self.assertNotEqual(a, b)

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            analyze_events([], ndp_threshold=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
