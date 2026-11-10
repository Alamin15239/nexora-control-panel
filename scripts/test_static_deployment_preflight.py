import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight-static-deployment-node.sh"


class StaticDeploymentPreflightContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_preflight_is_explicitly_read_only(self):
        self.assertIn("read-only acceptance preflight", self.source)
        self.assertIn("No services will be started, stopped, enabled, or reloaded.", self.source)
        for forbidden in (
            "systemctl start", "systemctl enable", "systemctl restart",
            "systemctl reload", "chmod ", "chown ", "mkdir ", "rm -",
            "install -", "cp ", "mv ",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_checks_both_service_identities_and_filesystem_boundaries(self):
        for required in (
            'id -gn nexora-runtime', "nexora-static",
            "/etc/nexora-static-vhost/trust.json",
            "/etc/nexora-static-vhost/bindings.json",
            "/etc/nexora-static-publisher/node-ed25519.key",
            "/var/lib/nexora-static/accounts",
            "/var/lib/nexora-static/replay",
            "runuser -u www-data -- test -x",
        ):
            self.assertIn(required, self.source)

    def test_matches_deployment_trust_and_validates_registry(self):
        for required in (
            "deployment_envelope_issuer", "deployment_envelope_audience",
            "deployment_signing_key_id", "linuxUsername", "linuxUid",
            "domainId", "hostingAccountId", "hostname",
            "duplicate domain ID or hostname",
        ):
            self.assertIn(required, self.source)

    def test_does_not_activate_services(self):
        self.assertIn("nginx -t", self.source)
        self.assertIn("systemd-analyze verify", self.source)
        self.assertIn("Do not start or enable either service.", self.source)
        self.assertNotIn("systemctl enable", self.source)


if __name__ == "__main__":
    unittest.main()
