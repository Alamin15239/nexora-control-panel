import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight-static-deployment-node.sh"


class StaticDeploymentPreflightContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_preflight_is_explicitly_read_only(self):
        self.assertIn("Read-only acceptance preflight", self.source)
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
            "broker binary is root:root 755",
            "publisher binary is root:root 755",
            "broker unit is root:root 644",
            "publisher unit is root:root 644",
            'grep -Fxq "Group=www-data"',
            'grep -Fxq "SupplementaryGroups=nexora-static"',
        ):
            self.assertIn(required, self.source)

    def test_matches_deployment_trust_and_validates_registry(self):
        for required in (
            "deployment_envelope_issuer", "deployment_envelope_audience",
            "deployment_signing_key_id", "linuxUsername", "linuxUid",
            "domainId", "hostingAccountId", "hostname",
            "duplicate domain ID or hostname",
            "set(config) != expected_config",
            "set(account) != {\"hostingAccountId\", \"linuxUsername\", \"linuxUid\"}",
            "set(domain) != {\"domainId\", \"hostingAccountId\", \"hostname\"}",
            "reserved Linux identity",
            "private_key_file",
            "deployment_signing_public_key_file",
            'set(bindings) != {"accounts", "domains"}',
            "publisher node private key must encode exactly 64 Ed25519 bytes",
            "1 <= len(bindings[\"accounts\"]) <= 10000",
            "1 <= len(bindings[\"domains\"]) <= 50000",
            "1000 <= uid <= 4294967295",
            "not isinstance(trust, dict)",
            "not isinstance(config, dict)",
            "not isinstance(bindings, dict)",
            're.fullmatch(r"https://[^/?#@]+", config["control_plane_url"])',
        ):
            self.assertIn(required, self.source)

    def test_does_not_activate_services(self):
        self.assertIn("nginx -t", self.source)
        self.assertIn("systemd-analyze verify", self.source)
        self.assertIn("Do not start or enable either service.", self.source)
        self.assertNotIn("systemctl enable", self.source)


if __name__ == "__main__":
    unittest.main()
