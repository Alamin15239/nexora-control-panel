import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-static-deployment-node.sh"


class StaticDeploymentInstallerTests(unittest.TestCase):
    def test_help_is_available_without_privilege_or_mutation(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--apply", result.stdout)
        self.assertIn("never starts", result.stdout)

    def test_plan_lists_installation_without_mutating_host(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            for name in ("nexora-static-vhostd", "nexora-static-publisher"):
                path = root / name
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            (root / "nexora-static-vhostd.service").write_text(
                "[Service]\nUser=root\nGroup=nexora-static\n", encoding="utf-8")
            (root / "nexora-static-publisher.service").write_text(
                "[Service]\nUser=nexora-runtime\nGroup=www-data\nSupplementaryGroups=nexora-static\n",
                encoding="utf-8")
            result = subprocess.run(
                ["bash", str(SCRIPT), "--artifact-dir", str(root), "--plan"],
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PLAN ONLY", result.stdout)
            self.assertIn("stopped and disabled", result.stdout)
            self.assertNotIn("systemctl", result.stdout)

    def test_plan_requires_artifact_directory(self):
        result = subprocess.run(["bash", str(SCRIPT), "--plan"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--artifact-dir is required", result.stderr)

    def test_apply_is_explicitly_approved_and_non_activating(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "MODE=plan", "--apply", "--node-id", "/etc/nexora-static-node/approval.json",
            '"environment") != "disposable-test"', "allow_static_publisher_install",
            "Refusing to install on protected development host nexora-server",
            "root:root:600", "Refusing to overwrite existing target",
            "Group=www-data", "SupplementaryGroups=nexora-static",
            'runtime_uid" -lt 1000', 'runtime_home" == "/var/lib/nexora-static"',
            'runtime_shell" == "/usr/sbin/nologin"',
            "Existing nexora-runtime primary group is not www-data",
            "Existing nexora-runtime shell is not /usr/sbin/nologin",
            "stopped and disabled",
        ):
            self.assertIn(required, source)
        for forbidden in ("systemctl start", "systemctl enable", "systemctl restart", "systemctl daemon-reload"):
            self.assertNotIn(forbidden, source)

    def test_artifact_paths_reject_symlinks(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('[[ -d "$ARTIFACT_DIR" && ! -L "$ARTIFACT_DIR" ]]', source)
        self.assertIn('[[ -f "$ARTIFACT_DIR/$file" && ! -L "$ARTIFACT_DIR/$file" ]]', source)


if __name__ == "__main__":
    unittest.main()
