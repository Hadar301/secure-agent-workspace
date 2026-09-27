"""Tests for CLI commands (click integration tests)."""

from unittest.mock import patch

from click.testing import CliRunner

from openshell_saw.cli import main


@patch("openshell_saw.config.repo_root", return_value=None)
class TestHelp:
    def test_main_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Secure Agent Workspace" in result.output
        assert "sandbox" in result.output
        assert "login" in result.output

    def test_sandbox_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["sandbox", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "list" in result.output
        assert "delete" in result.output

    def test_build_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["build", "--help"])
        assert result.exit_code == 0
        assert "gateway-image" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxList:
    def test_empty_list(self, _):
        with patch("openshell_saw.helm.list_sandboxes", return_value=[]):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            assert "No sandboxes found" in result.output

    def test_with_sandboxes(self, _):
        sandboxes = [
            {
                "name": "test-sb",
                "status": "deployed",
                "vm_status": "Running",
                "updated": "2026-07-27 10:00:00",
            }
        ]
        with patch("openshell_saw.helm.list_sandboxes", return_value=sandboxes):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            assert "test-sb" in result.output
            assert "Running" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxUrl:
    def test_shows_urls(self, _):
        with patch("openshell_saw.kube.get_route_url") as mock_route:
            mock_route.side_effect = lambda name, ns: (
                "https://gw.example.com" if "gateway" in name
                else "https://dash.example.com"
            )
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "url", "my-sb"])
            assert result.exit_code == 0
            assert "https://gw.example.com" in result.output
            assert "https://dash.example.com" in result.output

    def test_not_found(self, _):
        with patch("openshell_saw.kube.get_route_url", return_value=None):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "url", "my-sb"])
            assert result.exit_code == 0
            assert "route not found" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxCreate:
    def test_missing_provider(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["sandbox", "create", "test"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def _create(self, *extra, claims=None, issuer=None):
        calls = {}
        with (
            patch("openshell_saw.oidc.auto_detect_issuer", return_value=issuer),
            patch("openshell_saw.oidc.token_claims", return_value=claims or {}),
            patch("openshell_saw.config.ssh_pubkey", return_value="ssh-ed25519 AAAA"),
            patch("openshell_saw.config.chart_path", return_value="/charts/openshell-saw"),
            patch("openshell_saw.kube.ensure_namespace") as ns,
            patch("openshell_saw.kube.label_saw_namespace") as label,
            patch("openshell_saw.kube.apply_secret") as secret,
            patch("openshell_saw.helm.install_chart") as install,
            patch("openshell_saw.kube.get_route_url", return_value=None),
        ):
            result = CliRunner().invoke(main, [*extra, "sandbox", "create", "test",
                                               "--provider", "build", "--model", "m1",
                                               "--api-key", "key123"])
            calls.update(ns=ns, label=label, secret=secret, install=install)
        return result, calls

    def test_create_uses_its_own_namespace(self, _):
        result, calls = self._create()
        assert result.exit_code == 0, result.output
        calls["ns"].assert_called_once_with("saw-test")
        calls["label"].assert_called_once_with("saw-test", None)
        kwargs = calls["install"].call_args.kwargs
        assert kwargs["namespace"] == "saw-test"
        assert kwargs["chart_path"] == "/charts/openshell-saw"
        assert kwargs["sets"]["governance.namespace"] == "openshell-agents"
        assert kwargs["sets"]["source.dataSourceNamespace"] == "openshell-agents"
        assert kwargs["sets"]["oidc.keycloakNamespace"] == "keycloak"

    def test_api_key_goes_to_a_secret_not_helm_values(self, _):
        result, calls = self._create()
        calls["secret"].assert_called_once_with(
            "inference", "saw-test", {"api_key": "key123", "provider": "build", "model": "m1"})
        kwargs = calls["install"].call_args.kwargs
        assert "key123" not in repr(kwargs)

    def test_owner_subject_from_token_and_no_token_in_values(self, _):
        claims = {"sub": "f00d-subject", "preferred_username": "alice"}
        result, calls = self._create(claims=claims, issuer="https://kc/realms/openshell")
        assert result.exit_code == 0, result.output
        kwargs = calls["install"].call_args.kwargs
        assert kwargs["set_strings"] == {"accessControl.ownerSubject": "f00d-subject"}
        assert kwargs["sets"]["accessControl.owner"] == "alice"
        assert kwargs["sets"]["oidc.issuerUrl"] == "https://kc/realms/openshell"
        assert not any("token" in k for k in {**kwargs["sets"], **kwargs["set_strings"]})
        calls["label"].assert_called_once_with("saw-test", "alice")

    def test_explicit_namespace_is_honoured(self, _):
        result, calls = self._create("-n", "team-a")
        assert result.exit_code == 0, result.output
        assert calls["install"].call_args.kwargs["namespace"] == "team-a"


@patch("openshell_saw.config.repo_root", return_value=None)
class TestNamespaceOverride:
    def test_namespace_flag(self, _):
        with patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list:
            runner = CliRunner()
            result = runner.invoke(main, ["-n", "custom-ns", "sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with("custom-ns")

    def test_default_lists_every_saw_namespace(self, _):
        with patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list:
            result = CliRunner().invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with(None)

    def test_commands_target_the_saw_namespace(self, _):
        with patch("openshell_saw.kube.get_route_url", return_value=None) as mock_url:
            result = CliRunner().invoke(main, ["sandbox", "url", "alice-saw"])
            assert result.exit_code == 0
            assert mock_url.call_args_list[0].args == ("alice-saw-gateway", "saw-alice-saw")
