import json
import os
import subprocess
import sys
import tempfile
import unittest

import compose_checker as cc

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "sample_compose")
TOOL = os.path.join(HERE, "compose_checker.py")


def check(text):
    return cc.check_compose(cc.parse_compose(text.strip("\n").splitlines()))


def rules(text):
    return [f["rule"] for f in check(text)]


def svc(body, name="app"):
    """Wrap service lines (4 spaces deep) in a compose file with a pinned image."""
    return "services:\n  %s:\n    image: example/app:1.0\n    user: '1000'\n    security_opt: ['no-new-privileges:true']\n%s\n" % (name, body)


class ParserTests(unittest.TestCase):
    def test_reads_maps_and_lists(self):
        root = cc.parse_compose("services:\n  a:\n    image: x:1\n    ports:\n      - \"80:80\"\n".splitlines())
        service = root["services"][1]["a"][1]
        self.assertEqual(service["image"][1], "x:1")
        self.assertEqual(service["ports"][1][0][1], "80:80")

    def test_line_numbers(self):
        root = cc.parse_compose("services:\n  a:\n    image: x:1\n".splitlines())
        self.assertEqual(root["services"][1]["a"][1]["image"][0], 3)

    def test_list_at_same_indent_as_key(self):
        root = cc.parse_compose("services:\n  a:\n    ports:\n    - \"80:80\"\n".splitlines())
        self.assertEqual(root["services"][1]["a"][1]["ports"][1][0][1], "80:80")

    def test_comments_ignored(self):
        root = cc.parse_compose("# top\nservices:  # here\n  a:\n    image: x:1  # pin\n".splitlines())
        self.assertEqual(root["services"][1]["a"][1]["image"][1], "x:1")

    def test_hash_inside_quotes_kept(self):
        self.assertEqual(cc.strip_comment('a: "x # y"'), 'a: "x # y"')

    def test_inline_list(self):
        root = cc.parse_compose("services:\n  a:\n    cap_add: [SYS_ADMIN, NET_RAW]\n".splitlines())
        items = root["services"][1]["a"][1]["cap_add"][1]
        self.assertEqual([v for _, v in items], ["SYS_ADMIN", "NET_RAW"])

    def test_list_of_maps(self):
        text = "services:\n  a:\n    volumes:\n      - type: bind\n        source: /etc\n        target: /x\n"
        root = cc.parse_compose(text.splitlines())
        item = root["services"][1]["a"][1]["volumes"][1][0][1]
        self.assertEqual(item["source"][1], "/etc")

    def test_block_scalar_skipped(self):
        text = "services:\n  a:\n    command: |\n      echo hi\n      echo there\n    image: x:1\n"
        root = cc.parse_compose(text.splitlines())
        self.assertEqual(root["services"][1]["a"][1]["image"][1], "x:1")

    def test_quoted_values_unquoted(self):
        self.assertEqual(cc.unquote("'abc'"), "abc")
        self.assertEqual(cc.unquote('"abc"'), "abc")

    def test_port_like_value_is_not_a_map(self):
        root = cc.parse_compose("services:\n  a:\n    ports:\n      - 80:80\n".splitlines())
        self.assertEqual(root["services"][1]["a"][1]["ports"][1][0][1], "80:80")

    def test_tab_indent_is_an_error(self):
        with self.assertRaises(cc.ComposeError):
            cc.parse_compose("services:\n\ta: 1\n".splitlines())

    def test_anchor_is_an_error(self):
        with self.assertRaises(cc.ComposeError):
            cc.parse_compose("x: &a\n  b: 1\n".splitlines())

    def test_merge_key_is_an_error(self):
        with self.assertRaises(cc.ComposeError):
            cc.parse_compose("services:\n  a:\n    <<: *x\n".splitlines())

    def test_empty_file_gives_empty(self):
        self.assertEqual(cc.parse_compose([]), {})
        self.assertEqual(cc.parse_compose(["# only a comment"]), {})

    def test_no_services_is_an_error(self):
        with self.assertRaises(cc.ComposeError):
            cc.check_compose(cc.parse_compose(["version: '3'"]))


class RuleTests(unittest.TestCase):
    def test_clean_service_has_no_findings(self):
        self.assertEqual(rules(svc("")), [])

    def test_privileged(self):
        self.assertIn("privileged", rules(svc("    privileged: true")))

    def test_privileged_false_ok(self):
        self.assertNotIn("privileged", rules(svc("    privileged: false")))

    def test_privileged_yes_counts(self):
        self.assertIn("privileged", rules(svc("    privileged: yes")))

    def test_host_network(self):
        self.assertIn("host-network", rules(svc("    network_mode: host")))

    def test_bridge_network_ok(self):
        self.assertNotIn("host-network", rules(svc("    network_mode: bridge")))

    def test_host_pid_and_ipc(self):
        found = rules(svc("    pid: host\n    ipc: host"))
        self.assertIn("host-pid", found)
        self.assertIn("host-ipc", found)

    def test_dangerous_capability(self):
        self.assertIn("dangerous-capability", rules(svc("    cap_add:\n      - SYS_ADMIN")))

    def test_capability_all_and_cap_prefix(self):
        self.assertIn("dangerous-capability", rules(svc("    cap_add: [ALL]")))
        self.assertIn("dangerous-capability", rules(svc("    cap_add: [CAP_SYS_MODULE]")))

    def test_harmless_capability_ok(self):
        self.assertNotIn("dangerous-capability", rules(svc("    cap_add:\n      - NET_BIND_SERVICE")))

    def test_docker_socket(self):
        body = "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock"
        self.assertIn("docker-socket", rules(svc(body)))

    def test_docker_socket_read_only_still_flagged(self):
        body = "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro"
        self.assertIn("docker-socket", rules(svc(body)))

    def test_sensitive_mount(self):
        self.assertIn("sensitive-host-mount", rules(svc("    volumes:\n      - /etc:/host-etc")))
        self.assertIn("sensitive-host-mount", rules(svc("    volumes:\n      - /:/host")))
        self.assertIn("sensitive-host-mount", rules(svc("    volumes:\n      - /root/.ssh:/keys")))

    def test_localtime_mount_ok(self):
        body = "    volumes:\n      - /etc/localtime:/etc/localtime:ro"
        self.assertNotIn("sensitive-host-mount", rules(svc(body)))

    def test_named_and_relative_volumes_ok(self):
        body = "    volumes:\n      - data:/var/lib/x\n      - ./config:/config"
        self.assertEqual(rules(svc(body)), [])

    def test_long_syntax_mount(self):
        body = "    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /s"
        self.assertIn("docker-socket", rules(svc(body)))

    def test_hardcoded_secret_in_map(self):
        body = "    environment:\n      DB_PASSWORD: hunter2"
        self.assertIn("hardcoded-secret", rules(svc(body)))

    def test_hardcoded_secret_in_list(self):
        body = "    environment:\n      - API_TOKEN=abc123"
        self.assertIn("hardcoded-secret", rules(svc(body)))

    def test_variable_reference_ok(self):
        body = "    environment:\n      - API_TOKEN=${API_TOKEN}\n      - DB_PASSWORD=${DB_PASSWORD:-x}"
        self.assertNotIn("hardcoded-secret", rules(svc(body)))

    def test_file_style_secret_ok(self):
        body = "    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/pw"
        self.assertNotIn("hardcoded-secret", rules(svc(body)))

    def test_passthrough_variable_ok(self):
        body = "    environment:\n      - API_TOKEN"
        self.assertNotIn("hardcoded-secret", rules(svc(body)))

    def test_non_secret_name_ok(self):
        body = "    environment:\n      - LOG_LEVEL=debug"
        self.assertEqual(rules(svc(body)), [])

    def test_secret_never_printed(self):
        body = "    environment:\n      DB_PASSWORD: hunter2"
        for f in check(svc(body)):
            self.assertNotIn("hunter2", json.dumps(f))

    def test_db_port_public(self):
        self.assertIn("db-port-public", rules(svc('    ports:\n      - "3306:3306"')))
        self.assertIn("db-port-public", rules(svc('    ports:\n      - "0.0.0.0:6379:6379"')))

    def test_db_port_local_ok(self):
        self.assertNotIn("db-port-public", rules(svc('    ports:\n      - "127.0.0.1:5432:5432"')))

    def test_db_port_with_protocol(self):
        self.assertIn("db-port-public", rules(svc('    ports:\n      - "5432:5432/tcp"')))

    def test_container_only_port_ok(self):
        self.assertNotIn("db-port-public", rules(svc('    ports:\n      - "5432"')))

    def test_web_port_ok(self):
        self.assertEqual(rules(svc('    ports:\n      - "8080:80"')), [])

    def test_db_port_long_syntax(self):
        body = "    ports:\n      - target: 3306\n        published: 3306"
        self.assertIn("db-port-public", rules(svc(body)))

    def test_unconfined_profile(self):
        text = ("services:\n  a:\n    image: x:1\n    user: '1'\n"
                "    security_opt:\n      - seccomp:unconfined\n      - no-new-privileges:true\n")
        self.assertEqual(rules(text), ["unconfined-security-profile"])

    def test_image_latest(self):
        text = "services:\n  a:\n    image: nginx:latest\n    user: '1'\n    security_opt: ['no-new-privileges:true']\n"
        self.assertEqual(rules(text), ["image-latest-tag"])

    def test_image_no_tag(self):
        text = "services:\n  a:\n    image: nginx\n    user: '1'\n    security_opt: ['no-new-privileges:true']\n"
        self.assertEqual(rules(text), ["image-latest-tag"])

    def test_image_registry_port_not_a_tag(self):
        self.assertIsNotNone(cc.image_problem("registry.local:5000/team/app"))
        self.assertIsNone(cc.image_problem("registry.local:5000/team/app:1.2"))

    def test_image_digest_ok(self):
        self.assertIsNone(cc.image_problem("nginx@sha256:" + "a" * 64))
        self.assertIsNone(cc.image_problem("nginx:1.27@sha256:" + "a" * 64))

    def test_image_variable_skipped(self):
        self.assertIsNone(cc.image_problem("${IMAGE}"))

    def test_no_user_flagged(self):
        text = "services:\n  a:\n    image: x:1\n    security_opt: ['no-new-privileges:true']\n"
        self.assertEqual(rules(text), ["no-user"])

    def test_no_new_privileges_flagged(self):
        text = "services:\n  a:\n    image: x:1\n    user: '1'\n"
        self.assertEqual(rules(text), ["no-new-privileges"])

    def test_no_new_privileges_false_flagged(self):
        text = "services:\n  a:\n    image: x:1\n    user: '1'\n    security_opt:\n      - no-new-privileges:false\n"
        self.assertEqual(rules(text), ["no-new-privileges"])

    def test_build_only_service_checked(self):
        text = "services:\n  a:\n    build: .\n"
        self.assertEqual(sorted(rules(text)), ["no-new-privileges", "no-user"])

    def test_finding_line_numbers(self):
        findings = check(svc("    privileged: true"))
        privileged = [f for f in findings if f["rule"] == "privileged"][0]
        self.assertEqual(privileged["line"], 6)

    def test_service_level_line_points_at_service_name(self):
        text = "services:\n  web:\n    image: x:1\n"
        self.assertTrue(all(f["line"] == 2 for f in check(text)))

    def test_findings_sorted_high_first(self):
        found = check(svc("    privileged: true\n    network_mode: host"))
        order = [cc.SEVERITIES[f["severity"]] for f in found]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_each_service_checked(self):
        text = ("services:\n  a:\n    image: x:1\n    privileged: true\n    user: '1'\n    security_opt: ['no-new-privileges:true']\n"
                "  b:\n    image: y:1\n    privileged: true\n    user: '1'\n    security_opt: ['no-new-privileges:true']\n")
        self.assertEqual(rules(text).count("privileged"), 2)


class OutputTests(unittest.TestCase):
    def test_filter(self):
        found = check(svc("    privileged: true\n    ports: ['3306:3306']"))
        self.assertTrue(all(f["severity"] == "high" for f in cc.filter_findings(found, "high")))

    def test_text_format(self):
        out = cc.format_text([("a.yml", check(svc("    privileged: true")))])
        self.assertIn("[HIGH] line 6  privileged", out)
        self.assertIn("Fix:", out)

    def test_text_no_findings(self):
        self.assertIn("No findings.", cc.format_text([("a.yml", [])]))

    def test_json_format(self):
        data = json.loads(cc.format_json([("a.yml", check(svc("    privileged: true")))]))
        self.assertEqual(data[0]["file"], "a.yml")
        self.assertEqual(data[0]["findings"][0]["rule"], "privileged")


def run_tool(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)


class CommandLineTests(unittest.TestCase):
    def sample(self, name):
        return os.path.join(SAMPLES, name)

    def test_risky_exits_1(self):
        self.assertEqual(run_tool(self.sample("01_risky.yml")).returncode, 1)

    def test_hardened_exits_0(self):
        result = run_tool(self.sample("03_hardened.yml"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("No findings.", result.stdout)

    def test_gaps_exit_0_by_default(self):
        self.assertEqual(run_tool(self.sample("02_okay_with_gaps.yml")).returncode, 0)

    def test_fail_on_medium(self):
        self.assertEqual(run_tool(self.sample("02_okay_with_gaps.yml"), "--fail-on", "medium").returncode, 1)

    def test_min_severity_high(self):
        out = run_tool(self.sample("01_risky.yml"), "--min-severity", "high").stdout
        self.assertNotIn("[LOW]", out)
        self.assertNotIn("[MEDIUM]", out)

    def test_json_output_parses(self):
        data = json.loads(run_tool(self.sample("01_risky.yml"), "--format", "json").stdout)
        self.assertEqual(len(data[0]["findings"]), 20)

    def test_missing_file_exits_2(self):
        result = run_tool("nope.yml")
        self.assertEqual(result.returncode, 2)
        self.assertIn("file not found", result.stderr)

    def test_not_compose_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            handle.write("name: tests\non: push\n")
        try:
            result = run_tool(handle.name)
            self.assertEqual(result.returncode, 2)
            self.assertIn("services", result.stderr)
        finally:
            os.unlink(handle.name)

    def test_empty_file_note(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
            handle.write("# nothing here\n")
        try:
            result = run_tool(handle.name)
            self.assertEqual(result.returncode, 0)
            self.assertIn("empty", result.stderr)
        finally:
            os.unlink(handle.name)

    def test_binary_file_exits_2(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".yml", delete=False) as handle:
            handle.write(b"\xff\xfe\x00\x01")
        try:
            self.assertEqual(run_tool(handle.name).returncode, 2)
        finally:
            os.unlink(handle.name)

    def test_several_files(self):
        out = run_tool(self.sample("01_risky.yml"), self.sample("03_hardened.yml")).stdout
        self.assertIn("01_risky.yml", out)
        self.assertIn("03_hardened.yml", out)


class SampleTests(unittest.TestCase):
    def counts(self, name):
        root = cc.parse_compose(cc.load_compose(os.path.join(SAMPLES, name)))
        found = cc.check_compose(root)
        return len(found), sum(1 for f in found if f["severity"] == "high")

    def test_risky(self):
        self.assertEqual(self.counts("01_risky.yml"), (20, 7))

    def test_gaps(self):
        self.assertEqual(self.counts("02_okay_with_gaps.yml"), (3, 0))

    def test_hardened(self):
        self.assertEqual(self.counts("03_hardened.yml"), (0, 0))


if __name__ == "__main__":
    unittest.main()
