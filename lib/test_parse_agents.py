#!/usr/bin/env python3
"""Unit tests for the AGENTS.md port parser.

Run directly (`python3 lib/test_parse_agents.py`) or via `nix flake check`.
"""

import unittest

from parse_agents import ConfigError, Mapping, parse_ports, parse_proxy_domains


def block(body: str, info: str = "toml agent-sandbox") -> str:
    return f"# Project\n\nSome prose.\n\n```{info}\n{body}\n```\n\nMore prose.\n"


def specs(text: str, **kwargs) -> list[str]:
    return [mapping.spec() for mapping in parse_ports(text, **kwargs)]


class TestDiscovery(unittest.TestCase):
    def test_no_file_content(self):
        self.assertEqual(specs(""), [])

    def test_no_tagged_block(self):
        self.assertEqual(specs("# Title\n\n```toml\n[ports]\nweb = 3000\n```\n"), [])

    def test_tagged_block_without_ports_table(self):
        self.assertEqual(specs(block('[agent]\ndefault = "opencode"')), [])

    def test_bare_tag_without_language(self):
        self.assertEqual(
            specs(block("[ports]\nweb = 3000", info="agent-sandbox")),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_tilde_fence(self):
        text = "~~~toml agent-sandbox\n[ports]\nweb = 3000\n~~~\n"
        self.assertEqual(specs(text), ["127.0.0.1:3000:3000/tcp"])

    def test_untagged_fence_is_not_scanned(self):
        # A ```toml block that merely *mentions* ports must be ignored.
        text = "```toml\n[ports]\nweb = 9999\n```\n" + block("[ports]\nweb = 3000")
        self.assertEqual(specs(text), ["127.0.0.1:3000:3000/tcp"])

    def test_two_tagged_blocks_merge(self):
        text = block("[ports]\nweb = 3000") + block("[ports]\napi = 8080")
        self.assertEqual(
            specs(text), ["127.0.0.1:3000:3000/tcp", "127.0.0.1:8080:8080/tcp"]
        )

    def test_duplicate_name_across_blocks_is_rejected(self):
        text = block("[ports]\nweb = 3000") + block("[ports]\nweb = 4000")
        with self.assertRaisesRegex(ConfigError, "declared more than once"):
            specs(text)

    def test_unclosed_fence_still_parses(self):
        self.assertEqual(
            specs("```toml agent-sandbox\n[ports]\nweb = 3000\n"),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_indented_fence(self):
        self.assertEqual(
            specs("  ```toml agent-sandbox\n  [ports]\n  web = 3000\n  ```\n"),
            ["127.0.0.1:3000:3000/tcp"],
        )


class TestEntryForms(unittest.TestCase):
    def test_bare_integer(self):
        self.assertEqual(specs(block("[ports]\nweb = 3000")), ["127.0.0.1:3000:3000/tcp"])

    def test_table_with_distinct_host(self):
        self.assertEqual(
            specs(block("[ports]\napi = { container = 8080, host = 18080 }")),
            ["127.0.0.1:18080:8080/tcp"],
        )

    def test_table_defaults_host_to_container(self):
        self.assertEqual(
            specs(block("[ports]\napi = { container = 8080 }")),
            ["127.0.0.1:8080:8080/tcp"],
        )

    def test_udp(self):
        self.assertEqual(
            specs(block('[ports]\ndns = { container = 53, protocol = "udp" }')),
            ["127.0.0.1:53:53/udp"],
        )

    def test_ipv6_loopback_is_bracketed(self):
        self.assertEqual(
            specs(block('[ports]\nweb = { container = 3000, bind = "::1" }')),
            ["[::1]:3000:3000/tcp"],
        )

    def test_localhost_normalises(self):
        self.assertEqual(
            specs(block('[ports]\nweb = { container = 3000, bind = "localhost" }')),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_host_zero_is_left_alone_by_the_parser(self):
        # allocate() resolves it; parse_ports must not.
        self.assertEqual(
            specs(block("[ports]\ndb = { container = 5432, host = 0 }")),
            ["127.0.0.1:0:5432/tcp"],
        )


class TestValidation(unittest.TestCase):
    def test_malformed_toml(self):
        with self.assertRaisesRegex(ConfigError, "malformed TOML"):
            specs(block("[ports\nweb = 3000"))

    def test_port_out_of_range(self):
        with self.assertRaisesRegex(ConfigError, "outside 1-65535"):
            specs(block("[ports]\nweb = 70000"))

    def test_zero_container_port_rejected(self):
        with self.assertRaisesRegex(ConfigError, "outside 1-65535"):
            specs(block("[ports]\nweb = 0"))

    def test_string_port_rejected(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block('[ports]\nweb = "3000"'))

    def test_boolean_is_not_a_port(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block("[ports]\nweb = true"))

    def test_unknown_field(self):
        with self.assertRaisesRegex(ConfigError, "unknown field"):
            specs(block("[ports]\nweb = { container = 3000, sudo = 1 }"))

    def test_missing_container_field(self):
        with self.assertRaisesRegex(ConfigError, "missing required field"):
            specs(block("[ports]\nweb = { host = 3000 }"))

    def test_non_loopback_bind_needs_opt_in(self):
        text = block('[ports]\nweb = { container = 3000, bind = "0.0.0.0" }')
        with self.assertRaisesRegex(ConfigError, "not a loopback address"):
            specs(text)
        self.assertEqual(specs(text, allow_any_interface=True), ["0.0.0.0:3000:3000/tcp"])

    def test_bad_protocol(self):
        with self.assertRaisesRegex(ConfigError, "expected 'tcp' or 'udp'"):
            specs(block('[ports]\nweb = { container = 3000, protocol = "sctp" }'))

    def test_ports_must_be_a_table(self):
        with self.assertRaisesRegex(ConfigError, r"\[ports\] must be a table"):
            specs(block("ports = 3000"))

    def test_cap_on_mapping_count(self):
        body = "[ports]\n" + "\n".join(f"p{i} = {4000 + i}" for i in range(33))
        with self.assertRaisesRegex(ConfigError, "limit is 32"):
            specs(block(body))

    def test_name_charset(self):
        with self.assertRaisesRegex(ConfigError, "name must match"):
            specs(block('[ports]\n"we b" = 3000'))


class TestInjection(unittest.TestCase):
    """AGENTS.md is workspace content; nothing in it may become a podman flag."""

    def test_flag_smuggled_through_bind(self):
        with self.assertRaisesRegex(ConfigError, "not an IP address literal"):
            specs(
                block(
                    '[ports]\nweb = { container = 3000, '
                    'bind = "127.0.0.1 --privileged" }'
                )
            )

    def test_flag_smuggled_through_port(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block('[ports]\nweb = "3000 -v /:/host"'))

    def test_flag_smuggled_through_protocol(self):
        with self.assertRaisesRegex(ConfigError, "expected 'tcp' or 'udp'"):
            specs(block('[ports]\nweb = { container = 3000, protocol = "tcp -v /:/h" }'))

    def test_emitted_specs_never_contain_whitespace(self):
        text = block(
            "[ports]\n"
            "web = 3000\n"
            'api = { container = 8080, host = 18080, protocol = "udp" }\n'
            'v6  = { container = 9000, bind = "::1" }\n'
        )
        for spec in specs(text):
            self.assertNotIn(" ", spec)
            self.assertRegex(spec, r"^[0-9a-f.:\[\]]+:\d+:\d+/(tcp|udp)$")


class TestAllocate(unittest.TestCase):
    def test_allocate_resolves_zero(self):
        from parse_agents import allocate

        resolved = allocate(
            Mapping(name="db", bind="127.0.0.1", host=0, container=5432, protocol="tcp")
        )
        self.assertGreater(resolved.host, 0)
        self.assertEqual(resolved.container, 5432)

    def test_allocate_leaves_fixed_ports(self):
        from parse_agents import allocate

        fixed = Mapping(
            name="web", bind="127.0.0.1", host=3000, container=3000, protocol="tcp"
        )
        self.assertIs(allocate(fixed), fixed)


class TestProxyDomains(unittest.TestCase):
    def test_valid_domains(self):
        text = block('[proxy]\nallow_domains = ["github.com", "api.example.org"]')
        self.assertEqual(parse_proxy_domains(text), ["github.com", "api.example.org"])

    def test_wildcard_domains(self):
        text = block('[proxy]\nallow_domains = ["*.github.com", "*.example.org"]')
        self.assertEqual(parse_proxy_domains(text), ["*.github.com", "*.example.org"])

    def test_empty_list(self):
        text = block("[proxy]\nallow_domains = []")
        self.assertEqual(parse_proxy_domains(text), [])

    def test_no_proxy_block(self):
        text = block("[ports]\nweb = 3000")
        self.assertEqual(parse_proxy_domains(text), [])

    def test_newline_injection_rejected(self):
        text = block('[proxy]\nallow_domains = ["github.com\\nevil.com"]')
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_domains(text)

    def test_trailing_newline_rejected(self):
        text = block('[proxy]\nallow_domains = ["github.com\\n"]')
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_domains(text)

    def test_space_injection_rejected(self):
        text = block('[proxy]\nallow_domains = ["github.com --privileged"]')
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_domains(text)

    def test_empty_string_rejected(self):
        text = block('[proxy]\nallow_domains = [""]')
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_domains(text)

    def test_invalid_wildcard_rejected(self):
        text = block('[proxy]\nallow_domains = ["*github.com"]')
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_domains(text)

    def test_non_string_rejected(self):
        text = block("[proxy]\nallow_domains = [42]")
        with self.assertRaisesRegex(ConfigError, "must be strings"):
            parse_proxy_domains(text)


class TestProxyAllowIpsParsing(unittest.TestCase):
    def test_valid_ips(self):
        text = block('[proxy]\nallow_ips = ["10.0.0.0/8", "8.8.8.8"]')
        from parse_agents import parse_proxy_allow_ips
        self.assertEqual(parse_proxy_allow_ips(text), ["10.0.0.0/8", "8.8.8.8"])

    def test_empty_list(self):
        text = block("[proxy]\nallow_ips = []")
        from parse_agents import parse_proxy_allow_ips
        self.assertEqual(parse_proxy_allow_ips(text), [])

    def test_invalid_ip_rejected(self):
        text = block('[proxy]\nallow_ips = ["130.234.0.0/999"]')
        from parse_agents import parse_proxy_allow_ips, ConfigError
        with self.assertRaisesRegex(ConfigError, "not a valid IP address or network"):
            parse_proxy_allow_ips(text)

    def test_non_string_rejected(self):
        text = block("[proxy]\nallow_ips = [42]")
        from parse_agents import parse_proxy_allow_ips, ConfigError
        with self.assertRaisesRegex(ConfigError, "must be strings"):
            parse_proxy_allow_ips(text)


class TestProxyDenyIpsParsing(unittest.TestCase):
    def test_valid_ips(self):
        text = block('[proxy]\ndeny_ips = ["130.234.0.0/16", "1.1.1.1"]')
        from parse_agents import parse_proxy_deny_ips
        self.assertEqual(parse_proxy_deny_ips(text), ["130.234.0.0/16", "1.1.1.1"])

    def test_empty_list(self):
        text = block("[proxy]\ndeny_ips = []")
        from parse_agents import parse_proxy_deny_ips
        self.assertEqual(parse_proxy_deny_ips(text), [])

    def test_invalid_ip_rejected(self):
        text = block('[proxy]\ndeny_ips = ["130.234.0.0/999"]')
        from parse_agents import parse_proxy_deny_ips, ConfigError
        with self.assertRaisesRegex(ConfigError, "not a valid IP address or network"):
            parse_proxy_deny_ips(text)

    def test_non_string_rejected(self):
        text = block("[proxy]\ndeny_ips = [42]")
        from parse_agents import parse_proxy_deny_ips, ConfigError
        with self.assertRaisesRegex(ConfigError, "must be strings"):
            parse_proxy_deny_ips(text)


class TestProxyAllowPortsParsing(unittest.TestCase):
    def test_valid_ports(self):
        text = block('[proxy]\nallow_ports = ["443", "8000-8100"]')
        from parse_agents import parse_proxy_allow_ports
        self.assertEqual(parse_proxy_allow_ports(text), ["443", "8000-8100"])

    def test_empty_list(self):
        text = block("[proxy]\nallow_ports = []")
        from parse_agents import parse_proxy_allow_ports
        self.assertEqual(parse_proxy_allow_ports(text), [])

    def test_invalid_port_rejected(self):
        from parse_agents import parse_proxy_allow_ports, ConfigError
        for bad in ("70000", "abc", "100-50", "0"):
            text = block(f'[proxy]\nallow_ports = ["{bad}"]')
            with self.assertRaisesRegex(ConfigError, "not a port or port range|out of range"):
                parse_proxy_allow_ports(text)

    def test_non_string_rejected(self):
        text = block("[proxy]\nallow_ports = [443]")
        from parse_agents import parse_proxy_allow_ports, ConfigError
        with self.assertRaisesRegex(ConfigError, "must be strings"):
            parse_proxy_allow_ports(text)


class TestProxyDenyDomainsParsing(unittest.TestCase):
    def test_valid_domains(self):
        text = block('[proxy]\ndeny_domains = ["github.com", "api.example.org"]')
        from parse_agents import parse_proxy_deny_domains
        self.assertEqual(parse_proxy_deny_domains(text), ["github.com", "api.example.org"])

    def test_wildcard_domains(self):
        text = block('[proxy]\ndeny_domains = ["*.github.com", "*.example.org"]')
        from parse_agents import parse_proxy_deny_domains
        self.assertEqual(parse_proxy_deny_domains(text), ["*.github.com", "*.example.org"])

    def test_empty_list(self):
        text = block("[proxy]\ndeny_domains = []")
        from parse_agents import parse_proxy_deny_domains
        self.assertEqual(parse_proxy_deny_domains(text), [])

    def test_no_proxy_block(self):
        text = block("[ports]\nweb = 3000")
        from parse_agents import parse_proxy_deny_domains
        self.assertEqual(parse_proxy_deny_domains(text), [])

    def test_invalid_wildcard_rejected(self):
        text = block('[proxy]\ndeny_domains = ["*github.com"]')
        from parse_agents import parse_proxy_deny_domains, ConfigError
        with self.assertRaisesRegex(ConfigError, "not a valid domain name"):
            parse_proxy_deny_domains(text)

    def test_non_string_rejected(self):
        text = block("[proxy]\ndeny_domains = [42]")
        from parse_agents import parse_proxy_deny_domains, ConfigError
        with self.assertRaisesRegex(ConfigError, "must be strings"):
            parse_proxy_deny_domains(text)


class TestProxyPolicyFile(unittest.TestCase):
    """The policy file is the wire format between the host and the proxy.

    Every list here carries two entries on purpose: the bug this format replaced
    was that a second entry was silently dropped, and a one-entry fixture cannot
    tell the two apart.
    """

    def policy(self, body: str) -> str:
        from parse_agents import format_proxy_policy, parse_proxy

        return format_proxy_policy(parse_proxy(block(body)), "AGENTS.md")

    def test_one_entry_per_line(self):
        text = self.policy(
            "[proxy]\n"
            'allow_domains = ["github.com", "*.githubusercontent.com"]\n'
            'deny_domains = ["telemetry.example.com", "ads.example.com"]\n'
            'allow_ips = ["10.0.0.0/8", "192.168.1.0/24"]\n'
            'deny_ips = ["10.1.0.0/24", "8.8.8.8"]\n'
            'allow_ports = ["443", "8000-8100"]\n'
        )
        self.assertEqual(
            text.splitlines()[1:],
            [
                "allow_domains github.com",
                "allow_domains *.githubusercontent.com",
                "deny_domains telemetry.example.com",
                "deny_domains ads.example.com",
                "allow_ips 10.0.0.0/8",
                "allow_ips 192.168.1.0/24",
                "deny_ips 10.1.0.0/24",
                "deny_ips 8.8.8.8",
                "allow_ports 443",
                "allow_ports 8000-8100",
            ],
        )

    def test_first_line_names_the_source(self):
        self.assertTrue(self.policy("[proxy]").startswith("# generated by"))

    def test_no_value_ever_contains_whitespace(self):
        # This is the invariant the proxy enforces on read, so the writer must
        # never be able to produce a violation.
        text = self.policy(
            "[proxy]\n"
            'allow_domains = ["github.com", "*.example.org"]\n'
            'allow_ips = ["10.0.0.0/8", "2001:db8::/32"]\n'
        )
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            self.assertEqual(len(line.split()), 2, line)

    def test_empty_proxy_block_emits_only_the_comment(self):
        self.assertEqual(len(self.policy("[proxy]").splitlines()), 1)

    def test_default_is_carried_through(self):
        self.assertIn("default deny", self.policy('[proxy]\ndefault = "deny"'))

    def test_default_rejects_anything_else(self):
        from parse_agents import ConfigError

        with self.assertRaisesRegex(ConfigError, "expected 'allow' or 'deny'"):
            self.policy('[proxy]\ndefault = "maybe"')

    def test_unknown_field_is_rejected(self):
        # A typo used to leave the allow list empty, which for a firewall means
        # allowing everything.
        from parse_agents import ConfigError

        with self.assertRaisesRegex(ConfigError, "unknown field.*allow_domians"):
            self.policy('[proxy]\nallow_domians = ["github.com"]')

    def test_blocks_accumulate(self):
        from parse_agents import format_proxy_policy, parse_proxy

        text = (
            block('[proxy]\nallow_domains = ["a.example.com"]')
            + block('[proxy]\nallow_domains = ["b.example.com"]')
        )
        rendered = format_proxy_policy(parse_proxy(text), "AGENTS.md")
        self.assertIn("allow_domains a.example.com", rendered)
        self.assertIn("allow_domains b.example.com", rendered)


if __name__ == "__main__":
    unittest.main()

class TestMounts(unittest.TestCase):
    def test_string_value(self):
        from parse_agents import parse_mounts
        text = block('[mounts]\n"data" = "/workspace/data"')
        self.assertEqual(parse_mounts(text), ["data:/workspace/data"])

    def test_dict_value(self):
        from parse_agents import parse_mounts
        text = block('[mounts]\n"config.json" = { destination = "/etc/config", options = ["ro"] }')
        self.assertEqual(parse_mounts(text), ["config.json:/etc/config:ro"])

    def test_dict_value_with_multiple_options(self):
        from parse_agents import parse_mounts
        text = block('[mounts]\n"config.json" = { destination = "/etc/config", options = ["ro", "z"] }')
        self.assertEqual(parse_mounts(text), ["config.json:/etc/config:ro,z"])

    def test_dict_value_with_string_options(self):
        from parse_agents import parse_mounts
        text = block('[mounts]\n"config.json" = { destination = "/etc/config", options = "ro,z" }')
        self.assertEqual(parse_mounts(text), ["config.json:/etc/config:ro,z"])

    def test_missing_destination(self):
        from parse_agents import parse_mounts, ConfigError
        text = block('[mounts]\n"data" = { options = ["ro"] }')
        with self.assertRaisesRegex(ConfigError, "missing required field 'destination'"):
            parse_mounts(text)

    def test_unknown_field(self):
        from parse_agents import parse_mounts, ConfigError
        text = block('[mounts]\n"data" = { destination = "/data", source = "data" }')
        with self.assertRaisesRegex(ConfigError, "unknown field"):
            parse_mounts(text)

    def test_not_a_table(self):
        from parse_agents import parse_mounts, ConfigError
        text = block('mounts = 3')
        with self.assertRaisesRegex(ConfigError, r"\[mounts\] must be a table"):
            parse_mounts(text)
