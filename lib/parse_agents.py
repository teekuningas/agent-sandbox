#!/usr/bin/env python3
"""Extract sandbox port declarations from a project's AGENTS.md.

The launcher runs this on the host, before `podman run`, against the AGENTS.md
of the workspace it is about to mount.  Declarations live in a fenced block
whose info string is tagged `agent-sandbox`:

    ```toml agent-sandbox
    [ports]
    web = 3000
    api = { container = 8080, host = 18080 }
    db  = { container = 5432, host = 0 }      # 0 = pick a free host port
    ```

Output is one validated mapping per line, in podman's `--publish` syntax:

    BIND:HOST:CONTAINER/PROTO

AGENTS.md is workspace content: on a cloned repo it is attacker-controlled.
So every field is validated to a narrow type here, and the launcher rebuilds
the `-p` flag from the result rather than passing anything through verbatim.
A value like "127.0.0.1 --privileged" cannot survive `ipaddress.ip_address()`.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import re
import socket
import sys
import tomllib

BLOCK_TAG = "agent-sandbox"
MAX_PORTS = 32

FENCE_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DOMAIN_RE = re.compile(r"\A(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")

ENTRY_FIELDS = frozenset({"container", "host", "bind", "protocol"})
PROTOCOLS = frozenset({"tcp", "udp"})


class ConfigError(Exception):
    """A declaration in AGENTS.md is missing, malformed, or out of bounds."""


@dataclasses.dataclass(frozen=True)
class Mapping:
    name: str
    bind: str
    host: int
    container: int
    protocol: str

    def spec(self) -> str:
        """Render as a podman --publish operand.  IPv6 binds need brackets."""
        bind = f"[{self.bind}]" if ":" in self.bind else self.bind
        return f"{bind}:{self.host}:{self.container}/{self.protocol}"


def iter_tagged_blocks(text: str):
    """Yield the body of every fenced block tagged `agent-sandbox`.

    Handles both fence characters and the CommonMark rules that actually
    matter here: a closing fence is at least as long as the opening one, uses
    the same character, and carries no info string.
    """
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        opening = FENCE_RE.match(lines[index])
        index += 1
        if not opening:
            continue
        fence = opening.group("fence")
        info = opening.group("info").strip()
        # A backtick fence's info string may not itself contain a backtick.
        if fence[0] == "`" and "`" in info:
            continue

        body: list[str] = []
        while index < len(lines):
            closing = FENCE_RE.match(lines[index])
            if (
                closing
                and closing.group("fence")[0] == fence[0]
                and len(closing.group("fence")) >= len(fence)
                and not closing.group("info").strip()
            ):
                index += 1
                break
            body.append(lines[index])
            index += 1

        if BLOCK_TAG in info.split():
            yield "\n".join(body)


def _port(name: str, field: str, value: object, *, allow_zero: bool = False) -> int:
    # bool is an int subclass; `web = true` must not read as port 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"ports.{name}.{field}: expected an integer, got {value!r}")
    low = 0 if allow_zero else 1
    if not low <= value <= 65535:
        raise ConfigError(f"ports.{name}.{field}: {value} is outside {low}-65535")
    return value


def _bind(name: str, value: object, allow_any_interface: bool) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"ports.{name}.bind: expected a string, got {value!r}")
    literal = "127.0.0.1" if value == "localhost" else value
    try:
        address = ipaddress.ip_address(literal)
    except ValueError as exc:
        raise ConfigError(
            f"ports.{name}.bind: {value!r} is not an IP address literal"
        ) from exc
    if not address.is_loopback and not allow_any_interface:
        raise ConfigError(
            f"ports.{name}.bind: {address} is not a loopback address; "
            f"pass --ports-any-interface to publish there"
        )
    return str(address)


def _protocol(name: str, value: object) -> str:
    if not isinstance(value, str) or value.lower() not in PROTOCOLS:
        raise ConfigError(
            f"ports.{name}.protocol: expected 'tcp' or 'udp', got {value!r}"
        )
    return value.lower()


def parse_entry(name: str, value: object, allow_any_interface: bool) -> Mapping:
    if not NAME_RE.match(name):
        raise ConfigError(f"ports.{name!r}: name must match {NAME_RE.pattern}")

    if isinstance(value, dict):
        unknown = set(value) - ENTRY_FIELDS
        if unknown:
            raise ConfigError(
                f"ports.{name}: unknown field(s) {', '.join(sorted(unknown))}"
            )
        if "container" not in value:
            raise ConfigError(f"ports.{name}: missing required field 'container'")
        container = _port(name, "container", value["container"])
        host = _port(name, "host", value.get("host", container), allow_zero=True)
        bind = _bind(name, value.get("bind", "127.0.0.1"), allow_any_interface)
        protocol = _protocol(name, value.get("protocol", "tcp"))
    else:
        container = _port(name, "container", value)
        host, bind, protocol = container, "127.0.0.1", "tcp"

    return Mapping(
        name=name, bind=bind, host=host, container=container, protocol=protocol
    )


PROXY_DOMAIN_FIELDS = ("allow_domains", "deny_domains")
PROXY_IP_FIELDS = ("allow_ips", "deny_ips")
PROXY_PORT_FIELDS = ("allow_ports",)
PROXY_FIELDS = frozenset(
    PROXY_DOMAIN_FIELDS + PROXY_IP_FIELDS + PROXY_PORT_FIELDS + ("default",)
)
PROXY_DEFAULTS = ("allow", "deny")
PORT_RANGE_RE = re.compile(r"\A(\d{1,5})(?:-(\d{1,5}))?\Z")


def _proxy_list(field: str, value: object, validate) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(f"[proxy].{field} must be a list of strings")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"[proxy].{field} elements must be strings")
        validate(field, item)
        out.append(item)
    return out


def _proxy_domain(field: str, value: str) -> None:
    if not DOMAIN_RE.match(value):
        raise ConfigError(
            f"[proxy].{field}: {value!r} is not a valid domain name "
            f"(must match {DOMAIN_RE.pattern})"
        )


def _proxy_ip(field: str, value: str) -> None:
    try:
        ipaddress.ip_network(value)
    except ValueError as exc:
        raise ConfigError(
            f"[proxy].{field}: {value!r} is not a valid IP address or network: {exc}"
        ) from exc


def _proxy_port(field: str, value: str) -> None:
    match = PORT_RANGE_RE.match(value)
    if not match:
        raise ConfigError(
            f"[proxy].{field}: {value!r} is not a port or port range "
            f"(e.g. '443', '8000-8100')"
        )
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ConfigError(
            f"[proxy].{field}: {value!r} is out of range (1-65535) or start > end"
        )


def parse_proxy(text: str) -> dict[str, list[str]]:
    """Collect every [proxy] block into one policy mapping.

    Unknown keys are rejected rather than ignored: a typo like allow_domians
    would otherwise leave the allow list empty, which for a firewall means
    allowing everything.
    """
    policy: dict[str, list[str]] = {field: [] for field in PROXY_FIELDS - {"default"}}
    default: list[str] = []

    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        proxy = block.get("proxy")
        if proxy is None:
            continue
        if not isinstance(proxy, dict):
            raise ConfigError("[proxy] must be a table")

        unknown = set(proxy) - PROXY_FIELDS
        if unknown:
            raise ConfigError(
                f"[proxy]: unknown field(s) {', '.join(sorted(unknown))}"
            )

        for field in PROXY_DOMAIN_FIELDS:
            if field in proxy:
                policy[field] += _proxy_list(field, proxy[field], _proxy_domain)
        for field in PROXY_IP_FIELDS:
            if field in proxy:
                policy[field] += _proxy_list(field, proxy[field], _proxy_ip)
        for field in PROXY_PORT_FIELDS:
            if field in proxy:
                policy[field] += _proxy_list(field, proxy[field], _proxy_port)

        if "default" in proxy:
            value = proxy["default"]
            if value not in PROXY_DEFAULTS:
                raise ConfigError(
                    f"[proxy].default: expected 'allow' or 'deny', got {value!r}"
                )
            default = [value]

    policy["default"] = default
    return policy


def format_proxy_policy(policy: dict[str, list[str]], source: str) -> str:
    """Render the policy file the proxy reads.

    One entry per line, so no value ever needs an in-value separator: that is
    what the space-vs-comma handoff bug came from, and a format with two entries
    on one line cannot express it.
    """
    lines = [f"# generated by agent-sandbox-parse-agents from {source}"]
    for field in PROXY_DOMAIN_FIELDS + PROXY_IP_FIELDS + PROXY_PORT_FIELDS:
        for value in policy.get(field, ()):
            lines.append(f"{field} {value}")
    for value in policy.get("default", ()):
        lines.append(f"default {value}")
    return "\n".join(lines) + "\n"


# Thin wrappers: the field-specific names are what lib/test_parse_agents.py
# imports, and they read better at a call site than parse_proxy()["..."].
def parse_proxy_allow_ips(text: str) -> list[str]:
    return parse_proxy(text)["allow_ips"]


def parse_proxy_deny_ips(text: str) -> list[str]:
    return parse_proxy(text)["deny_ips"]


def parse_proxy_domains(text: str) -> list[str]:
    return parse_proxy(text)["allow_domains"]


def parse_proxy_deny_domains(text: str) -> list[str]:
    return parse_proxy(text)["deny_domains"]


def parse_proxy_allow_ports(text: str) -> list[str]:
    return parse_proxy(text)["allow_ports"]


def parse_ports(
    text: str, *, allow_any_interface: bool = False, max_ports: int = MAX_PORTS
) -> list[Mapping]:
    mappings: dict[str, Mapping] = {}
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        ports = block.get("ports")
        if ports is None:
            continue
        if not isinstance(ports, dict):
            raise ConfigError("[ports] must be a table")

        for name, value in ports.items():
            if name in mappings:
                raise ConfigError(f"ports.{name}: declared more than once")
            mappings[name] = parse_entry(name, value, allow_any_interface)

    if len(mappings) > max_ports:
        raise ConfigError(
            f"{len(mappings)} port mappings declared, limit is {max_ports}"
        )
    return list(mappings.values())


def parse_mounts(text: str) -> list[str]:
    specs: list[str] = []
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        mounts = block.get("mounts")
        if mounts is None:
            continue
        if not isinstance(mounts, dict):
            raise ConfigError("[mounts] must be a table")

        for src, value in mounts.items():
            if isinstance(value, str):
                dest = value
                opts = ""
            elif isinstance(value, dict):
                dest = value.get("destination")
                if dest is None:
                    raise ConfigError(f"mounts.{src}: missing required field 'destination'")
                if not isinstance(dest, str):
                    raise ConfigError(f"mounts.{src}.destination: expected a string")
                
                opts = value.get("options", "")
                if not isinstance(opts, str):
                    if isinstance(opts, list):
                        for o in opts:
                            if not isinstance(o, str):
                                raise ConfigError(f"mounts.{src}.options: expected a string or list of strings")
                        opts = ",".join(opts)
                    else:
                        raise ConfigError(f"mounts.{src}.options: expected a string or list of strings")
                
                unknown = set(value) - {"destination", "options"}
                if unknown:
                    raise ConfigError(f"mounts.{src}: unknown field(s) {', '.join(sorted(unknown))}")
            else:
                raise ConfigError(f"mounts.{src}: expected a string or table")
            
            spec = f"{src}:{dest}"
            if opts:
                spec += f":{opts}"
            specs.append(spec)
            
    return specs


def allocate(mapping: Mapping) -> Mapping:
    """Resolve `host = 0` to a concrete free port.

    Binding and immediately closing races against anything else grabbing the
    port before podman does; the window is small and the failure is a loud
    "address already in use" from podman rather than a silent misroute.
    """
    if mapping.host != 0:
        return mapping
    family = socket.AF_INET6 if ":" in mapping.bind else socket.AF_INET
    kind = socket.SOCK_DGRAM if mapping.protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as sock:
        sock.bind((mapping.bind, 0))
        return dataclasses.replace(mapping, host=sock.getsockname()[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox-parse-agents",
        description="Emit podman --publish operands declared in an AGENTS.md.",
    )
    parser.add_argument("path", help="path to AGENTS.md")
    parser.add_argument(
        "--ports-any-interface",
        action="store_true",
        help="permit binds outside loopback",
    )
    parser.add_argument(
        "--max", type=int, default=MAX_PORTS, help=f"cap on mappings (default {MAX_PORTS})"
    )
    parser.add_argument(
        "--no-allocate",
        action="store_true",
        help="leave `host = 0` unresolved instead of picking a free port",
    )
    parser.add_argument(
        "--proxy-policy",
        action="store_true",
        help="emit the [proxy] policy file the proxy reads, instead of port mappings",
    )
    parser.add_argument(
        "--mounts",
        action="store_true",
        help="emit -v volume specs instead of port mappings",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return 0  # No AGENTS.md is the common case, not an error.
    except OSError as exc:
        print(f"agent-sandbox: cannot read {args.path}: {exc}", file=sys.stderr)
        return 1

    if args.proxy_policy:
        try:
            policy = parse_proxy(text)
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        sys.stdout.write(format_proxy_policy(policy, args.path))
        return 0

    if args.mounts:
        try:
            mounts = parse_mounts(text)
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        for spec in mounts:
            print(spec)
        return 0

    try:
        mappings = parse_ports(
            text, allow_any_interface=args.ports_any_interface, max_ports=args.max
        )
        if not args.no_allocate:
            mappings = [allocate(mapping) for mapping in mappings]
    except ConfigError as exc:
        print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"agent-sandbox: cannot allocate a host port: {exc}", file=sys.stderr)
        return 1

    for mapping in mappings:
        print(mapping.spec())
    return 0


if __name__ == "__main__":
    sys.exit(main())
