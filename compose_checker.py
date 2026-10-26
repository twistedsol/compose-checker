#!/usr/bin/env python3
"""Docker Compose checker.

Reads docker-compose files (.yml / .yaml) and flags risky settings, with line
numbers. It only reads the file. It never starts a container or contacts Docker.

It uses a small built-in reader for the YAML that Compose files normally use
(maps, lists, quotes, comments). It does not support anchors, merge keys (<<)
or multi-document files, so it says so instead of guessing.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import re
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

TRUE_VALUES = {"true", "yes", "on", "1"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH"}
DB_PORTS = {
    "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
    "9200": "Elasticsearch", "11211": "Memcached", "5984": "CouchDB", "1433": "SQL Server",
}
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/var/lib/docker")
SAFE_MOUNTS = ("/etc/localtime", "/etc/timezone")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.I)
KEY_VALUE = re.compile(r"^(\"[^\"]*\"|'[^']*'|[^\s:#\"'][^:#]*?)\s*:(?:\s+(.*))?$")
BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*$")


class ComposeError(Exception):
    """Raised when a compose file cannot be used."""


# ---------- reading the file ----------

def load_compose(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise ComposeError("file not found: %s" % path)
    except UnicodeDecodeError:
        raise ComposeError("not a text file: %s" % path)
    except OSError as exc:
        raise ComposeError("cannot read %s: %s" % (path, exc.strerror))


def strip_comment(text):
    """Remove a trailing # comment that is not inside quotes."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def tokenize(lines):
    """Return [indent, text, line_number] for each meaningful line.
    Lines inside block scalars (| or >) are dropped but remembered as the value."""
    tokens = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ComposeError("line %d uses a tab for indentation; YAML needs spaces" % (i + 1))
        text = strip_comment(raw)
        if not text.strip() or text.strip() in ("---", "..."):
            i += 1
            continue
        indent = len(text) - len(text.lstrip(" "))
        body = text.strip()
        tokens.append([indent, body, i + 1])
        value = body.split(":", 1)[1].strip() if ":" in body else ""
        if body.startswith("- "):
            value = body[2:].split(":", 1)[1].strip() if ":" in body[2:] else ""
        if BLOCK_SCALAR.match(value):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip(" ")) > indent):
                j += 1
            tokens[-1][1] = body[: len(body) - len(value)] + "<block>"
            i = j
            continue
        i += 1
    return tokens


def parse_inline_list(text, line):
    inner = text.strip()[1:-1]
    return [(line, unquote(p)) for p in inner.split(",") if p.strip()]


def scalar_or_inline(text, line):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return parse_inline_list(text, line)
    if text.startswith("{"):
        return text
    return unquote(text)


def parse_block(tokens, pos, indent):
    """Parse a map or a list starting at tokens[pos]. Returns (value, new_pos).
    A map is {key: (line, value)}; a list is [(line, value)]."""
    if tokens[pos][1] == "-" or tokens[pos][1].startswith("- "):
        return parse_list(tokens, pos, indent)
    return parse_map(tokens, pos, indent)


def parse_map(tokens, pos, indent):
    result = {}
    while pos < len(tokens) and tokens[pos][0] == indent:
        _, body, line = tokens[pos]
        if body == "-" or body.startswith("- "):
            break
        match = KEY_VALUE.match(body)
        if not match:
            raise ComposeError("line %d is not understood: %s" % (line, body))
        key = unquote(match.group(1))
        value = (match.group(2) or "").strip()
        pos += 1
        if value.startswith("&") or value.startswith("*") or key == "<<":
            raise ComposeError("line %d uses YAML anchors or merge keys, which this tool does not support" % line)
        if value == "<block>":
            result[key] = (line, "<block>")
        elif value:
            result[key] = (line, scalar_or_inline(value, line))
        elif pos < len(tokens) and (
            tokens[pos][0] > indent
            or (tokens[pos][0] == indent and (tokens[pos][1] == "-" or tokens[pos][1].startswith("- ")))
        ):
            child, pos = parse_block(tokens, pos, tokens[pos][0])
            result[key] = (line, child)
        else:
            result[key] = (line, None)
    return result, pos


def parse_list(tokens, pos, indent):
    result = []
    while pos < len(tokens) and tokens[pos][0] == indent and (tokens[pos][1] == "-" or tokens[pos][1].startswith("- ")):
        _, body, line = tokens[pos]
        content = body[1:].lstrip()
        if not content:
            pos += 1
            if pos < len(tokens) and tokens[pos][0] > indent:
                child, pos = parse_block(tokens, pos, tokens[pos][0])
                result.append((line, child))
            else:
                result.append((line, None))
        elif KEY_VALUE.match(content) and content[0] not in "\"'[{" and not re.match(r"^[^\s:]+:[^\s]", content):
            offset = len(body) - len(content)
            tokens[pos] = [indent + offset, content, line]
            child, pos = parse_map(tokens, pos, indent + offset)
            result.append((line, child))
        else:
            result.append((line, scalar_or_inline(content, line)))
            pos += 1
    return result, pos


def parse_compose(lines):
    tokens = tokenize(lines)
    if not tokens:
        return {}
    root, pos = parse_block(tokens, 0, tokens[0][0])
    if pos < len(tokens):
        raise ComposeError("line %d could not be read (check the indentation)" % tokens[pos][2])
    if not isinstance(root, dict):
        raise ComposeError("this does not look like a compose file (no top-level keys)")
    return root


# ---------- the rules ----------

def _finding(rule, severity, line, message, fix):
    return {"rule": rule, "severity": severity, "line": line, "message": message, "fix": fix}


def get(service, key):
    """Return (line, value) for a key of a service map, or (None, None)."""
    entry = service.get(key)
    return entry if entry else (None, None)


def is_true(value):
    return isinstance(value, str) and value.strip().lower() in TRUE_VALUES


def list_items(value):
    """Items of a list as (line, text) pairs, skipping anything that is not a plain string."""
    if not isinstance(value, list):
        return []
    return [(ln, v) for ln, v in value if isinstance(v, str)]


def image_problem(image):
    if "${" in image or "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "has no tag (that means 'latest')"
    tag = last.split(":", 1)[1]
    if tag.lower() == "latest":
        return "uses the 'latest' tag"
    return None


def check_service(name, service, findings):
    where = "Service '%s'" % name

    line, value = get(service, "privileged")
    if is_true(value):
        findings.append(_finding(
            "privileged", "high", line,
            "%s runs privileged, which gives it almost full access to the host." % where,
            "Remove privileged: true. Add only the specific capability it needs."))

    line, value = get(service, "network_mode")
    if isinstance(value, str) and value.strip().lower() == "host":
        findings.append(_finding(
            "host-network", "high", line,
            "%s shares the host's network, so it skips Docker's network isolation." % where,
            "Use a normal network and publish only the ports you need."))

    for key in ("pid", "ipc"):
        line, value = get(service, key)
        if isinstance(value, str) and value.strip().lower() == "host":
            findings.append(_finding(
                "host-%s" % key, "high", line,
                "%s shares the host's %s namespace." % (where, key.upper()),
                "Remove %s: host." % key))

    line, value = get(service, "cap_add")
    for ln, cap in list_items(value):
        if cap.upper().replace("CAP_", "") in DANGEROUS_CAPS:
            findings.append(_finding(
                "dangerous-capability", "high", ln,
                "%s adds the powerful capability %s." % (where, cap),
                "Drop it. If something needs a privilege, add the narrowest capability."))

    line, value = get(service, "volumes")
    for ln, item in volume_sources(value):
        path = item.rstrip("/") or "/"
        if "docker.sock" in path:
            findings.append(_finding(
                "docker-socket", "high", ln,
                "%s mounts the Docker socket, which lets it control every container on the host." % where,
                "Remove the mount, or use a socket proxy that allows only the calls needed."))
        elif path not in SAFE_MOUNTS and (
                path in SENSITIVE_MOUNTS
                or any(path.startswith(p + "/") for p in SENSITIVE_MOUNTS if p != "/")):
            findings.append(_finding(
                "sensitive-host-mount", "high", ln,
                "%s mounts the host path %s." % (where, path),
                "Mount only the one folder it needs, read-only if possible."))

    line, value = get(service, "environment")
    for ln, env_name, env_value in environment_items(value):
        if (SECRET_NAME.search(env_name) and not env_name.upper().endswith("_FILE")
                and env_value and not env_value.startswith("${") and not env_value.startswith("$$")):
            findings.append(_finding(
                "hardcoded-secret", "high", ln,
                "%s has a value for %s written in the file." % (where, env_name),
                "Use ${%s} with an .env file kept out of git, or Docker secrets." % env_name))

    line, value = get(service, "ports")
    for ln, text in port_items(value):
        problem = exposed_db_port(text)
        if problem:
            findings.append(_finding(
                "db-port-public", "medium", ln,
                "%s publishes the %s port to every network interface." % (where, problem),
                "Bind it to 127.0.0.1 (for example 127.0.0.1:%s) or do not publish it." % text.split(":")[-1]))

    line, value = get(service, "security_opt")
    options = [(ln, v) for ln, v in list_items(value)]
    for ln, option in options:
        if "unconfined" in option.lower():
            findings.append(_finding(
                "unconfined-security-profile", "medium", ln,
                "%s turns off a built-in security profile (%s)." % (where, option),
                "Remove it and use the default profile."))

    image_line, image = get(service, "image")
    if isinstance(image, str):
        problem = image_problem(image)
        if problem:
            findings.append(_finding(
                "image-latest-tag", "medium", image_line,
                "%s image '%s' %s and can change without warning." % (where, image, problem),
                "Pin a version tag, or better a digest (@sha256:...)."))

    if "image" in service or "build" in service:
        service_line = service_line_of(service)
        if "user" not in service:
            findings.append(_finding(
                "no-user", "low", service_line,
                "%s does not set a user, so it may run as root (the image might set one; "
                "this file cannot tell)." % where,
                "Add user: \"1000:1000\" or another non-root user."))
        safe = any(
            "no-new-privileges" in o.lower() and "false" not in o.lower() for _, o in options)
        if not safe:
            findings.append(_finding(
                "no-new-privileges", "low", service_line,
                "%s does not set no-new-privileges, so a process could gain extra rights." % where,
                "Add security_opt: [\"no-new-privileges:true\"]."))


def service_line_of(service):
    """The first line number used inside a service map (one line above it is the name)."""
    lines = [entry[0] for entry in service.values() if entry]
    return (min(lines) - 1) if lines else 1


def volume_sources(value):
    """Yield (line, host_path) for volume entries that point at a host path."""
    found = []
    if not isinstance(value, list):
        return found
    for ln, item in value:
        if isinstance(item, str):
            source = item.split(":", 1)[0]
            if source.startswith("/"):
                found.append((ln, source))
        elif isinstance(item, dict):
            _, source = get(item, "source")
            if isinstance(source, str) and source.startswith("/"):
                found.append((ln, source))
    return found


def environment_items(value):
    """Yield (line, name, value) from either style of environment block."""
    found = []
    if isinstance(value, dict):
        for env_name, entry in value.items():
            ln, env_value = entry if entry else (0, None)
            found.append((ln, env_name, env_value if isinstance(env_value, str) else ""))
    elif isinstance(value, list):
        for ln, item in value:
            if isinstance(item, str) and "=" in item:
                env_name, env_value = item.split("=", 1)
                found.append((ln, env_name.strip(), env_value.strip()))
    return found


def port_items(value):
    """Yield (line, 'text') for each published port written in short form or long form."""
    found = []
    if not isinstance(value, list):
        return found
    for ln, item in value:
        if isinstance(item, str):
            found.append((ln, item))
        elif isinstance(item, dict):
            _, published = get(item, "published")
            _, target = get(item, "target")
            _, host_ip = get(item, "host_ip")
            if published and target:
                text = "%s:%s" % (published, target)
                if host_ip:
                    text = "%s:%s" % (host_ip, text)
                found.append((ln, text))
    return found


def exposed_db_port(text):
    """Return the database name if this port mapping publishes a database port on all interfaces."""
    clean = text.split("/", 1)[0]
    parts = clean.split(":")
    if len(parts) == 1:
        return None
    if len(parts) >= 3:
        host_ip = ":".join(parts[:-2])
        if host_ip.strip("[]") in {h.strip("[]") for h in LOCAL_HOSTS}:
            return None
    host_port, container_port = parts[-2], parts[-1]
    for port in (container_port, host_port):
        if port in DB_PORTS:
            return "%s (%s)" % (DB_PORTS[port], port)
    return None


def check_compose(root):
    findings = []
    services = root.get("services")
    if not services or not isinstance(services[1], dict):
        raise ComposeError("no 'services:' section found, so this does not look like a compose file")
    for name, entry in services[1].items():
        if entry and isinstance(entry[1], dict):
            check_service(name, entry[1], findings)
    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["line"], f["rule"]))
    return findings


# ---------- output and command line ----------

def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    out = []
    for name, findings in results:
        out.append("%s: %d finding(s)" % (name, len(findings)))
        for f in findings:
            out.append("  [%s] line %d  %s: %s" % (f["severity"].upper(), f["line"], f["rule"], f["message"]))
            out.append("      Fix: %s" % f["fix"])
        if not findings:
            out.append("  No findings.")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def format_json(results):
    return json.dumps([{"file": n, "findings": f} for n, f in results], indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Check docker-compose files for risky settings.")
    parser.add_argument("files", nargs="+", help="compose file(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            lines = load_compose(path)
            root = parse_compose(lines)
            if not root:
                print("note: %s is empty." % path, file=sys.stderr)
                results.append((path, []))
                continue
            findings = check_compose(root)
        except ComposeError as exc:
            print("error: %s: %s" % (path, exc), file=sys.stderr)
            return 2
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity)))
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
