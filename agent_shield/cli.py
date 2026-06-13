import argparse
import sys
import os
import json
from agent_shield.config import find_project_root, parse_simple_yaml

def serialize_simple_yaml(data: dict) -> str:
    """Serializes a simple rules dictionary into YAML format."""
    lines = []
    lines.append("rules:")
    for rule in data.get("rules", []):
        pattern = rule.get("pattern", "*")
        lines.append(f'  - pattern: "{pattern}"')
        # Sort keys for deterministic output, ensuring 'pattern' is handled first
        for key in sorted(rule.keys()):
            if key == "pattern":
                continue
            val = rule[key]
            if isinstance(val, list):
                items_str = ", ".join(f'"{item}"' if isinstance(item, str) else str(item) for item in val)
                lines.append(f"    {key}: [{items_str}]")
            else:
                lines.append(f"    {key}: {val}")
    return "\n".join(lines) + "\n"

def cmd_status(args):
    root = find_project_root()
    report_path = os.path.join(root, "shield_reports", "violation_report.json")
    if not os.path.exists(report_path):
        print("No active violation reports found.")
        return 0

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading violation report: {e}")
        return 1

    violation_type = report.get("violation_type", "unknown")
    func_name = report.get("function_name", "unknown")
    file_path = report.get("file_path", "unknown")
    details = report.get("details", {})
    instruction = report.get("instruction", "")

    print("=" * 80)
    print("                         AGENT-SHIELD VIOLATION REPORT")
    print("=" * 80)
    print(f"Violation Type: {violation_type}")
    print(f"Function Name:  {func_name}")
    print(f"File Path:      {file_path}")
    print("Details:")
    if isinstance(details, dict):
        for k, v in details.items():
            print(f"  - {k}: {v}")
    else:
        print(f"  - {details}")
    if instruction:
        print("Instruction:")
        print(f"  - {instruction}")

    print("\nSuggested remediation commands:")
    if violation_type == "network_violation":
        host = details.get("requested_host") or details.get("host") or "<host>"
        print(f"  python -m agent_shield whitelist --host \"{host}\"")
    elif violation_type == "filesystem_violation":
        path = details.get("requested_path") or details.get("path") or "<path>"
        is_write = details.get("operation") == "write"
        op_flag = "--write" if is_write else "--read"
        print(f"  python -m agent_shield whitelist --path \"{path}\" {op_flag}")
    elif violation_type == "forbidden_import" or violation_type == "disallowed_import":
        imported = details.get("imported") or "<module>"
        print(f"  python -m agent_shield whitelist --import \"{imported}\"")
    elif violation_type == "subprocess_violation":
        forbidden = details.get("forbidden_command") or "<command>"
        print(f"  python -m agent_shield whitelist --command \"{forbidden}\"")
    elif violation_type == "call_limit_violation":
        print("  - Check your code for infinite loops or increase the limit_calls value in shield.yaml.")
    elif violation_type == "secrets_leak_violation":
        leak_type = details.get("leak_type") or "secret/PII"
        print(f"  - Remove the leaked '{leak_type}' from the output/file/request, or check decorator options.")
    else:
        print("  Check your shield.yaml rules and add exceptions manually.")
    print("=" * 80)
    return 0

def cmd_whitelist(args):
    if not args.import_name and not args.path and not args.host and not args.command_name:
        print("Error: You must specify at least one of --import, --path, --host, or --command to whitelist.")
        return 1

    root = find_project_root()
    yaml_path = os.path.join(root, "shield.yaml")

    # Read existing or initialize basic rules structure
    if os.path.exists(yaml_path):
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                content = f.read()
            config = parse_simple_yaml(content)
        except Exception as e:
            print(f"Error parsing shield.yaml: {e}")
            return 1
    else:
        config = {"rules": []}

    rules = config.get("rules", [])
    
    # Try to find a rule matching the given pattern (or default to "*")
    target_pattern = args.pattern or "*"
    matching_rule = None
    for rule in rules:
        if rule.get("pattern") == target_pattern:
            matching_rule = rule
            break

    if matching_rule is None:
        matching_rule = {"pattern": target_pattern}
        rules.append(matching_rule)

    # Apply changes
    if args.import_name:
        allowed = matching_rule.get("allowed_imports", [])
        if args.import_name not in allowed:
            allowed.append(args.import_name)
        matching_rule["allowed_imports"] = allowed
        print(f"Whitelisted import '{args.import_name}' for pattern '{target_pattern}'.")

    if args.host:
        hosts = matching_rule.get("restrict_network", [])
        if args.host not in hosts:
            hosts.append(args.host)
        matching_rule["restrict_network"] = hosts
        print(f"Whitelisted host '{args.host}' for pattern '{target_pattern}'.")

    if args.command_name:
        cmds = matching_rule.get("restrict_subprocess", [])
        if args.command_name not in cmds:
            cmds.append(args.command_name)
        matching_rule["restrict_subprocess"] = cmds
        print(f"Whitelisted subprocess command '{args.command_name}' for pattern '{target_pattern}'.")

    if args.path:
        # Default to both read and write if neither is specified
        read_flag = args.read
        write_flag = args.write
        if not read_flag and not write_flag:
            read_flag = True
            write_flag = True

        if read_flag:
            paths = matching_rule.get("allow_read", [])
            if args.path not in paths:
                paths.append(args.path)
            matching_rule["allow_read"] = paths
            print(f"Whitelisted read path '{args.path}' for pattern '{target_pattern}'.")
        if write_flag:
            paths = matching_rule.get("allow_write", [])
            if args.path not in paths:
                paths.append(args.path)
            matching_rule["allow_write"] = paths
            print(f"Whitelisted write path '{args.path}' for pattern '{target_pattern}'.")

    # Serialize back to shield.yaml
    config["rules"] = rules
    try:
        yaml_content = serialize_simple_yaml(config)
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)
    except Exception as e:
        print(f"Error writing to shield.yaml: {e}")
        return 1

    # Clean up violation_report.json if it is resolved
    report_path = os.path.join(root, "shield_reports", "violation_report.json")
    if os.path.exists(report_path):
        try:
            os.remove(report_path)
            print("Cleaned up violation report.")
        except Exception:
            pass

    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(prog="agent-shield", description="Agent-Shield CLI utility")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-commands")

    # Status sub-command
    status_parser = subparsers.add_parser("status", help="Show the latest policy violation report")

    # Whitelist sub-command
    whitelist_parser = subparsers.add_parser("whitelist", help="Add exception to shield.yaml config")
    whitelist_parser.add_argument("--import", dest="import_name", help="Whitelist module name for imports")
    whitelist_parser.add_argument("--path", help="Whitelist file/directory path")
    whitelist_parser.add_argument("--read", action="store_true", help="Allow read access to path")
    whitelist_parser.add_argument("--write", action="store_true", help="Allow write access to path")
    whitelist_parser.add_argument("--host", help="Whitelist network host/domain")
    whitelist_parser.add_argument("--command", dest="command_name", help="Whitelist subprocess command")
    whitelist_parser.add_argument("--pattern", help="Rule pattern to update (defaults to '*')")

    args = parser.parse_args(argv)

    if args.command == "status":
        return cmd_status(args)
    elif args.command == "whitelist":
        return cmd_whitelist(args)
    return 0

if __name__ == "__main__":
    sys.exit(main())
