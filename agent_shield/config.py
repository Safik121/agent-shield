import os
import sys
import builtins
import fnmatch
import inspect

_original_import = builtins.__import__
_hook_applied = False
_decorated_modules = set()

def find_project_root():
    """Finds the root directory containing shield.yaml."""
    cur = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for _ in range(4):
        if os.path.exists(os.path.join(cur, "shield.yaml")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.getcwd()

def parse_simple_yaml(content: str) -> dict:
    """Parses a simple list of rules from a YAML string without external dependencies."""
    data = {"rules": []}
    current_rule = None
    
    for line in content.splitlines():
        # Strip comments
        line = line.split("#")[0].strip()
        if not line:
            continue
            
        if line.startswith("-"):
            line = line[1:].strip()
            current_rule = {}
            data["rules"].append(current_rule)
            
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            
            # Parse list values like [math, json]
            if val.startswith("[") and val.endswith("]"):
                val = [item.strip().strip("'\"") for item in val[1:-1].split(",") if item.strip()]
            elif val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            else:
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                else:
                    try:
                        if "." in val:
                            val = float(val)
                        else:
                            val = int(val)
                    except ValueError:
                        pass
            
            if current_rule is not None:
                current_rule[key] = val
                
    return data

def _apply_rules_to_module(module, module_name, rules):
    matching_rules = []
    for rule in rules:
        pattern = rule.get("pattern")
        if pattern and fnmatch.fnmatch(module_name, pattern):
            matching_rules.append(rule)
            
    if not matching_rules:
        return
        
    for attr_name in dir(module):
        try:
            attr = getattr(module, attr_name)
        except Exception:
            continue
            
        if inspect.isfunction(attr):
            if getattr(attr, "__module__", None) == module_name:
                decorated = attr
                for rule in matching_rules:
                    if "timeout" in rule:
                        from agent_shield.timeout import timeout
                        decorated = timeout(float(rule["timeout"]))(decorated)
                        
                    if "limit_memory" in rule:
                        from agent_shield.memory_limit import limit_memory
                        decorated = limit_memory(float(rule["limit_memory"]))(decorated)
                        
                    if "restrict_network" in rule:
                        from agent_shield.network_sandbox import restrict_network
                        decorated = restrict_network(rule["restrict_network"])(decorated)
                        
                    if "allowed_imports" in rule:
                        from agent_shield.contracts import shield
                        decorated = shield(allowed_imports=rule["allowed_imports"])(decorated)
                        
                    if "forbidden_imports" in rule:
                        from agent_shield.contracts import shield
                        decorated = shield(forbidden_imports=rule["forbidden_imports"])(decorated)
                        
                    if "allow_read" in rule or "allow_write" in rule:
                        from agent_shield.fs_sandbox import restrict_fs
                        decorated = restrict_fs(
                            allow_read=rule.get("allow_read"),
                            allow_write=rule.get("allow_write")
                        )(decorated)
                        
                    if "max_complexity" in rule:
                        from agent_shield.contracts import shield
                        decorated = shield(max_complexity=int(rule["max_complexity"]))(decorated)
                        
                    if "no_side_effects" in rule and rule["no_side_effects"]:
                        from agent_shield.side_effects import no_side_effects
                        decorated = no_side_effects(decorated)
                        
                    if "restrict_subprocess" in rule:
                        from agent_shield.subprocess_sandbox import restrict_subprocess
                        decorated = restrict_subprocess(rule["restrict_subprocess"])(decorated)
                        
                    if "no_secrets_leak" in rule and rule["no_secrets_leak"]:
                        from agent_shield.secrets_sandbox import no_secrets_leak
                        leak_types = rule["no_secrets_leak"] if isinstance(rule["no_secrets_leak"], list) else None
                        decorated = no_secrets_leak(leak_types)(decorated)
                        
                    if "limit_calls" in rule:
                        from agent_shield.network_sandbox import limit_calls
                        max_calls = int(rule["limit_calls"])
                        decorated = limit_calls(max_calls)(decorated)
                        
                    if "restrict_env" in rule and rule["restrict_env"]:
                        from agent_shield.contracts import restrict_env
                        decorated = restrict_env(allow_mutation=False)(decorated)
                try:
                    setattr(module, attr_name, decorated)
                except Exception:
                    pass

def init_config(config_path: str = None):
    """Initializes config parsing and registers import hooks to auto-decorate functions."""
    global _hook_applied
    if _hook_applied and not config_path:
        return
        
    if config_path:
        yaml_path = config_path
    else:
        root = find_project_root()
        yaml_path = os.path.join(root, "shield.yaml")
        
    if not os.path.exists(yaml_path):
        return
        
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            content = f.read()
        config = parse_simple_yaml(content)
    except Exception as e:
        print(f"Warning: agent-shield failed to parse shield.yaml: {e}")
        return
        
    rules = config.get("rules", [])
    if not rules:
        return

    # Scan already imported modules
    for mod_name, mod in list(sys.modules.items()):
        if mod and mod_name not in _decorated_modules:
            _decorated_modules.add(mod_name)
            _apply_rules_to_module(mod, mod_name, rules)

    # Wrap __import__ to catch future imports
    def custom_import(name, globals=None, locals=None, fromlist=None, level=0):
        module = _original_import(name, globals, locals, fromlist, level)
        if module:
            module_name = getattr(module, "__name__", None)
            if module_name and module_name not in _decorated_modules:
                _decorated_modules.add(module_name)
                _apply_rules_to_module(module, module_name, rules)
        return module

    builtins.__import__ = custom_import
    _hook_applied = True
