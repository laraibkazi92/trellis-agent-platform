import sys
import json
import importlib
import asyncio
import inspect
import contextlib
from pathlib import Path

def get_annotation_str(annotation):
    if annotation == inspect.Parameter.empty:
        return "Any"
    if isinstance(annotation, str):
        return annotation
    # Try to get __name__ or just str()
    return getattr(annotation, "__name__", str(annotation))

def main():
    if len(sys.argv) < 5:
        print(json.dumps({"error": "Missing arguments"}))
        sys.exit(1)
        
    command = sys.argv[1]
    tool_path = sys.argv[2]
    module_name = sys.argv[3]
    func_name = sys.argv[4]
    
    # Add tool path to sys.path
    sys.path.insert(0, tool_path)
    
    try:
        mod = importlib.import_module(module_name)
        func = getattr(mod, func_name)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
        
    if command == "info":
        sig = inspect.signature(func)
        params = []
        for name, param in sig.parameters.items():
            # Handle defaults safely for JSON serialization
            if param.default == inspect.Parameter.empty:
                default_val = "__EMPTY__"
            else:
                try:
                    # check if serializable
                    json.dumps(param.default)
                    default_val = param.default
                except Exception:
                    default_val = str(param.default)
                    
            params.append({
                "name": name,
                "kind": str(param.kind),
                "default": default_val,
                "annotation": get_annotation_str(param.annotation)
            })
            
        print(json.dumps({
            "doc": inspect.getdoc(func) or "",
            "is_coro": inspect.iscoroutinefunction(func),
            "params": params
        }))
        
    elif command == "run":
        try:
            kwargs = json.loads(sys.stdin.read())
        except Exception as e:
            print(json.dumps({"error": f"Invalid input JSON: {str(e)}"}))
            sys.exit(1)
            
        try:
            # Redirect stdout to stderr during tool execution to prevent output corruption
            original_stdout = sys.stdout
            with contextlib.redirect_stdout(sys.stderr):
                if inspect.iscoroutinefunction(func):
                    result = asyncio.run(func(**kwargs))
                else:
                    result = func(**kwargs)
            
            # Print the actual JSON result to the original stdout
            original_stdout.write(json.dumps({"result": result}) + "\n")
        except Exception as e:
            # Errors should still be printed to stdout so they can be parsed by the MCP server
            sys.stdout.write(json.dumps({"error": str(e)}) + "\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
