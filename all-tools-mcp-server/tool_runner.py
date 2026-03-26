import sys
import json
import importlib
import asyncio
import inspect
from pathlib import Path

def main():
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
            params.append({
                "name": name,
                "kind": str(param.kind),
                "default": "empty" if param.default == inspect.Parameter.empty else repr(param.default),
                "annotation": "empty" if param.annotation == inspect.Parameter.empty else getattr(param.annotation, "__name__", str(param.annotation))
            })
        print(json.dumps({
            "doc": inspect.getdoc(func) or "",
            "is_coro": inspect.iscoroutinefunction(func),
            "params": params
        }))
        
    elif command == "run":
        kwargs = json.loads(sys.stdin.read())
        try:
            if inspect.iscoroutinefunction(func):
                result = asyncio.run(func(**kwargs))
            else:
                result = func(**kwargs)
            print(json.dumps({"result": result}))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)

if __name__ == "__main__":
    main()
