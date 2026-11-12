"""Line-oriented backend worker, executed by its own Python runtime."""

from contextlib import redirect_stdout
from hashlib import sha256
import importlib
from pathlib import Path
import sys
import traceback


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rlwe_params.installation import BACKENDS
from rlwe_params._serialization import dumps, loads


def main():
    backends = {}
    output = sys.stdout
    for line in sys.stdin:
        try:
            request = loads(line)
            with redirect_stdout(sys.stderr):
                if request["operation"] == "load":
                    module, _, adapter = BACKENDS[request["backend"]].adapter.partition(":")
                    backend = getattr(importlib.import_module(module), adapter)(**request["options"])
                    result = {key: getattr(backend, key) for key in
                              ("name", "revision", "cost_model", "configuration", "attacks")}
                    identifier = sha256(dumps(result).encode()).hexdigest()
                    backends[identifier] = backend
                    result["id"] = identifier
                elif request["operation"] == "supports":
                    result = backends[request["id"]].supports(request["parameters"])
                elif request["operation"] == "attack":
                    result = backends[request["id"]].attack(request["parameters"], request["attack"])
                else:
                    raise ValueError("Unknown worker operation.")
            response = {"result": result}
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            response = {"error": type(exc).__name__, "message": str(exc)}
        output.write(dumps(response) + "\n")
        output.flush()


if __name__ == "__main__":
    main()
