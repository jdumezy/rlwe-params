"""Line-oriented backend worker, executed by its own Python runtime."""

from contextlib import redirect_stdout
from hashlib import sha256
from pathlib import Path
import sys
import traceback


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ckks_estimator._serialization import dumps, loads


def main():
    backends = {}
    output = sys.stdout
    for line in sys.stdin:
        try:
            request = loads(line)
            with redirect_stdout(sys.stderr):
                if request["operation"] == "load":
                    from ckks_estimator.estimators._malb import MalbEstimator
                    from ckks_estimator.estimators._tabog import TabOgEstimator

                    adapter = {"malb": MalbEstimator, "tabog": TabOgEstimator}[request["backend"]]
                    backend = adapter(**request["options"])
                    result = {key: getattr(backend, key) for key in
                              ("name", "revision", "cost_model", "configuration")}
                    identifier = sha256(dumps(result).encode()).hexdigest()
                    backends[identifier] = backend
                    result["id"] = identifier
                elif request["operation"] in ("supports", "estimate"):
                    backend = backends[request["id"]]
                    result = getattr(backend, request["operation"])(request["parameters"])
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
