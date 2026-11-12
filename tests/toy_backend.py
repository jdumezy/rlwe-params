"""A backend written without rlwe-params, as one in another language would be.

Security is 3.5 * n / log2(q) bits for "primal", 5 bits more for "dual".
Uniform secrets are unsupported.
"""

import json
import math
import sys


def answer(request):
    if request["op"] == "describe":
        return {"name": "toy", "revision": "toy-1", "cost_model": request["options"]["cost_model"],
                "configuration": {}, "attacks": ["primal", "dual"]}
    parameters = request["parameters"]
    if parameters["secret"]["type"] == "uniform":
        raise LookupError("unsupported")
    if request["op"] == "supports":
        return True
    if request["op"] == "attack":
        if request["attack"] not in ("primal", "dual"):
            raise KeyError(request["attack"])
        bits = 3.5 * parameters["n"] / math.log2(int(parameters["q"], 16))
        return f"{math.floor((bits + (5 if request['attack'] == 'dual' else 0)) * 1e6) / 1e6:.6f}"
    raise KeyError(request["op"])


for line in sys.stdin:
    try:
        response = {"result": answer(json.loads(line))}
    except LookupError as exc:
        kind = "unsupported" if str(exc) == "unsupported" else "invalid"
        response = {"error": {"kind": kind, "message": f"toy: {exc}"}}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
