import json
import os
import subprocess
from typing import Dict, Any, Tuple

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

GRAPHQL_COP_SCRIPT = os.getenv("GRAPHQL_COP_SCRIPT", "graphql-cop.py")
GRAPHW00F_CMD = os.getenv("GRAPHW00F_CMD", "graphw00f")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


def parse_headers(raw_headers: str) -> Dict[str, str]:
    if not raw_headers:
        return {}
    parsed = json.loads(raw_headers)
    if not isinstance(parsed, dict):
        raise ValueError("Headers must be a JSON object")
    return {str(key): str(value) for key, value in parsed.items()}


def run_command(command: list[str]) -> Tuple[int, str, str]:
    try:
        process = subprocess.run(command, capture_output=True, text=True)
        return process.returncode, process.stdout.strip(), process.stderr.strip()
    except FileNotFoundError as exc:
        return 127, "", str(exc)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.post("/api/graphql-cop")
def run_graphql_cop() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    headers_raw = payload.get("headers", "")

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        headers = parse_headers(headers_raw)
    except Exception as exc:
        return jsonify({"error": f"invalid headers JSON: {exc}"}), 400

    command = ["python", GRAPHQL_COP_SCRIPT, "-t", target, "-o", "json"]
    for key, value in headers.items():
        command.extend(["-H", json.dumps({key: value})])

    returncode, stdout, stderr = run_command(command)

    if returncode != 0:
        return jsonify({"error": "GraphQL Cop execution failed", "stderr": stderr, "stdout": stdout}), 500

    try:
        findings = json.loads(stdout)
    except json.JSONDecodeError:
        return jsonify({"error": "GraphQL Cop output was not valid JSON", "stdout": stdout, "stderr": stderr}), 500

    return jsonify({"findings": findings, "command": " ".join(command)})


@app.post("/api/graphw00f")
def run_graphw00f() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    command = [GRAPHW00F_CMD, "-d", target]
    returncode, stdout, stderr = run_command(command)

    if returncode != 0:
        return jsonify({
            "error": "Graphw00f execution failed",
            "stderr": stderr,
            "stdout": stdout,
            "hint": "Ensure graphw00f is installed and available in PATH, or set GRAPHW00F_CMD.",
        }), 500

    return jsonify({"output": stdout, "command": " ".join(command)})


@app.post("/api/introspection")
def introspection() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "").strip()
    headers_raw = payload.get("headers", "")

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        headers = parse_headers(headers_raw)
    except Exception as exc:
        return jsonify({"error": f"invalid headers JSON: {exc}"}), 400

    req_headers = {"Content-Type": "application/json", **headers}

    try:
        response = requests.post(target, headers=req_headers, json={"query": INTROSPECTION_QUERY}, timeout=30)
        response.raise_for_status()
    except requests.RequestException as exc:
        return jsonify({"error": f"Introspection request failed: {exc}"}), 500

    data = response.json()

    if "errors" in data:
        return jsonify({"error": "Introspection returned errors", "details": data["errors"]}), 500

    return jsonify({"introspection": data.get("data")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
