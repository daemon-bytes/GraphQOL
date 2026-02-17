import json
from typing import Any, Dict, List, Tuple

import requests
from flask import Flask, jsonify, render_template, request

from config import HEADERS as GRAPHCOP_HEADERS
from lib.tests import tests as graphql_cop_tests

app = Flask(__name__)

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        type { ...TypeRef }
      }
      inputFields {
        name
        type { ...TypeRef }
      }
      interfaces { ...TypeRef }
      possibleTypes { ...TypeRef }
      enumValues(includeDeprecated: true) { name }
    }
    directives {
      name
      description
      locations
    }
  }
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
          }
        }
      }
    }
  }
}
"""

ENGINE_SECURITY_NOTES = {
    "Apollo": [
        "Disable introspection and GraphQL Playground in production.",
        "Apply query depth and complexity limits to prevent DoS.",
        "Avoid detailed stack traces and GraphQL error internals in responses.",
    ],
    "Hasura": [
        "Require strict admin secret/JWT validation and rotate credentials.",
        "Harden row/column permission policies for every role.",
        "Disable metadata/admin endpoints from public exposure.",
    ],
    "graphene-python": [
        "Disable debug middleware and tracing extensions in production.",
        "Add rate limiting and query cost control to endpoint.",
        "Disable GraphiQL on internet-facing deployments.",
    ],
    "PostGraphile": [
        "Constrain role privileges and schema exposure at DB level.",
        "Use persisted queries / allow-lists for sensitive operations.",
        "Disable detailed error hints leaking SQL metadata.",
    ],
    "Ariadne": [
        "Turn off debug mode and rich tracebacks in production.",
        "Apply operation depth and complexity guards.",
        "Restrict introspection where not needed.",
    ],
    "Hot Chocolate": [
        "Disable Banana Cake Pop / tooling endpoints on production.",
        "Use cost analysis middleware and request timeout limits.",
        "Harden authorization directives and resolver-level checks.",
    ],
    "Unknown": [
        "Apply strict authZ/authN controls on each resolver path.",
        "Use query complexity, depth, and rate limiting protections.",
        "Disable introspection/UI tooling for public production endpoints.",
    ],
}


def parse_headers(raw_headers: str) -> Dict[str, str]:
    if not raw_headers:
        return {}
    parsed = json.loads(raw_headers)
    if not isinstance(parsed, dict):
        raise ValueError("Headers must be a JSON object")
    return {str(key): str(value) for key, value in parsed.items()}


def _extract_named_type(type_obj: Dict[str, Any] | None) -> str | None:
    current = type_obj
    while current:
        name = current.get("name")
        if name:
            return name
        current = current.get("ofType")
    return None


def execute_graphql(target: str, headers: Dict[str, str], query: str, variables: Any = None, operation_name: str | None = None) -> Tuple[Dict[str, Any], Dict[str, str]]:
    payload: Dict[str, Any] = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    if operation_name:
        payload["operationName"] = operation_name

    response = requests.post(target, headers={"Content-Type": "application/json", **headers}, json=payload, timeout=40)
    response.raise_for_status()
    data = response.json()
    return data, dict(response.headers)


def run_graphql_cop_audit(target: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base_headers = dict(GRAPHCOP_HEADERS)
    base_headers.update(headers)

    for test in graphql_cop_tests.values():
        findings.append(test(target, {}, dict(base_headers), False))

    return sorted(findings, key=lambda item: item["title"])


def detect_engine(schema_data: Dict[str, Any], response_headers: Dict[str, str]) -> Dict[str, Any]:
    scored: Dict[str, int] = {
        "Apollo": 0,
        "Hasura": 0,
        "graphene-python": 0,
        "PostGraphile": 0,
        "Ariadne": 0,
        "Hot Chocolate": 0,
    }

    lower_headers = {k.lower(): str(v).lower() for k, v in response_headers.items()}
    header_blob = " ".join([f"{k}:{v}" for k, v in lower_headers.items()])

    if "apollo" in header_blob:
        scored["Apollo"] += 3
    if "hasura" in header_blob:
        scored["Hasura"] += 3
    if "graphene" in header_blob:
        scored["graphene-python"] += 3
    if "postgraphile" in header_blob:
        scored["PostGraphile"] += 3
    if "ariadne" in header_blob:
        scored["Ariadne"] += 3
    if "hotchocolate" in header_blob or "chilli" in header_blob:
        scored["Hot Chocolate"] += 3

    schema = schema_data.get("__schema", {})
    directives = {d.get("name", "").lower() for d in schema.get("directives", [])}
    type_names = {t.get("name", "") for t in schema.get("types", [])}
    type_blob = " ".join(type_names).lower()

    if "cachecontrol" in directives:
        scored["Apollo"] += 2
    if {"cached", "frontend"}.intersection(directives):
        scored["Hasura"] += 2
    if "relay" in type_blob:
        scored["PostGraphile"] += 1
    if "query_root" in {name.lower() for name in type_names}:
        scored["Hasura"] += 2
    if "pageinfo" in type_names:
        scored["PostGraphile"] += 1

    best_engine = max(scored, key=lambda key: scored[key])
    confidence = scored[best_engine]

    if confidence == 0:
        best_engine = "Unknown"

    return {
        "engine": best_engine,
        "confidence": confidence,
        "security_notes": ENGINE_SECURITY_NOTES[best_engine],
        "signals": scored,
    }


def build_schema_artifacts(schema_data: Dict[str, Any]) -> Dict[str, Any]:
    schema = schema_data.get("__schema", {})
    all_types = schema.get("types", [])

    object_types = [
        t for t in all_types
        if t.get("kind") == "OBJECT" and not str(t.get("name", "")).startswith("__")
    ]

    object_names = {t.get("name") for t in object_types if t.get("name")}

    nodes = []
    edges = []
    for obj in object_types:
        source = obj.get("name")
        if not source:
            continue
        nodes.append({"data": {"id": source, "label": source}})

        for field in obj.get("fields") or []:
            target_name = _extract_named_type(field.get("type"))
            if target_name and target_name in object_names:
                edges.append({
                    "data": {
                        "id": f"{source}->{target_name}:{field.get('name')}",
                        "source": source,
                        "target": target_name,
                        "label": field.get("name"),
                    }
                })

    object_summaries = [
        {
            "name": t.get("name"),
            "field_count": len(t.get("fields") or []),
            "fields": [f.get("name") for f in (t.get("fields") or [])],
        }
        for t in object_types
    ]

    return {
        "object_count": len(object_summaries),
        "objects": sorted(object_summaries, key=lambda item: item["name"]),
        "graph": {"nodes": nodes, "edges": edges},
    }


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.post("/api/analyze")
def analyze() -> Any:
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target", "")).strip()
    headers_raw = str(payload.get("headers", "")).strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        headers = parse_headers(headers_raw)
    except Exception as exc:
        return jsonify({"error": f"invalid headers JSON: {exc}"}), 400

    try:
        introspection_result, response_headers = execute_graphql(target, headers, INTROSPECTION_QUERY)
    except requests.RequestException as exc:
        return jsonify({"error": f"Failed to introspect endpoint: {exc}"}), 500
    except ValueError:
        return jsonify({"error": "Endpoint did not return valid JSON"}), 500

    if introspection_result.get("errors"):
        return jsonify({"error": "Introspection is unavailable", "details": introspection_result.get("errors")}), 500

    schema_data = introspection_result.get("data") or {}

    try:
        audit_findings = run_graphql_cop_audit(target, headers)
    except Exception as exc:
        return jsonify({"error": f"GraphQL Cop audit failed: {exc}"}), 500

    engine = detect_engine(schema_data, response_headers)
    schema_artifacts = build_schema_artifacts(schema_data)

    return jsonify({
        "engine": engine,
        "audit": audit_findings,
        "schema": schema_artifacts,
        "introspection": schema_data,
    })


@app.post("/api/query")
def run_query() -> Any:
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target", "")).strip()
    headers_raw = str(payload.get("headers", "")).strip()
    query = str(payload.get("query", "")).strip()
    variables_raw = payload.get("variables", "")
    operation_name = str(payload.get("operationName", "")).strip() or None

    if not target or not query:
        return jsonify({"error": "target and query are required"}), 400

    try:
        headers = parse_headers(headers_raw)
    except Exception as exc:
        return jsonify({"error": f"invalid headers JSON: {exc}"}), 400

    variables = None
    if isinstance(variables_raw, str) and variables_raw.strip():
        try:
            variables = json.loads(variables_raw)
        except Exception as exc:
            return jsonify({"error": f"invalid variables JSON: {exc}"}), 400
    elif isinstance(variables_raw, dict):
        variables = variables_raw

    try:
        result, _ = execute_graphql(target, headers, query, variables=variables, operation_name=operation_name)
        return jsonify({"result": result})
    except requests.RequestException as exc:
        return jsonify({"error": f"GraphQL query failed: {exc}"}), 500
    except ValueError:
        return jsonify({"error": "Endpoint did not return valid JSON"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
