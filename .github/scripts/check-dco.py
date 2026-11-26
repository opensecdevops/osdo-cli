#!/usr/bin/env python3
"""Check that every non-merge commit in a pull request carries a DCO sign-off.

Input: a JSON array of commits as returned by
GET /repos/{owner}/{repo}/pulls/{number}/commits (all pages concatenated).

A commit passes when its message contains a line exactly equal to
"Signed-off-by: <author name> <author email>". Merge commits (more than one
parent) are exempt.

Exit codes: 0 all commits signed off, 1 one or more commits fail or the list
is empty, 2 malformed input.
"""
import json
import sys

# The REST API returns at most 250 commits per pull request. At that size the
# list may be truncated, so refuse to pass it silently.
API_COMMIT_LIMIT = 250


def main(argv):
    if len(argv) != 2:
        print("usage: check-dco.py <commits.json>", file=sys.stderr)
        return 2

    try:
        with open(argv[1], encoding="utf-8") as handle:
            commits = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"::error::cannot read commit list: {exc}")
        return 2

    if not isinstance(commits, list):
        print("::error::commit list is not a JSON array")
        return 2
    if not commits:
        print("::error::no commits found for this pull request")
        return 1
    if len(commits) >= API_COMMIT_LIMIT:
        print(f"::error::pull request has {len(commits)} commits; the API may truncate the list. "
              "Check sign-off manually or split the pull request.")
        return 1

    failures = []
    checked = 0
    for entry in commits:
        try:
            sha = entry["sha"]
            meta = entry["commit"]
            message = meta["message"]
            name = meta["author"]["name"]
            email = meta["author"]["email"]
        except (KeyError, TypeError):
            print("::error::malformed commit entry in commit list")
            return 2

        if len(entry.get("parents", [])) > 1:
            print(f"merge commit {sha[:10]} is exempt")
            continue

        checked += 1
        expected = f"Signed-off-by: {name} <{email}>"
        lines = [line.rstrip("\r") for line in message.splitlines()]
        if expected not in lines:
            failures.append((sha, expected))

    for sha, expected in failures:
        print(f"::error title=DCO::commit {sha[:10]} has no line '{expected}'. "
              "Amend with 'git commit --amend -s' or rebase with '--signoff'.")

    if failures:
        print(f"DCO failed: {len(failures)} of {checked} non-merge commit(s) lack a matching sign-off.")
        return 1

    print(f"DCO passed: {checked} non-merge commit(s) signed off.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
