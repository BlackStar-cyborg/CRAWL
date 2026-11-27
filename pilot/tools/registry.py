#!/usr/bin/env python3
"""Small registry tasks around a deployment (standard library only).

    python3 pilot/tools/registry.py --state data/n01/state prereg       --node n01 --deployment n01-2026-12
    python3 pilot/tools/registry.py --state data/n01/state mark-exposed --node n01 --deployment n01-2026-12
    python3 pilot/tools/registry.py --state data/n01/state show         --node n01 --deployment n01-2026-12

prereg        hash the deployment's token list and store it (run BEFORE uploading the site).
              The hash reveals no tokens, so it can be shared as proof of pre-registration.
mark-exposed  set exposed_utc = now for the deployment's planted tokens that have none yet
              (run right AFTER a successful upload). Re-deploying keeps the first time.
              Also retires all tokens of the node's other deployments.
show          print the deployment's tokens and their timestamps.
positive-urls print the URL paths of the deployment's positive control tokens (one per line).
"""

import argparse
import sys

from common import open_registry, registry_hash, utc_now_iso


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", required=True)
    ap.add_argument("command", choices=["prereg", "mark-exposed", "show", "positive-urls"])
    ap.add_argument("--node", required=True)
    ap.add_argument("--deployment", required=True)
    args = ap.parse_args()

    con = open_registry(args.state)
    n = con.execute("SELECT count(*) FROM tokens WHERE node=? AND deployment=?",
                    (args.node, args.deployment)).fetchone()[0]
    if n == 0:
        sys.exit("No tokens for node %s, deployment %s in %s. Build the site first."
                 % (args.node, args.deployment, args.state))

    if args.command == "prereg":
        digest, count = registry_hash(con, args.node, args.deployment)
        prev = con.execute("SELECT sha256 FROM preregistrations WHERE node=? AND deployment=? "
                           "ORDER BY recorded_utc DESC LIMIT 1", (args.node, args.deployment)).fetchone()
        if prev and prev[0] == digest:
            print("Pre-registration unchanged: %s (%d tokens)" % (digest, count))
        else:
            if prev:
                print("WARNING: token list changed since the last pre-registration of this deployment.")
            con.execute("INSERT INTO preregistrations VALUES (?,?,?,?,?)",
                        (args.node, args.deployment, digest, count, utc_now_iso()))
            con.commit()
            print("Pre-registered %s %s: sha256 %s (%d tokens)" % (args.node, args.deployment, digest, count))

    elif args.command == "mark-exposed":
        now = utc_now_iso()
        cur = con.execute("UPDATE tokens SET exposed_utc=? WHERE node=? AND deployment=? "
                          "AND control IS NULL AND exposed_utc IS NULL", (now, args.node, args.deployment))
        con.commit()
        exposed = cur.rowcount
        # the previous deployment of this node is replaced now, so its tokens are retired from now on
        cur = con.execute("UPDATE tokens SET retired_utc=? WHERE node=? AND deployment<>? AND retired_utc IS NULL",
                          (now, args.node, args.deployment))
        con.commit()
        print("Marked %d tokens as exposed at %s; retired %d tokens of earlier deployments"
              % (exposed, now, cur.rowcount))

    elif args.command == "positive-urls":
        for r in con.execute("SELECT url_path FROM tokens WHERE node=? AND deployment=? AND control='positive' "
                             "ORDER BY token", (args.node, args.deployment)):
            print(r["url_path"])

    else:
        for r in con.execute("SELECT placement, depth, url_path, control, created_utc, exposed_utc, retired_utc "
                             "FROM tokens WHERE node=? AND deployment=? ORDER BY control, placement, depth",
                             (args.node, args.deployment)):
            print("%-16s %3s  %-45s %-9s exposed=%s retired=%s" % (
                r["placement"], r["depth"], r["url_path"], r["control"] or "", r["exposed_utc"], r["retired_utc"]))


if __name__ == "__main__":
    main()
