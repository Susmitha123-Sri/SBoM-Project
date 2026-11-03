# sbom-tools/summarize_snapshots.py
#
# Fill the /trends summary tables (migration 005) from the daily snapshots,
# one finished (completed / partial) run at a time, then one pair of
# consecutive runs at a time (tier crossings). Each item is its own
# transaction: an error or Ctrl+C rolls back only that item, and a rerun
# continues with what is left. package_snapshots is only read.
#
# Preview (default): what is summarised and what is pending; writes nothing.
#     python sbom-tools/summarize_snapshots.py
# Summarise everything pending (or the first N items):
#     python sbom-tools/summarize_snapshots.py --apply [--limit N]

import argparse
import sys
import time


def main(argv=None, clock=time.monotonic):
    parser = argparse.ArgumentParser(
        description="Summarise daily snapshots for /trends (preview by default)."
    )
    parser.add_argument("--apply", action="store_true",
                        help="Write the summaries. Without this flag only a preview is shown.")
    parser.add_argument("--limit", type=int, default=None,
                        help="summarise at most N items (runs, then pairs)")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1:
        print("Error: --limit must be at least 1.")
        return 2

    import snapshot_summary as ss

    try:
        runs = ss.eligible_runs()
        pairs = ss.consecutive_pairs(runs)
    except ss.SummaryTablesMissing:
        print("Error: migration 005 is not applied (summary tables missing).")
        return 2
    except Exception as e:
        print(f"Error: database not reachable ({type(e).__name__}: {e}). Is MySQL running?")
        return 2

    todo_runs = [r for r in runs if not r["summarized"]]
    todo_pairs = [(p, r) for p, r, done in pairs if not done]
    print(f"Finished runs: {len(runs)} (summarised {len(runs) - len(todo_runs)}, "
          f"pending {len(todo_runs)}); consecutive pairs: {len(pairs)} "
          f"(pending {len(todo_pairs)})")
    for r in runs:
        print(f"  run {r['run_id']:>5}  {r['snapshot_date'].isoformat()}  {r['status']:<9} "
              f"{r['package_count'] or 0:>9} rows  "
              f"{'summarised' if r['summarized'] else 'pending'}")

    if not args.apply:
        print("\nPreview only. Nothing was written. Re-run with --apply to summarise.")
        return 0
    if not todo_runs and not todo_pairs:
        print("Nothing to summarise.")
        return 0

    items = ([("run", r) for r in todo_runs] + [("pair", p) for p in todo_pairs])
    items = items[:args.limit] if args.limit else items
    failed = 0
    for i, (kind, item) in enumerate(items, 1):
        start = clock()
        try:
            if kind == "run":
                rows, packages = ss.summarize_run(item["run_id"])
                text = (f"run {item['run_id']} ({item['snapshot_date'].isoformat()}, "
                        f"{item['status']}): {rows:,} rows, {packages:,} packages")
            else:
                prev, run = item
                c = ss.summarize_pair(prev["run_id"], run["run_id"])
                text = (f"pair {prev['snapshot_date'].isoformat()} -> "
                        f"{run['snapshot_date'].isoformat()}: {c['rows_changed']:,} of "
                        f"{c['rows_both']:,} rows changed tier, {c['rows_new']:,} new, "
                        f"{c['rows_gone']:,} gone")
        except KeyboardInterrupt:
            print(f"Interrupted at item {i} of {len(items)} (rolled back); rerun to continue.")
            return 130
        except Exception as e:
            failed += 1
            text = f"{kind} failed ({type(e).__name__}: {e})"
        print(f"[{i}/{len(items)}] {text}, {clock() - start:.1f} s")

    print(f"Done: {len(items) - failed} summarised, {failed} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
