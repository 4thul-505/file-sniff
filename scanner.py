#!/usr/bin/env python3
import os, sys, argparse
from virustotal import lookup_hash, print_bazaar_result
from magic_detector import analyze_file, print_result
from report import save_report

def scan(target, flagged_only=False, save=True):
    results = []
    if os.path.isfile(target):
        r = analyze_file(target)
        print_result(r)
        if r:
            results.append(r)
    elif os.path.isdir(target):
        print(f"[*] Scanning: {target}\n")
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                fpath = os.path.join(root, fname)
                r = analyze_file(fpath)
                if r:
                    print_result(r)
                    results.append(r)
    else:
        print(f"[-] Not found: {target}")
        sys.exit(1)

    total = len(results)
    flagged = [r for r in results if r['verdict'] != 'CLEAN']
    investigate = [r for r in results if r['verdict'] == 'INVESTIGATE']

    print(f"\n{'─'*50}")
    print(f"  Scanned    : {total} files")
    print(f"  Suspicious : {len(flagged)}")
    print(f"  Investigate: {len(investigate)}")

    if save and flagged:
        out = save_report(results, flagged_only=flagged_only)
        print(f"  Report     : {out}")

    print(f"{'─'*50}\n")

    if investigate:
        print("[!] Running MalwareBazaar lookups for INVESTIGATE verdicts...\n")
        for r in investigate:
            print(f"  {r['filename']} — {r['sha256']}")
            result = lookup_hash(r['sha256'])
            print_bazaar_result(r['sha256'], result)
            print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('--flagged-only', action='store_true')
    parser.add_argument('--no-report', action='store_true')
    args = parser.parse_args()
    scan(args.target, flagged_only=args.flagged_only, save=not args.no_report)

if __name__ == '__main__':
    main()
