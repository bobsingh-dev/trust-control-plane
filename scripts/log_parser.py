import argparse, json, os, time, sys

def compute(path):
    allow = deny = 0
    if not os.path.exists(path):
        return allow, deny, 0.0
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("allowed"):
                allow += 1
            else:
                deny += 1
    total = allow + deny
    score = (allow / total) if total > 0 else 0.0
    return allow, deny, score

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    args = ap.parse_args()

    last_stats = (-1, -1, -1.0)
    while True:
        allow, deny, score = compute(args.input)
        if (allow, deny, score) != last_stats:
            print(f"[trust-score] allow={allow} deny={deny} score={score:.4f}", flush=True)
            last_stats = (allow, deny, score)
        time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
