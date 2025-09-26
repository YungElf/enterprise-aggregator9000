import sys
from .run_catalog import main as run_catalog_main
from .run_metrics import main as run_metrics_main

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m flask_app.data_aggregator.main [catalog|metrics|both]")
        return 2
    cmd = sys.argv[1].lower()
    if cmd == "catalog":
        run_catalog_main()
        return 0
    if cmd == "metrics":
        run_metrics_main()
        return 0
    if cmd == "both":
        run_catalog_main()
        run_metrics_main()
        return 0
    print(f"Unknown option: {cmd}")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
