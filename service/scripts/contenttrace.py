#!/usr/bin/env python3
"""Unified TraceClean CLI entrypoint for experimental audit orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

# Insert parent dir so we can import from provenance
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from provenance.db import (
    save_experiment,
    get_experiment,
    list_experiments,
    get_experiment_run,
    list_experiment_runs,
    get_run_metrics,
)
from provenance.experiments import (
    validate_config,
    run_pipeline,
)


def cmd_experiment_run(args: argparse.Namespace) -> int:
    config_path = Path(args.config_path).expanduser().resolve()
    if not config_path.is_file():
        print(f"Error: configuration file not found: {config_path}", file=sys.stderr)
        return 2

    try:
        config_str = config_path.read_text("utf-8")
        config = validate_config(config_str)
    except Exception as e:
        print(f"Validation Error: {e}", file=sys.stderr)
        return 2

    exp_name = config["experiment"]["name"]
    experiment_id = f"exp-{uuid.uuid4().hex[:12]}"
    
    # Save experiment definition
    save_experiment(experiment_id, exp_name, json.dumps(config), time.time())
    print(f"Created Experiment: {exp_name} ({experiment_id})")

    # Detect if parameter sweep is requested
    sweep_sec = config.get("sweep")
    runs_to_execute = []

    if sweep_sec:
        param_path = sweep_sec["parameter"]  # e.g. "attack.parameters.strength"
        sweep_values = sweep_sec["values"]
        print(f"Initiating Parameter Sweep for '{param_path}' with {len(sweep_values)} steps...")
        
        # Helper to set nested dict value
        def set_nested(d, path_keys, val):
            current = d
            for key in path_keys[:-1]:
                current = current.setdefault(key, {})
            current[path_keys[-1]] = val

        path_keys = param_path.split(".")
        for val in sweep_values:
            import copy
            sweep_config = copy.deepcopy(config)
            try:
                set_nested(sweep_config, path_keys, val)
            except Exception as e:
                print(f"Error setting sweep parameter {param_path}: {e}", file=sys.stderr)
                return 1
            runs_to_execute.append((val, sweep_config))
    else:
        runs_to_execute.append((None, config))

    for sweep_val, run_config in runs_to_execute:
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        label = f" [Sweep Value: {sweep_val}]" if sweep_val is not None else ""
        print(f"\nLaunching Run: {run_id}{label}...")
        
        # Run synchronously in CLI
        run_pipeline(run_id, experiment_id, run_config)
        
        # Fetch results
        run = get_experiment_run(run_id)
        if run["status"] == "completed":
            print(f"Run {run_id} completed successfully.")
            metrics = get_run_metrics(run_id)
            print("Recorded Metrics:")
            for m in metrics:
                val_str = f"{m['value']:.4f}" if m['value'] is not None else "N/A"
                print(f"  - {m['name']}: {val_str} {m['unit']}")
        else:
            print(f"Run {run_id} failed. Error: {run['error']}", file=sys.stderr)

    print("\n" + "=" * 60)
    print("Result Honesty & Methodology Disclosure:")
    print("  Detection confidence changes under these simulated attacks are reported")
    print("  solely as measured benchmarks under the specified pipeline parameters.")
    print("  This evaluation does NOT establish that watermarks are universally removed.")
    print("=" * 60)
    return 0


def cmd_experiment_list(args: argparse.Namespace) -> int:
    exps = list_experiments()
    if not exps:
        print("No experiments found in history.")
        return 0

    print(f"{'Experiment ID':<16} | {'Name':<30} | {'Runs':<5}")
    print("-" * 60)
    for e in exps:
        runs = list_experiment_runs(e["id"])
        print(f"{e['id']:<16} | {e['name'][:30]:<30} | {len(runs):<5}")
    return 0


def cmd_experiment_show(args: argparse.Namespace) -> int:
    run = get_experiment_run(args.run_id)
    if not run:
        print(f"Error: Experiment run {args.run_id} not found.", file=sys.stderr)
        return 4

    exp = get_experiment(run["experiment_id"])
    exp_name = exp["name"] if exp else "Unknown"

    print(f"Experiment Name: {exp_name}")
    print(f"Run ID:          {run['id']}")
    print(f"Status:          {run['status'].upper()}")
    print(f"Device:          {run['device'] or 'auto'}")
    print(f"Started At:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run['started_at']))}")
    if run["finished_at"]:
        print(f"Finished At:     {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run['finished_at']))}")
    if run["input_hash"]:
        print(f"Input SHA256:    {run['input_hash']}")
    if run["error"]:
        print(f"Error Log:       {run['error']}")

    print("\nReproducibility Metadata:")
    try:
        rep = json.loads(run["reproducibility_json"])
        print(f"  TraceClean Version: {rep.get('version')}")
        print(f"  Platform:           {rep.get('platform')}")
        print(f"  Python Version:     {rep.get('python_version').split()[0]}")
        print("  Harness Environments:")
        for h, path in rep.get("harness_versions", {}).items():
            print(f"    - {h}: {path}")
    except Exception:
        print("  Unavailable or corrupted JSON.")

    print("\nMetrics:")
    metrics = get_run_metrics(args.run_id)
    if not metrics:
        print("  No metrics recorded.")
    for m in metrics:
        val_str = f"{m['value']:.4f}" if m['value'] is not None else "N/A"
        print(f"  - {m['name']}: {val_str} {m['unit']}")
    return 0


def cmd_experiment_compare(args: argparse.Namespace) -> int:
    run1 = get_experiment_run(args.run1_id)
    run2 = get_experiment_run(args.run2_id)
    
    if not run1:
        print(f"Error: Run {args.run1_id} not found.", file=sys.stderr)
        return 4
    if not run2:
        print(f"Error: Run {args.run2_id} not found.", file=sys.stderr)
        return 4

    metrics1 = {m["name"]: m for m in get_run_metrics(args.run1_id)}
    metrics2 = {m["name"]: m for m in get_run_metrics(args.run2_id)}

    all_metric_names = sorted(list(set(metrics1.keys()) | set(metrics2.keys())))

    print(f"Comparing Runs:")
    print(f"  Run A: {args.run1_id} (Status: {run1['status']})")
    print(f"  Run B: {args.run2_id} (Status: {run2['status']})")
    print("-" * 70)
    print(f"{'Metric Name':<30} | {'Run A':<15} | {'Run B':<15}")
    print("-" * 70)
    for name in all_metric_names:
        m1 = metrics1.get(name)
        m2 = metrics2.get(name)
        val1 = f"{m1['value']:.4f} {m1['unit']}" if m1 and m1['value'] is not None else "N/A"
        val2 = f"{m2['value']:.4f} {m2['unit']}" if m2 and m2['value'] is not None else "N/A"
        print(f"{name:<30} | {val1:<15} | {val2:<15}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # experiment parser
    exp_parser = subparsers.add_parser("experiment", help="Experiment commands")
    exp_sub = exp_parser.add_subparsers(dest="action", required=True)

    # experiment run
    run_parser = exp_sub.add_parser("run", help="Run a configuration experiment")
    run_parser.add_argument("config_path", help="Path to config.yaml")
    run_parser.set_defaults(handler=cmd_experiment_run)

    # experiment list
    list_parser = exp_sub.add_parser("list", help="List experiments history")
    list_parser.set_defaults(handler=cmd_experiment_list)

    # experiment show
    show_parser = exp_sub.add_parser("show", help="Show an individual run details")
    show_parser.add_argument("run_id", help="Experiment run ID")
    show_parser.set_defaults(handler=cmd_experiment_show)

    # experiment compare
    compare_parser = exp_sub.add_parser("compare", help="Compare two experiment runs")
    compare_parser.add_argument("run1_id", help="First experiment run ID")
    compare_parser.add_argument("run2_id", help="Second experiment run ID")
    compare_parser.set_defaults(handler=cmd_experiment_compare)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
