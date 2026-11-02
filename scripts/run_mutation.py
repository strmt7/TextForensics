#!/usr/bin/env python3
"""
Mutation testing runner for TextForensics using Cosmic Ray.

Supports three modes:
- diff: Mutate only changed lines using git diff (for push/PR)
- full: Full mutation on all configured modules (weekly)
- safety-critical: Deep mutation on safety-critical modules only

Exit codes:
- 0: All mutations caught (no surviving mutants)
- 2: Surviving mutants detected
- 3: Mutation budget exceeded
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def run_command(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return result
    except subprocess.TimeoutExpired as e:
        print(f"Command timed out: {' '.join(cmd)}", file=sys.stderr)
        raise


def get_changed_modules(base_sha: str, target_modules: list[str]) -> list[str]:
    """Get list of changed modules from git diff."""
    try:
        result = run_command(["git", "diff", "--name-only", f"{base_sha}...HEAD"])
        if result.returncode != 0:
            print(f"Git diff failed: {result.stderr}", file=sys.stderr)
            return []
        
        changed_files = result.stdout.strip().split('\n')
        changed_modules = []
        
        for file in changed_files:
            file = file.strip()
            if not file:
                continue
            # Convert file path to module name
            if file.startswith('src/textforensics/') and file.endswith('.py'):
                module = file.replace('src/', '').replace('.py', '').replace('/', '.')
                if module in target_modules:
                    changed_modules.append(module)
        
        return changed_modules
    except Exception as e:
        print(f"Error getting changed modules: {e}", file=sys.stderr)
        return []


def run_cosmic_ray(
    modules: list[str],
    config_path: Path,
    session_name: str,
    timeout: int = 30,
    budget: int = 200,
) -> tuple[int, dict[str, Any]]:
    """Run cosmic-ray mutation testing and return exit code and results."""
    
    # Create a temporary config with only the specified modules
    import yaml
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    config['mutation']['modules'] = modules
    config['mutation']['session']['baseline'] = True
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(config, f)
        temp_config = f.name
    
    try:
        # Run cosmic-ray baseline first
        print(f"Running baseline tests for {len(modules)} modules...")
        result = run_command([
            "cosmic-ray", "baseline",
            temp_config,
            session_name
        ], timeout=timeout * len(modules))
        
        if result.returncode != 0:
            print(f"Baseline tests failed: {result.stderr}")
            return 1, {"error": "baseline_failed", "stderr": result.stderr}
        
        # Run mutation testing
        print(f"Running mutation testing on {len(modules)} modules...")
        result = run_command([
            "cosmic-ray", "run",
            "--timeout", str(timeout),
            "--max-mutations", str(budget),
            temp_config,
            session_name
        ], timeout=timeout * len(modules) * 2)
        
        # Get results
        result_json = run_command([
            "cosmic-ray", "report",
            "--format", "json",
            session_name
        ])
        
        if result_json.returncode == 0:
            try:
                report = json.loads(result_json.stdout)
                return result.returncode, report
            except json.JSONDecodeError:
                print("Failed to parse cosmic-ray JSON report")
                return 1, {"error": "json_parse_failed"}
        
        return result.returncode, {"error": "report_failed", "stderr": result_json.stderr}
    
    finally:
        # Cleanup temp config
        try:
            os.unlink(temp_config)
        except OSError:
            pass


def parse_results(report: dict[str, Any]) -> dict[str, int]:
    """Parse cosmic-ray report and extract summary statistics."""
    summary = {
        "total": 0,
        "killed": 0,
        "surviving": 0,
        "timeout": 0,
        "error": 0,
        "skipped": 0,
    }
    
    if "error" in report:
        return summary
    
    # Cosmic ray report structure varies by version
    # Try to extract from different possible structures
    mutants = report.get("mutants", [])
    if not mutants and "results" in report:
        mutants = report["results"]
    
    for mutant in mutants:
        summary["total"] += 1
        status = mutant.get("status", mutant.get("outcome", "unknown")).lower()
        
        if status in ("killed", "detected"):
            summary["killed"] += 1
        elif status in ("survived", "alive", "surviving"):
            summary["surviving"] += 1
        elif status in ("timeout", "timed_out"):
            summary["timeout"] += 1
        elif status in ("error", "exception"):
            summary["error"] += 1
        elif status in ("skipped",):
            summary["skipped"] += 1
    
    return summary


def write_summary(summary: dict[str, int], output_dir: Path) -> None:
    """Write mutation summary to JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"Summary written to {summary_path}")


def check_results(summary_path: Path) -> int:
    """Check mutation results and return appropriate exit code."""
    with open(summary_path) as f:
        summary = json.load(f)
    
    print(f"Mutation Summary: {json.dumps(summary, indent=2)}")
    
    if summary.get("error"):
        print("Mutation testing failed with errors")
        return 1
    
    if summary.get("surviving", 0) > 0:
        print(f"⚠️  {summary['surviving']} surviving mutant(s) detected!")
        return 2
    
    if summary.get("timeout", 0) > 0:
        print(f"⚠️  {summary['timeout']} mutation(s) timed out")
        # Timeouts don't necessarily mean failure, but could indicate budget issues
        if summary.get("total", 0) > 0 and summary["timeout"] / summary["total"] > 0.1:
            print("⚠️  High timeout ratio - mutation budget may be exceeded")
            return 3
    
    if summary.get("total", 0) == 0:
        print("No mutations were run")
        return 1
    
    print("✅ All mutations caught!")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Run mutation testing for TextForensics")
    parser.add_argument(
        "--mode",
        choices=["diff", "full", "safety-critical"],
        default="diff",
        help="Mutation mode"
    )
    parser.add_argument(
        "--base-sha",
        default="origin/main",
        help="Base SHA for diff mode"
    )
    parser.add_argument(
        "--config",
        default=".cosmic-ray.yml",
        help="Path to cosmic-ray config"
    )
    parser.add_argument(
        "--check-results",
        help="Check results from summary.json file"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout per test run (seconds)"
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=200,
        help="Maximum mutations per session"
    )
    
    args = parser.parse_args()
    
    # Handle check-results mode
    if args.check_results:
        return check_results(Path(args.check_results))
    
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 1
    
    # Define target modules (matching .cosmic-ray.yml)
    target_modules = [
        "textforensics.benchmark",
        "textforensics.trust",
        "textforensics.consensus",
        "textforensics.threshold_selection",
        "textforensics.detectors",
        "textforensics.analyzers",
        "textforensics.engine",
        "textforensics.capability_ledger",
        "textforensics.casefile",
        "textforensics.robustness",
    ]
    
    # Safety-critical modules (subset for deep mutation)
    safety_critical_modules = [
        "textforensics.benchmark",
        "textforensics.trust",
        "textforensics.consensus",
        "textforensics.threshold_selection",
    ]
    
    if args.mode == "diff":
        print(f"Running diff-based mutation against {args.base_sha}")
        modules = get_changed_modules(args.base_sha, target_modules)
        if not modules:
            print("No relevant modules changed - skipping mutation testing")
            # Write empty summary
            write_summary({"total": 0, "killed": 0, "surviving": 0, "timeout": 0, "error": 0, "skipped": 0}, Path("mutation-results"))
            return 0
        print(f"Mutating {len(modules)} changed modules: {', '.join(modules)}")
        
    elif args.mode == "full":
        print("Running full mutation testing on all target modules")
        modules = target_modules
        
    elif args.mode == "safety-critical":
        print("Running safety-critical deep mutation testing")
        modules = safety_critical_modules
        # Increase budget for safety-critical
        args.budget = 500
    
    # Run cosmic-ray
    session_name = f"textforensics-mutation-{args.mode}"
    exit_code, report = run_cosmic_ray(
        modules=modules,
        config_path=config_path,
        session_name=session_name,
        timeout=args.timeout,
        budget=args.budget,
    )
    
    # Parse and write results
    summary = parse_results(report)
    write_summary(summary, Path("mutation-results"))
    
    # Return appropriate exit code based on results
    if exit_code == 0:
        return check_results(Path("mutation-results/summary.json"))
    else:
        # Cosmic-ray itself failed
        return 1


if __name__ == "__main__":
    sys.exit(main())