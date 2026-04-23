#!/usr/bin/env python
# coding: utf-8

"""
SBOM Scanner Tool - Generates SBOMs and scans for vulnerabilities
"""
'''Added this'''
import uuid
from datetime import datetime
from version_monitor import get_latest_version

import io
import sys

# Set UTF-8 encoding for stdout/stderr on Windows to prevent encoding errors
if sys.platform == 'win32':
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if sys.stderr.encoding != 'utf-8':
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Import database storage module
try:
    from .db_storage import get_db_storage
except ImportError:
    # Handle case when running as script
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from db_storage import get_db_storage


'''added'''
import re

def normalize_version(version):

    if not version:
        return "unknown"

    # If version is a git commit hash (long hex)
    if re.fullmatch(r"[a-f0-9]{40}", version):
        return "unknown"

    # Remove leading 'v'
    version = version.lstrip("v")

    return version
'''till here'''

# ============================================================================
# Configuration
# ============================================================================
class Config:
    """Configuration - manages paths for tools and directories"""
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    TOOLS_DIR = Path(__file__).resolve().parent
    BASE_DIR = PROJECT_ROOT
    REPORTS_DIR = BASE_DIR / "reports"
    TEMP_DIR = BASE_DIR / "temp"
    REPO_CACHE_DIR = BASE_DIR / "repo-cache"

    '''Changes done'''
    SYFT_PATH = Path(shutil.which("syft") or "syft")
    GRYPE_PATH = Path(shutil.which("grype") or "grype")

    '''
    SYFT_PATH = Path(
        os.environ.get("SYFT_PATH", TOOLS_DIR / "syft" / ("syft.exe" if os.name == "nt" else "syft"))
    )
    GRYPE_PATH = Path(
        os.environ.get("GRYPE_PATH", TOOLS_DIR / "grype" / ("grype.exe" if os.name == "nt" else "grype"))
    )
    '''

    @classmethod
    def init_directories(cls):
        """Create necessary directories"""
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[ok] Directories initialized at {cls.BASE_DIR}")


# ============================================================================
# Helper Functions
# ============================================================================
def is_github_repo(url: str) -> bool:
    """Check if URL is a valid GitHub repository"""
    if not isinstance(url, str):
        return False
    
    u = urlparse(url.strip())
    if u.netloc not in {"github.com", "www.github.com"}:
        return False
    
    parts = [p for p in u.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return False
    
    excluded_paths = {"topics", "explore", "trending", "stars", "collections", 
                      "events", "sponsors", "marketplace", "pricing", "login",
                      "signup", "settings", "notifications", "search", "about"}
    
    if parts[0] in excluded_paths:
        return False
    
    return True


def generate_safe_filename(target: str, is_github: bool) -> str:
    """Generate a safe filename from target URL or path"""
    if is_github:
        parts = target.rstrip('/').split('/')
        github_parts = [p for p in parts if p and p not in ['http:', 'https:', 'github.com', 'www.github.com']]
        if len(github_parts) >= 2:
            owner = github_parts[-2]
            repo = github_parts[-1].replace('.git', '')
            filename = f"{owner}-{repo}"
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"scan-{timestamp}"
    else:
        path_obj = Path(target)
        if path_obj.exists():
            filename = path_obj.name if path_obj.is_dir() else path_obj.stem
        else:
            filename = target.replace('\\', '-').replace('/', '-').replace(':', '-')
    
    filename = re.sub(r'[<>:"/\\|?*]', '-', filename)
    filename = re.sub(r'\s+', '-', filename).strip('.-')
    return filename[:200] if len(filename) > 200 else filename or f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


# ============================================================================
# SBOM Scanner Class
# ============================================================================
class SBOMScanner:
    """Main SBOM Scanner - handles scanning and report generation"""

    def __init__(self, use_cache: bool = False, shallow_clone: bool = True, skip_vuln: bool = False):
        """Initialize scanner"""
        self.git_command = self._resolve_git_command()
        self.syft_path = Config.SYFT_PATH
        self.grype_path = Config.GRYPE_PATH
        self.use_cache = use_cache
        self.shallow_clone = shallow_clone
        self.skip_vuln = skip_vuln

        if not Path(self.syft_path).exists():
            raise FileNotFoundError(f"Syft not found at {self.syft_path}")
        if not self.skip_vuln and not Path(self.grype_path).exists():
            raise FileNotFoundError(f"Grype not found at {self.grype_path}")

    @staticmethod
    def _resolve_git_command() -> List[str]:
        """Find Git executable"""
        git_path = shutil.which("git")
        if git_path:
            return [git_path]

        fallback_paths = [
            Path("C:/Program Files/Git/cmd/git.exe"),
            Path("C:/Program Files/Git/bin/git.exe"),
            Path("C:/Program Files (x86)/Git/cmd/git.exe"),
            Path("C:/Program Files (x86)/Git/bin/git.exe"),
        ]

        for path in fallback_paths:
            if path.exists():
                return [str(path)]

        raise FileNotFoundError("Git executable not found. Install Git or add it to PATH.")

    def _clone_repo(self, repo_url: str, destination: Path):
        """Clone repository to destination with retry logic for rate limits"""
        import time
        
        clone_cmd = [*self.git_command, "clone"]
        if self.shallow_clone:
            clone_cmd.extend(["--depth", "1", "--single-branch", "--filter=blob:none"])
        clone_cmd.extend([repo_url, str(destination)])

        print(f"  -> Cloning repository ({'shallow' if self.shallow_clone else 'full'} clone)...")
        
        # Try cloning with retry for rate limits
        max_retries = 2
        for attempt in range(max_retries + 1):
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=900  # Reduced from 600 to 300 seconds (5 minutes)
            )

            if result.returncode == 0:
                return  # Success!

            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            
            # Check for rate limiting (403)
            if ("403" in error_msg or "forbidden" in error_msg.lower()) and attempt < max_retries:
                wait_time = (attempt + 1) * 10  # Wait 10, 20 seconds
                print(f"  -> GitHub rate limit detected. Waiting {wait_time} seconds before retry {attempt + 1}/{max_retries}...")
                time.sleep(wait_time)
                continue
            
            # Handle different error types
            if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                raise RuntimeError(f"Repository not found: {repo_url}. Please check that the repository exists and is accessible.")
            elif "403" in error_msg or "forbidden" in error_msg.lower():
                raise RuntimeError(
                    f"GitHub returned 403 Forbidden for {repo_url}.\n"
                    f"This usually means GitHub rate limiting (too many requests).\n"
                    f"Solutions:\n"
                    f"  - Wait 5-10 minutes and try again\n"
                    f"  - Enable 'Use cache' option if you've scanned this repo before\n"
                    f"  - Try a different repository\n"
                    f"Error details: {error_msg}"
                )
            elif "authentication" in error_msg.lower() or "permission" in error_msg.lower():
                raise RuntimeError(f"Authentication failed for {repo_url}. The repository may be private or require authentication.")
            else:
                raise RuntimeError(f"Failed to clone repository {repo_url}: {error_msg}")

    def _update_repo(self, repo_path: Path):
        """Update cached repository to latest version"""
        print("  -> Updating cached repository...")
        if self.shallow_clone:
            fetch_cmd = [*self.git_command, "-C", str(repo_path), "fetch", "--depth", "1", "origin"]
            reset_cmd = [*self.git_command, "-C", str(repo_path), "reset", "--hard", "FETCH_HEAD"]
            commands = [fetch_cmd, reset_cmd]
        else:
            commands = [
                [*self.git_command, "-C", str(repo_path), "pull", "--rebase"]
            ]

        for cmd in commands:
            lock_file = repo_path / ".git" / "index.lock"
            if lock_file.exists():
                try:
                    lock_file.unlink()
                except OSError as exc:
                    raise RuntimeError(f"Failed to remove stale git lock: {exc}") from exc

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # Reduced from 300 to 180 seconds (3 minutes)
            )
            if result.returncode == 0:
                continue

            stderr = result.stderr or ""
            if "index.lock" in stderr:
                lock_file = repo_path / ".git" / "index.lock"
                if lock_file.exists():
                    try:
                        lock_file.unlink()
                    except OSError as exc:
                        raise RuntimeError(f"Failed to remove git lock: {exc}") from exc
                    retry = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=900
                    )
                    if retry.returncode == 0:
                        continue
                    stderr = retry.stderr or stderr

            raise RuntimeError(f"Failed to update repository: {stderr}")

    def _clone_and_scan_github(self, owner: str, repo: str) -> Tuple[str, str, bool]:
        """Prepare GitHub repo for scanning - returns (path, identifier, cleanup_needed)"""
        repo_url = f"https://github.com/{owner}/{repo}.git"

        if self.use_cache:
            cache_path = Config.REPO_CACHE_DIR / f"{owner}-{repo}"
            if cache_path.exists():
                try:
                    self._update_repo(cache_path)
                except RuntimeError as err:
                    print(f"  -> Cache update failed ({err}); recloning cache...")
                    shutil.rmtree(cache_path, ignore_errors=True)
                    self._clone_repo(repo_url, cache_path)
            else:
                self._clone_repo(repo_url, cache_path)
            return str(cache_path), f"{owner}/{repo}", False

        temp_repo_path = Config.TEMP_DIR / f"{owner}-{repo}-{uuid.uuid4().hex[:8]}"
        self._clone_repo(repo_url, temp_repo_path)
        return str(temp_repo_path), f"{owner}/{repo}", True

    def scan(self, target: str) -> Optional[str]:
        """Main scan method"""
        cleanup_path: Optional[Path] = None
        is_github_target = is_github_repo(target)
        try:
            if is_github_target:
                parts = target.rstrip('/').split('/')
                github_parts = [p for p in parts if p and p not in ['http:', 'https:', 'github.com', 'www.github.com']]
                
                if len(github_parts) < 2:
                    raise ValueError(f"Invalid GitHub repository URL: {target}. Expected format: https://github.com/owner/repo")
                
                owner = github_parts[-2]
                repo = github_parts[-1].replace('.git', '')

                repo_path, scan_target, cleanup_needed = self._clone_and_scan_github(owner, repo)
                if cleanup_needed:
                    cleanup_path = Path(repo_path)
                print(f"  -> Scanning repository: {scan_target}")
            else:
                if 'github.com' in target.lower():
                    raise ValueError(f"Invalid GitHub URL: {target}. This appears to be a GitHub page (topics, explore, etc.) but not a repository. Please use a repository URL like: https://github.com/owner/repo")
                scan_target = target
                repo_path = scan_target

            filename = generate_safe_filename(target, is_github_target)
            scan_id = filename

            print(f"\n{'='*60}")
            print(f"Scanning: {target}")
            print(f"{'='*60}\n")
            
            total_start = time.time()

            print("[1/3] Generating SBOM...")
            print("      Please wait, scanning in progress...")
            sys.stdout.flush()  # Force output to be visible immediately
            step_start = time.time()
            sbom_data = self._generate_sbom(repo_path if is_github_target else scan_target)
            elapsed = time.time() - step_start
            print(f"      [OK] SBOM generation completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)\n")

            if self.skip_vuln:
                print("[2/3] Skipping vulnerability scan (--skip-vuln enabled)")
                vuln_data = {"matches": []}
            else:
                print("[2/3] Scanning vulnerabilities...")
                print("      Please wait, scanning in progress...")
                print("      This may take 10-30 minutes for large repositories...")
                sys.stdout.flush()  # Force output to be visible immediately
                step_start = time.time()
                vuln_data = self._scan_vulnerabilities(repo_path if is_github_target else scan_target)
                elapsed = time.time() - step_start
                print(f"      [OK] Vulnerability scan completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)\n")

            print("[3/3] Creating reports...")
            step_start = time.time()
            report_data = self._create_report(scan_id, target, sbom_data, vuln_data)

            # ============================
            # SAVE TO NEW NORMALIZED DATABASE (sbom_common)
            # ============================

            try:
                db = get_db_storage()

                # Insert scan record
                #scan_db_id = db.insert_scan(target)
                scan_db_id = db.insert_scan(target)
                
                if not scan_db_id:
                    raise Exception("Failed to create scan record")

                for pkg in report_data.get("packages", []):

                    package_name = pkg.get("package")
                    #package_version = pkg.get("version")
                    package_version = normalize_version(pkg.get("version"))
                    package_type = pkg.get("type")

                    # Normalize ecosystem type
                    if package_type in ["python", "pypi"]:
                        ecosystem = "python"
                    elif package_type in ["npm", "node"]:
                        ecosystem = "npm"
                    elif package_type == "github-action":
                        ecosystem = "github-action"
                    else:
                        ecosystem = "unknown"

                    # Insert package if not exists
                    #package_id = db.insert_package(package_name, package_type)
                    package_id = db.insert_package(package_name, ecosystem)

                    # Insert version
                    # Check external latest version (PyPI / GitHub)
                    #external_latest = get_latest_version(package_name, package_type)
                    api_latest = get_latest_version(package_name, ecosystem)

                    '''
                    grype_fix = None
                    if pkg_vulns:
                        fix_versions = pkg_vulns[0].get("vulnerability", {}).get("fix", {}).get("versions", [])
                        if fix_versions:
                            grype_fix = fix_versions[0]
                    '''

                    external_latest = api_latest or package_version

                    if external_latest is None:
                        status = "unknown"
                    elif external_latest == package_version:
                        status = "up_to_date"
                    else:
                        status = "outdated"

                    # Insert version only once
                    #version_id = db.insert_version(package_id, package_version, status=status)
                    version_id = db.insert_version(
                        scan_db_id,
                        package_id,
                        package_name,        # ✅ FIXED
                        package_version,     # ✅ FIXED
                        status=status,
                        latest_version=external_latest,
                        baseline_status="active"
                    )

                    # Insert vulnerability if exists
                    vulnerability_id = pkg.get("vulnerability_id")
                    severity = (pkg.get("severity") or "none").lower()
                    fixed_version = pkg.get("fixed_version")

                    if vulnerability_id and vulnerability_id != "None":
                        db.insert_vulnerability(vulnerability_id, severity)

                        db.insert_scan_result(
                            scan_db_id,
                            version_id,
                            vulnerability_id,
                            fixed_version
                        )

                print("      [OK] Data saved to sbom_common database")
                
            except Exception as e:
                print("      [ERROR] Database insert failed:", e)

            # Show vulnerability summary
            total_vulns = report_data.get('summary', {}).get('total_vulnerabilities', 0)
            if total_vulns > 0:
                print(f"      Found {total_vulns} vulnerabilities:")
                print(f"        - Critical: {report_data.get('summary', {}).get('critical', 0)}")
                print(f"        - High: {report_data.get('summary', {}).get('high', 0)}")
                print(f"        - Medium: {report_data.get('summary', {}).get('medium', 0)}")
                print(f"        - Low: {report_data.get('summary', {}).get('low', 0)}")
            else:
                print(f"      No vulnerabilities found - all packages are secure!")
            
            self._save_json_report(scan_id, report_data)
            self._save_csv_report(scan_id, report_data)
            elapsed = time.time() - step_start
            print(f"      [OK] Reports created in {elapsed:.1f} seconds\n")
            
            '''
            # Automatically save to MySQL database
            print("[4/4] Saving to database...")
            table_name = None
            database_message = ""
            try:
                db_storage = get_db_storage()
                print(f"      Attempting to save report '{scan_id}' to database...")
                success, table_name = db_storage.store_report(report_data)
                if success:
                    if table_name:
                        database_message = f"Report saved to database table: {table_name}"
                        print(f"      [OK] Report saved to database successfully! Table: {table_name}\n")
                        # Add table name and message to report data for UI display
                        report_data['database_table'] = table_name
                        report_data['database_message'] = database_message
                    else:
                        database_message = "Report saved to database successfully"
                        print(f"      [OK] Report saved to database successfully!\n")
                        report_data['database_message'] = database_message
                else:
                    database_message = "Failed to save report to database (check server console for details)"
                    print(f"      [ERROR] Report NOT saved to database (check error messages above)\n")
                    report_data['database_message'] = database_message
            except Exception as e:
                database_message = f"Database error: {str(e)}"
                print(f"      [ERROR] Could not save to database: {e}")
                import traceback
                traceback.print_exc()
                print()
                report_data['database_message'] = database_message
            '''
            # Optimize: Only build dependency graph if it's small (< 1000 edges)
            if len(report_data.get("dependency_graph", [])) > 1000:
                print(f"      [info] Large dependency graph ({len(report_data['dependency_graph'])} edges) - processing optimized\n")

            total_time = time.time() - total_start
            print(f"{'='*60}")
            print(f"Scan completed successfully!")
            print(f"Total time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
            print(f"Reports saved:")
            print(f"   - {Config.REPORTS_DIR / scan_id}.json")
            print(f"   - {Config.REPORTS_DIR / scan_id}.csv")
            print(f"   - MySQL database (sbom_common)")
            print(f"{'='*60}\n")

            return scan_id

        except Exception as e:
            print(f"\nScan failed: {str(e)}\n")
            raise

        finally:
            if cleanup_path and cleanup_path.exists():
                try:
                    shutil.rmtree(cleanup_path)
                    print(f"  -> Cleaned up temporary files")
                except Exception as e:
                    print(f"  !! Warning: Could not remove temp directory: {e}")

    def _generate_sbom(self, target: str) -> dict:
        """Generate SBOM using Syft with optimizations for speed"""
        target_path_obj = Path(target)
        if target_path_obj.exists():
            target_path = target_path_obj.resolve()
            syft_target = f"dir:{target_path}" if target_path.is_dir() else str(target_path)
        else:
            syft_target = target
        
        # Show progress indicator
        import sys
        sys.stdout.write("      Running Syft (optimized)... ")
        sys.stdout.flush()
        
        # Use optimized Syft command for faster scanning
        # Syft will automatically skip .git and other non-essential files
        result = subprocess.run(
            [self.syft_path, syft_target, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=600  # Reduced from 1200 to 600 seconds (10 minutes) for speed
        )

        if result.returncode != 0:
            error_msg = (result.stderr or "").strip() or (result.stdout or "").strip() or "Unknown error"
            raise RuntimeError(f"SBOM generation failed: {error_msg}")

        if not result.stdout:
            raise RuntimeError(f"SBOM generation produced no output. stderr: {result.stderr or 'None'}")

        try:
            data = json.loads(result.stdout)
            sys.stdout.write("[OK]\n")
            sys.stdout.flush()
            return data
        except json.JSONDecodeError as e:
            output_preview = (result.stdout or "")[:500] if result.stdout else "No output"
            raise RuntimeError(f"Failed to parse SBOM JSON output: {e}\nOutput: {output_preview}")

    def _scan_vulnerabilities(self, target: str) -> dict:
        """Scan vulnerabilities using Grype (optimized for speed)"""
        target_path_obj = Path(target)
        if target_path_obj.exists():
            target_path = target_path_obj.resolve()
            grype_target = f"dir:{target_path}" if target_path.is_dir() else str(target_path)
        else:
            grype_target = target
        
        # Show progress indicator
        import sys
        sys.stdout.write("      Running Grype (optimized)... ")
        sys.stdout.flush()
        
        # Optimize Grype command for faster scanning
        # Use default scope (squashed) for faster scanning - shows vulnerabilities in final image
        grype_cmd = [
            self.grype_path,
            grype_target,
            "-o", "json",
        ]
        
        result = subprocess.run(
            grype_cmd,
            capture_output=True,
            text=True,
            timeout=1200  # Reduced from 1800 to 1200 seconds (20 minutes) for speed
        )

        if result.returncode not in [0, 1]:
            error_msg = (result.stderr or "").strip() or (result.stdout or "").strip() or "Unknown error"
            raise RuntimeError(f"Vulnerability scan failed: {error_msg}")

        if not result.stdout:
            raise RuntimeError(f"Vulnerability scan produced no output. stderr: {result.stderr or 'None'}")

        try:
            data = json.loads(result.stdout)
            sys.stdout.write("[OK]\n")
            sys.stdout.flush()
            return data
        except json.JSONDecodeError as e:
            output_preview = (result.stdout or "")[:500] if result.stdout else "No output"
            raise RuntimeError(f"Failed to parse vulnerability JSON output: {e}\nOutput: {output_preview}")

    def _create_report(self, scan_id: str, target: str, sbom_data: dict, vuln_data: dict) -> dict:
        """Create structured report data"""

        from version_monitor import get_latest_version, compare_versions

        packages = sbom_data.get("artifacts", [])
        vulnerabilities = vuln_data.get("matches", [])

        artifact_lookup = {
            pkg.get("id"): pkg for pkg in packages if pkg.get("id")
        }

        
        packages = sbom_data.get("artifacts", [])
        vulnerabilities = vuln_data.get("matches", [])

        # ===============================
        # REMOVE DUPLICATES + MAP VULNS
        # ===============================

        unique_packages = {}
        detailed_packages = []

        # Build vulnerability map (name + version)
        vuln_map = {}

        for vuln in vulnerabilities:
            artifact = vuln.get("artifact", {})
            v_name = artifact.get("name")
            v_version = artifact.get("version")

            key = f"{v_name}:{v_version}"
            vuln_map.setdefault(key, []).append(vuln)

        for pkg in packages:

            pkg_name = pkg.get("name", "unknown")
            pkg_version = normalize_version(pkg.get("version"))
            pkg_type = pkg.get("type", "unknown")

            key = f"{pkg_name}:{pkg_version}"

            if key in unique_packages:
                continue

            pkg_vulns = vuln_map.get(key, [])

            external_latest = normalize_version(get_latest_version(pkg_name, pkg_type))
            if not external_latest:
                external_latest = pkg_version

            version_status = compare_versions(pkg_version, external_latest)

            if pkg_vulns:
                highest_severity = "None"

                severity_rank = {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                    "negligible": 0
                }

                for v in pkg_vulns:
                    sev = v.get("vulnerability", {}).get("severity", "None").lower()
                    if severity_rank.get(sev, 0) > severity_rank.get(highest_severity.lower(), 0):
                        highest_severity = sev

                detailed_packages.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "type": pkg_type,
                    "vulnerability_id": pkg_vulns[0].get("vulnerability", {}).get("id"),
                    "severity": highest_severity.capitalize(),
                    "fixed_version": "See advisory",
                    "latest_version": external_latest,
                    "version_status": version_status
                })

            else:
                detailed_packages.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "type": pkg_type,
                    "vulnerability_id": "None",
                    "severity": "None",
                    "fixed_version": "N/A",
                    "latest_version": external_latest,
                    "version_status": version_status
                })

            unique_packages[key] = True
        
        # -------------------------------
        # SEVERITY SUMMARY
        # -------------------------------

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get("vulnerability", {}).get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        

        # ===============================
        # BUILD DEPENDENCY GRAPH
        # ===============================

        dependency_graph = []

        # Get root component (main project)
        root_component = sbom_data.get("metadata", {}).get("component", {})
        root_name = root_component.get("name")

        # Fallback if metadata.component not found
        if not root_name:
            root_name = scan_id

        # Create simple parent → child tree
        for pkg in detailed_packages:
            pkg_name = pkg.get("package")
            if pkg_name and pkg_name != root_name:
                dependency_graph.append({
                    "type": "DIRECT_DEPENDENCY",
                    "parent": root_name,
                    "child": pkg_name
                })

        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "summary": {
                "total_packages": len(detailed_packages),
                "total_vulnerabilities": len(vulnerabilities),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "negligible": severity_counts["negligible"]
            },
            "packages": detailed_packages,
            "dependency_graph": dependency_graph
        }

    def _save_json_report(self, scan_id: str, report_data: dict):
        """Save report as JSON"""
        json_path = Config.REPORTS_DIR / f"{scan_id}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

    def _save_csv_report(self, scan_id: str, report_data: dict):
        """Save report as CSV"""
        csv_path = Config.REPORTS_DIR / f"{scan_id}.csv"

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            '''
            fieldnames = [
                'scan_id',
                'target',
                'timestamp',
                'package',
                'version',
                'type',
                'vulnerability_id',
                'severity',
                'fixed_version',
            ]
            '''
            '''Changes made'''
            fieldnames = [
                'scan_id',
                'target',
                'timestamp',
                'package',
                'version',
                'type',
                'vulnerability_id',
                'severity',
                'fixed_version',
                'latest_version',
                'version_status'
            ]

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for pkg in report_data['packages']:
                row = dict(pkg)
                row['scan_id'] = report_data.get('scan_id')
                row['target'] = report_data.get('target')
                row['timestamp'] = report_data.get('timestamp')
                writer.writerow(row)

    def get_report(self, scan_id: str) -> Optional[dict]:
        """Get report by scan_id"""
        json_path = Config.REPORTS_DIR / f"{scan_id}.json"

        if not json_path.exists():
            print(f"Report not found: {scan_id}")
            return None

        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def list_reports(self) -> List[str]:
        """List all available reports"""
        reports = [f.stem for f in Config.REPORTS_DIR.glob("*.json")]
        return sorted(reports, reverse=True)


# ============================================================================
# Utility Functions
# ============================================================================
def print_report_summary(report: Dict[str, Any]):
    """Print a formatted summary of the scan report"""
    print("\n" + "="*60)
    print("REPORT SUMMARY")
    print("="*60)

    print(f"\nScan ID: {report['scan_id']}")
    print(f"Target: {report['target']}")
    print(f"Timestamp: {report['timestamp']}")
    print(f"\nSummary:")
    print(f"  - Total Packages: {report['summary']['total_packages']}")
    print(f"  - Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
    print(f"  - Critical: {report['summary']['critical']}")
    print(f"  - High: {report['summary']['high']}")
    print(f"  - Medium: {report['summary']['medium']}")
    print(f"  - Low: {report['summary']['low']}")

    if report.get('dependency_graph'):
        print(f"\nFirst 5 dependency edges:")
        for edge in report['dependency_graph'][:5]:
            print(f"  - {edge['parent']} -> {edge['child']} ({edge['type']})")

    print(f"\nFirst 5 packages with vulnerabilities:")
    for pkg in report['packages'][:5]:
        if pkg.get('vulnerability_id') != "None":
            print(f"  - {pkg['package']} ({pkg['version']}) - {pkg['severity']} - Fixed: {pkg['fixed_version']}")


# ============================================================================
# CLI Entrypoint
# ============================================================================
def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Generate SBOM and vulnerability reports for a given target."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Local path or GitHub repository URL to scan.",
    )
    parser.add_argument(
        "--cache",
        dest="use_cache",
        action="store_true",
        default=False,
        help="Enable repository caching (reuse local clone between scans).",
    )
    parser.add_argument(
        "--full-clone",
        action="store_true",
        help="Clone repositories with full history instead of a shallow clone.",
    )
    parser.add_argument(
        "--list-reports",
        action="store_true",
        help="List existing reports and exit without running a new scan.",
    )
    parser.add_argument(
        "--report-id",
        help="Show a previously generated report by scan ID (skips new scan).",
    )
    parser.add_argument(
        "--skip-vuln",
        dest="skip_vuln",
        action="store_true",
        help="Skip vulnerability scanning (faster, only generates SBOM).",
    )
    return parser.parse_args()


def main():
    """Main entry point for CLI"""
    args = parse_args()

    Config.init_directories()

    scanner = SBOMScanner(
        use_cache=args.use_cache,
        shallow_clone=not args.full_clone,
        skip_vuln=args.skip_vuln,
    )
    print("[ok] SBOM Scanner ready!")
    if args.skip_vuln:
        print("[info] Vulnerability scanning is disabled (SBOM only - faster)")
    else:
        print("[info] Full scan enabled: SBOM + Vulnerability scanning")
    if args.use_cache:
        print("[info] Repository caching is enabled")
    print(f"[ok] Reports will be saved to: {Config.REPORTS_DIR}\n")

    if args.list_reports:
        print("=" * 60)
        print("AVAILABLE REPORTS")
        print("=" * 60)
        for report_id in scanner.list_reports():
            print(f"  - {report_id}")
        return

    if args.report_id:
        report = scanner.get_report(args.report_id)
        if not report:
            print(f"Report '{args.report_id}' not found.")
            sys.exit(1)
        print_report_summary(report)
        return

    if not args.target:
        print("Target repository or path is required.")
        sys.exit(1)

    scan_id = scanner.scan(args.target)

    if not scan_id:
        sys.exit(1)

    report = scanner.get_report(scan_id)
    if report:
        print_report_summary(report)

    print("\n" + "="*60)
    print("AVAILABLE REPORTS")
    print("=" * 60)
    for report_id in scanner.list_reports():
        print(f"  - {report_id}")


if __name__ == "__main__":
    main()
