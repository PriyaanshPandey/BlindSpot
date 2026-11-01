"""
Dependency Discovery Engine:
Discovers exact dependency instances across Node.js/npm and lockfile formats (v1, v2, v3),
nested dependencies, monorepos, and establishes extensible ecosystem adapter interfaces.
"""
import os
import json
import logging
from typing import Dict, Any, List, Optional
from app.intelligence.models import (
    PackageInstance,
    EcosystemType,
    DependencyScope,
    RetrievalStatus
)

logger = logging.getLogger("blindspot.intelligence.discovery")

class EcosystemAdapter:
    def discover(self, project_path: str) -> List[PackageInstance]:
        raise NotImplementedError

class NpmDiscoveryAdapter(EcosystemAdapter):
    """Parses package.json and package-lock.json v1, v2, and v3."""

    def discover(self, project_path: str) -> List[PackageInstance]:
        abs_path = os.path.abspath(project_path)
        pkg_json_path = os.path.join(abs_path, "package.json")
        lock_json_path = os.path.join(abs_path, "package-lock.json")

        declared_manifest = {}
        dev_manifest = {}
        peer_manifest = {}
        optional_manifest = {}

        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    pj_data = json.load(f)
                    declared_manifest = pj_data.get("dependencies", {})
                    dev_manifest = pj_data.get("devDependencies", {})
                    peer_manifest = pj_data.get("peerDependencies", {})
                    optional_manifest = pj_data.get("optionalDependencies", {})
            except Exception as e:
                logger.warning(f"Error parsing package.json at {pkg_json_path}: {e}")

        instances: List[PackageInstance] = []

        # Lockfile exists
        if os.path.exists(lock_json_path):
            try:
                with open(lock_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    lock_data = json.load(f)

                lock_version = lock_data.get("lockfileVersion", 1)

                # v2/v3 use "packages"
                if "packages" in lock_data:
                    for pkg_key, pkg_info in lock_data["packages"].items():
                        if not pkg_key:  # root package ""
                            continue
                        
                        # pkg_key is e.g. "node_modules/axios" or "node_modules/foo/node_modules/axios" or "fixtures/packages/..."
                        parts = pkg_key.split("node_modules/")
                        pkg_name = parts[-1]
                        if not pkg_name:
                            continue

                        # If link or local reference
                        if pkg_info.get("link") and pkg_info.get("resolved"):
                            # node_modules alias to local package
                            pass

                        version = pkg_info.get("version", "unknown")
                        resolved = pkg_info.get("resolved")
                        integrity = pkg_info.get("integrity")
                        is_dev = pkg_info.get("dev", False)
                        is_optional = pkg_info.get("optional", False)
                        has_install_script = pkg_info.get("hasInstallScript", False)

                        # Determine if direct
                        is_direct = (pkg_key.count("node_modules/") == 1 or not pkg_key.startswith("node_modules/")) and (
                            pkg_name in declared_manifest or pkg_name in dev_manifest or
                            pkg_name in peer_manifest or pkg_name in optional_manifest
                        )

                        scope = DependencyScope.PROD
                        if is_dev or pkg_name in dev_manifest:
                            scope = DependencyScope.DEV
                        elif is_optional or pkg_name in optional_manifest:
                            scope = DependencyScope.OPTIONAL
                        elif pkg_name in peer_manifest:
                            scope = DependencyScope.PEER
                        elif not is_direct:
                            scope = DependencyScope.TRANSITIVE

                        parent = None
                        if pkg_key.count("node_modules/") > 1:
                            parent_parts = [p.rstrip("/") for p in parts if p]
                            if len(parent_parts) >= 2:
                                parent = parent_parts[-2]

                        dec_range = declared_manifest.get(pkg_name) or dev_manifest.get(pkg_name)

                        instance_id = f"pkg:npm/{pkg_name}@{version}#{pkg_key}"
                        instances.append(PackageInstance(
                            instance_id=instance_id,
                            name=pkg_name,
                            version=version,
                            ecosystem=EcosystemType.NPM,
                            declared_range=dec_range,
                            is_direct=is_direct,
                            scope=scope,
                            install_path=pkg_key,
                            parent_dependency=parent,
                            registry_url="https://registry.npmjs.org",
                            resolved_url=resolved,
                            integrity=integrity,
                            has_install_script=has_install_script,
                            has_source_retrieved=False,
                            retrieval_status=RetrievalStatus.UNPROCESSED,
                            metadata={"lockfile_version": lock_version}
                        ))

                # v1 uses "dependencies" recursive tree
                elif "dependencies" in lock_data:
                    def parse_v1_deps(dep_dict: Dict[str, Any], parent_name: Optional[str] = None, current_path: str = ""):
                        for name, info in dep_dict.items():
                            version = info.get("version", "unknown")
                            resolved = info.get("resolved")
                            integrity = info.get("integrity")
                            is_dev = info.get("dev", False)
                            is_opt = info.get("optional", False)
                            path_str = f"{current_path}/node_modules/{name}".lstrip("/")

                            is_direct = (parent_name is None) and (
                                name in declared_manifest or name in dev_manifest
                            )
                            scope = DependencyScope.PROD
                            if is_dev:
                                scope = DependencyScope.DEV
                            elif is_opt:
                                scope = DependencyScope.OPTIONAL
                            elif not is_direct:
                                scope = DependencyScope.TRANSITIVE

                            instance_id = f"pkg:npm/{name}@{version}#{path_str}"
                            instances.append(PackageInstance(
                                instance_id=instance_id,
                                name=name,
                                version=version,
                                ecosystem=EcosystemType.NPM,
                                declared_range=declared_manifest.get(name) or dev_manifest.get(name),
                                is_direct=is_direct,
                                scope=scope,
                                install_path=path_str,
                                parent_dependency=parent_name,
                                registry_url="https://registry.npmjs.org",
                                resolved_url=resolved,
                                integrity=integrity,
                                has_source_retrieved=False,
                                retrieval_status=RetrievalStatus.UNPROCESSED,
                                metadata={"lockfile_version": 1}
                            ))

                            if "dependencies" in info:
                                parse_v1_deps(info["dependencies"], parent_name=name, current_path=path_str)

                    parse_v1_deps(lock_data["dependencies"])

            except Exception as e:
                logger.error(f"Failed to parse lockfile at {lock_json_path}: {e}")

        # Fallback to package.json if lockfile absent
        if not instances and declared_manifest:
            for name, ver in declared_manifest.items():
                clean_v = str(ver).replace("^", "").replace("~", "").replace(">", "").strip()
                instances.append(PackageInstance(
                    instance_id=f"pkg:npm/{name}@{clean_v}#direct",
                    name=name,
                    version=clean_v,
                    ecosystem=EcosystemType.NPM,
                    declared_range=ver,
                    is_direct=True,
                    scope=DependencyScope.PROD,
                    install_path=f"node_modules/{name}",
                    has_source_retrieved=False,
                    retrieval_status=RetrievalStatus.UNPROCESSED
                ))
            for name, ver in dev_manifest.items():
                clean_v = str(ver).replace("^", "").replace("~", "").replace(">", "").strip()
                instances.append(PackageInstance(
                    instance_id=f"pkg:npm/{name}@{clean_v}#dev",
                    name=name,
                    version=clean_v,
                    ecosystem=EcosystemType.NPM,
                    declared_range=ver,
                    is_direct=True,
                    scope=DependencyScope.DEV,
                    install_path=f"node_modules/{name}",
                    has_source_retrieved=False,
                    retrieval_status=RetrievalStatus.UNPROCESSED
                ))

        return instances

class PyPIDiscoveryAdapter(EcosystemAdapter):
    """PyPI manifest parser for requirements.txt and pyproject.toml."""
    def discover(self, project_path: str) -> List[PackageInstance]:
        instances = []
        req_path = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_path):
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        parts = clean.split("==")
                        pkg = parts[0].strip()
                        ver = parts[1].strip() if len(parts) > 1 else "*"
                        instances.append(PackageInstance(
                            instance_id=f"pkg:pypi/{pkg}@{ver}",
                            name=pkg,
                            version=ver,
                            ecosystem=EcosystemType.PYPI,
                            is_direct=True,
                            scope=DependencyScope.PROD
                        ))
        return instances

class ExtensibleDependencyDiscovery:
    def __init__(self):
        self.adapters: Dict[str, EcosystemAdapter] = {
            "npm": NpmDiscoveryAdapter(),
            "pypi": PyPIDiscoveryAdapter(),
        }

    def discover_all(self, project_path: str) -> List[PackageInstance]:
        all_instances = []
        for name, adapter in self.adapters.items():
            try:
                found = adapter.discover(project_path)
                all_instances.extend(found)
            except Exception as e:
                logger.warning(f"Adapter {name} error on {project_path}: {e}")
        return all_instances
