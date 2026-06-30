"""
ARNIE Cluster Vision — read-only OpenShift/Kubernetes awareness.

This is ARNIE's "eyes." It connects to a cluster with a READ-ONLY service account
token and lets ARNIE observe live state — what operators are installed, which CRDs
exist, what namespaces and storage classes are available, the status of resources —
so generation is grounded in reality and ARNIE can answer questions about the cluster.

══════════════════════════════════════════════════════════════════════════════
GUARDRAIL — READ-ONLY BY CONSTRUCTION
══════════════════════════════════════════════════════════════════════════════
This module issues ONLY HTTP GET requests. There is no method here that performs
POST, PUT, PATCH, or DELETE. ARNIE cannot mutate the cluster through this client —
not by policy, but by construction. All cluster CHANGES flow exclusively through the
governed AAP pipeline with human approval. The observation layer and the action layer
are separate, and only the action layer can write.

The connection should use a service account bound to the read-only 'view' ClusterRole:

    oc create serviceaccount arnie-viewer -n default
    oc adm policy add-cluster-role-to-user view -z arnie-viewer -n default
    oc create token arnie-viewer -n default --duration=87600h

Even if this code were changed to attempt a write, the 'view' role would deny it at
the API server. Defense in depth: read-only client + read-only RBAC.

Built on the RMCP engine by BLCKBX.
"""

import logging
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("arnie.cluster-vision")


class ClusterVisionError(Exception):
    """Raised when a read query against the cluster fails."""


class ClusterVision:
    """Read-only window into an OpenShift/Kubernetes cluster.

    Every public method performs GET-only requests. Construction with no token
    yields a disconnected client whose `connected` is False; callers should check
    `is_connected()` (or handle ClusterVisionError) before relying on results.
    """

    def __init__(
        self,
        api_url: str = "",
        token: str = "",
        verify_ssl: bool = False,
        timeout: float = 15.0,
    ):
        self.api_url = (api_url or "").rstrip("/")
        self._token = (token or "").strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # ── connection ──

    def configure(self, api_url: str, token: str, verify_ssl: bool = False) -> None:
        """Update connection settings (e.g. from saved settings)."""
        self.api_url = (api_url or "").rstrip("/")
        self._token = (token or "").strip()
        self.verify_ssl = verify_ssl

    def is_configured(self) -> bool:
        return bool(self.api_url and self._token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Issue a single GET against the cluster API. The ONLY request primitive
        in this module — there is deliberately no _post/_patch/_delete."""
        if not self.is_configured():
            raise ClusterVisionError("Cluster vision is not configured (missing API URL or token).")
        url = f"{self.api_url}{path}"
        try:
            resp = httpx.get(
                url,
                headers=self._headers(),
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except httpx.HTTPError as e:
            raise ClusterVisionError(f"Cluster request failed: {e}") from e
        if resp.status_code == 401:
            raise ClusterVisionError("Unauthorized — the cluster token is invalid or expired.")
        if resp.status_code == 403:
            raise ClusterVisionError("Forbidden — the service account lacks read access for this resource.")
        if resp.status_code >= 400:
            raise ClusterVisionError(f"Cluster returned {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def check_connection(self) -> Dict[str, Any]:
        """Verify connectivity + auth with a cheap read. Returns a status dict."""
        try:
            data = self._get("/version")
            return {
                "connected": True,
                "api_url": self.api_url,
                "version": data.get("gitVersion") or data.get("major", "") + "." + data.get("minor", ""),
            }
        except ClusterVisionError as e:
            return {"connected": False, "api_url": self.api_url, "error": str(e)}

    # ── namespaces ──

    def list_namespaces(self) -> List[str]:
        data = self._get("/api/v1/namespaces")
        return [i["metadata"]["name"] for i in data.get("items", [])]

    def namespace_exists(self, name: str) -> bool:
        return name in self.list_namespaces()

    # ── operators (OLM) ──

    def find_package_manifest(self, name_fragment: str) -> Optional[Dict[str, Any]]:
        """Look up an operator's PackageManifest (OLM catalog metadata) to discover its
        package name, default channel, and the CatalogSource that carries it — the facts
        needed to write a Subscription for a NOT-yet-installed operator. Read-only."""
        frag = name_fragment.lower().replace(" ", "-")
        try:
            data = self._get("/apis/packages.operators.coreos.com/v1/packagemanifests")
        except ClusterVisionError:
            return None
        best = None
        for pm in data.get("items", []):
            pkg = (pm.get("status", {}).get("packageName") or pm["metadata"].get("name") or "")
            disp = (pm.get("status", {}).get("channels", [{}])[0]
                    .get("currentCSVDesc", {}).get("displayName", "")) if pm.get("status", {}).get("channels") else ""
            if frag in pkg.lower() or (disp and frag in disp.lower()):
                status = pm.get("status", {})
                default_channel = status.get("defaultChannel")
                channels = status.get("channels", [])
                chan = next((c for c in channels if c.get("name") == default_channel), channels[0] if channels else {})
                cand = {
                    "package_name": pkg,
                    "channel": default_channel or chan.get("name"),
                    "catalog_source": status.get("catalogSource"),
                    "catalog_source_namespace": status.get("catalogSourceNamespace", "openshift-marketplace"),
                    "display_name": chan.get("currentCSVDesc", {}).get("displayName") or pkg,
                }
                # Prefer an exact package match.
                if pkg.lower() == frag:
                    return cand
                best = best or cand
        return best

    def get_csv(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Fetch a single ClusterServiceVersion (the operator's self-description)."""
        try:
            return self._get(
                f"/apis/operators.coreos.com/v1alpha1/namespaces/{namespace}"
                f"/clusterserviceversions/{name}"
            )
        except ClusterVisionError:
            return None

    def find_csv(self, name_fragment: str) -> Optional[Dict[str, Any]]:
        """Find an installed CSV whose name/displayName contains the fragment, and
        return the full CSV object (for reading alm-examples, install modes, owned CRDs)."""
        frag = name_fragment.lower()
        data = self._get("/apis/operators.coreos.com/v1alpha1/clusterserviceversions")
        for csv in data.get("items", []):
            nm = (csv["metadata"].get("name") or "").lower()
            disp = (csv.get("spec", {}).get("displayName") or "").lower()
            if frag in nm or frag in disp:
                return csv
        return None

    def get_operator_self_description(self, name_fragment: str) -> Optional[Dict[str, Any]]:
        """Extract everything ARNIE needs to AUTO-GROUND an operator from its own CSV:
        the sample CRs the authors ship (alm-examples), the install modes, and the
        owned CRDs. This is how ARNIE configures operators it has never seen — it reads
        what the operator says about itself."""
        csv = self.find_csv(name_fragment)
        if not csv:
            return None
        meta = csv.get("metadata", {})
        spec = csv.get("spec", {})

        # alm-examples: a JSON array of sample CRs the operator authors provide.
        alm_raw = meta.get("annotations", {}).get("alm-examples", "")
        examples = []
        if alm_raw:
            try:
                import json
                examples = json.loads(alm_raw)
                if isinstance(examples, dict):
                    examples = [examples]
            except Exception:
                examples = []

        install_modes = spec.get("installModes", [])
        supports_all_ns = any(
            m.get("type") == "AllNamespaces" and m.get("supported")
            for m in install_modes
        )
        supports_single_ns = any(
            m.get("type") == "SingleNamespace" and m.get("supported")
            for m in install_modes
        )

        owned_crds = [
            {"name": c.get("name"), "kind": c.get("kind"), "version": c.get("version"),
             "description": c.get("description", "")}
            for c in spec.get("customresourcedefinitions", {}).get("owned", [])
        ]

        return {
            "csv_name": meta.get("name"),
            "display_name": spec.get("displayName"),
            "version": spec.get("version"),
            "namespace": meta.get("namespace"),
            "examples": examples,            # sample CRs — the "answer key"
            "owned_crds": owned_crds,        # operands this operator manages
            "supports_all_namespaces": supports_all_ns,
            "supports_single_namespace": supports_single_ns,
        }

    def list_operators(self) -> List[Dict[str, Any]]:
        """List installed operators via their ClusterServiceVersions.

        OLM copies a CSV into every namespace an AllNamespaces operator watches, so
        the raw list is heavily duplicated. We dedupe by CSV name and report the set
        of UNIQUE operators (keeping the install/source namespace if identifiable)."""
        data = self._get("/apis/operators.coreos.com/v1alpha1/clusterserviceversions")
        seen: Dict[str, Dict[str, Any]] = {}
        for csv in data.get("items", []):
            name = csv["metadata"].get("name")
            if not name or name in seen:
                continue
            seen[name] = {
                "name": name,
                "display_name": csv.get("spec", {}).get("displayName"),
                "version": csv.get("spec", {}).get("version"),
                "phase": csv.get("status", {}).get("phase"),
            }
        return sorted(seen.values(), key=lambda o: (o.get("display_name") or o["name"]).lower())

    def is_operator_installed(self, name_fragment: str) -> bool:
        """True if any installed CSV name/displayName contains the fragment."""
        frag = name_fragment.lower()
        for op in self.list_operators():
            if frag in (op.get("name") or "").lower() or frag in (op.get("display_name") or "").lower():
                return True
        return False

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        data = self._get("/apis/operators.coreos.com/v1alpha1/subscriptions")
        return [
            {
                "name": s["metadata"].get("name"),
                "namespace": s["metadata"].get("namespace"),
                "channel": s.get("spec", {}).get("channel"),
                "package": s.get("spec", {}).get("name"),
                "source": s.get("spec", {}).get("source"),
            }
            for s in data.get("items", [])
        ]

    # ── CRDs (for grounding the operand of any operator) ──

    def list_crds(self) -> List[str]:
        data = self._get("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
        return [i["metadata"]["name"] for i in data.get("items", [])]

    def get_crd(self, name: str) -> Optional[Dict[str, Any]]:
        """Fetch a CRD by full name (e.g. 'grafanas.grafana.integreatly.org')."""
        try:
            return self._get(f"/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}")
        except ClusterVisionError:
            return None

    def find_crds_by_group(self, group_fragment: str) -> List[Dict[str, Any]]:
        """Return CRDs whose group contains the fragment, with their kinds + versions —
        used to ground an operator's Custom Resource from the live schema."""
        frag = group_fragment.lower()
        out = []
        data = self._get("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
        for crd in data.get("items", []):
            spec = crd.get("spec", {})
            group = spec.get("group", "")
            if frag in group.lower():
                versions = [v["name"] for v in spec.get("versions", [])]
                out.append({
                    "name": crd["metadata"]["name"],
                    "group": group,
                    "kind": spec.get("names", {}).get("kind"),
                    "plural": spec.get("names", {}).get("plural"),
                    "scope": spec.get("scope"),
                    "versions": versions,
                })
        return out

    def get_crd_schema(self, crd_name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Extract the openAPIV3Schema + required fields for a CRD version, so ARNIE can
        ground config questions on the REAL schema present on this cluster."""
        crd = self.get_crd(crd_name)
        if not crd:
            return None
        versions = crd.get("spec", {}).get("versions", [])
        chosen = None
        for v in versions:
            if version and v["name"] == version:
                chosen = v
                break
            if v.get("served"):
                chosen = chosen or v
        if not chosen:
            return None
        schema = chosen.get("schema", {}).get("openAPIV3Schema", {})
        spec_props = schema.get("properties", {}).get("spec", {})
        return {
            "crd": crd_name,
            "version": chosen["name"],
            "required": spec_props.get("required", []),
            "properties": list((spec_props.get("properties", {}) or {}).keys()),
            "schema": spec_props,
        }

    # ── storage / general resources ──

    def list_storage_classes(self) -> List[Dict[str, Any]]:
        data = self._get("/apis/storage.k8s.io/v1/storageclasses")
        out = []
        for sc in data.get("items", []):
            ann = sc["metadata"].get("annotations", {}) or {}
            out.append({
                "name": sc["metadata"]["name"],
                "provisioner": sc.get("provisioner"),
                "default": ann.get("storageclass.kubernetes.io/is-default-class") == "true",
            })
        return out

    def default_storage_class(self) -> Optional[str]:
        for sc in self.list_storage_classes():
            if sc["default"]:
                return sc["name"]
        scs = self.list_storage_classes()
        return scs[0]["name"] if scs else None

    def get_resource(
        self,
        api_version: str,
        kind_plural: str,
        name: str,
        namespace: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generic GET for a single resource. api_version like 'v1' or
        'grafana.integreatly.org/v1beta1'; kind_plural like 'grafanas'."""
        base = "/api" if api_version == "v1" else f"/apis/{api_version}"
        if namespace:
            path = f"{base}/namespaces/{namespace}/{kind_plural}/{name}"
        else:
            path = f"{base}/{kind_plural}/{name}"
        try:
            return self._get(path)
        except ClusterVisionError:
            return None

    def list_pods(self, namespace: str) -> List[Dict[str, Any]]:
        data = self._get(f"/api/v1/namespaces/{namespace}/pods")
        out = []
        for p in data.get("items", []):
            st = p.get("status", {})
            out.append({
                "name": p["metadata"]["name"],
                "phase": st.get("phase"),
                "ready": all(c.get("ready") for c in st.get("containerStatuses", []) or []),
                "restarts": sum(c.get("restartCount", 0) for c in st.get("containerStatuses", []) or []),
            })
        return out

    # ── grounding helpers used by the generator / operator flow ──

    def operator_context(self, name_fragment: str) -> Dict[str, Any]:
        """Snapshot of cluster facts relevant to installing/configuring an operator:
        is it already installed, what CRDs/storage exist. Feeds grounded generation."""
        ctx: Dict[str, Any] = {"connected": True}
        try:
            ctx["already_installed"] = self.is_operator_installed(name_fragment)
            ctx["crds"] = self.find_crds_by_group(name_fragment)
            ctx["default_storage_class"] = self.default_storage_class()
            ctx["namespaces"] = self.list_namespaces()
        except ClusterVisionError as e:
            return {"connected": False, "error": str(e)}
        return ctx
