"""
ARNIE Operator Auto-Grounder
The scalability unlock for "install any operator."

Hand-curating a knowledge entry for every operator does not scale — there are thousands.
Instead, ARNIE reads what an operator says about ITSELF and grounds the install from that:

  • The CSV's `alm-examples` — sample Custom Resources the operator authors ship. This is
    the "answer key": a known-valid instance showing exactly how to configure the operand.
  • The CSV's install modes — whether the operator supports AllNamespaces or SingleNamespace,
    which determines how the OperatorGroup is written.
  • The owned CRD's OpenAPI schema (read via cluster vision) — the required fields, property
    types, and field descriptions, which become the config questions ARNIE asks.

This produces a "grounding" with the same shape a curated catalog entry would have, but
derived live from the operator's own metadata. Curated entries (the gold standard, with
OpenShift-specific tuning) take precedence; the auto-grounder covers everything else.

The auto-grounder only READS (through cluster vision, which is read-only). It proposes a
configuration; nothing is applied until the user answers and approves.

Built on the RMCP engine by BLCKBX.
"""

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.auto-grounder")

# Fields that are structural/managed, not user config — never ask about these.
SKIP_FIELDS = {
    "status", "apiVersion", "kind", "metadata", "managedFields",
    "creationTimestamp", "resourceVersion", "uid", "generation",
}

# Heuristic mapping from a schema property type to an ARNIE question input type.
TYPE_TO_INPUT = {
    "string": "text",
    "integer": "int",
    "number": "int",
    "boolean": "toggle",
}


class OperatorAutoGrounder:
    """Derives an install grounding for an operator from its own self-description.

    Requires a cluster_vision instance (read-only) to read the live CSV + CRD on the
    cluster where the operator is (or will be) installed.
    """

    def __init__(self, cluster_vision):
        self.vision = cluster_vision

    def can_autoground(self) -> bool:
        return self.vision is not None and self.vision.is_configured()

    def ground(self, name_fragment: str) -> Optional[Dict[str, Any]]:
        """Produce a grounding for the operator identified by name_fragment.

        Returns a dict shaped like a catalog entry:
          {source: 'auto', display_name, csv_name, operand{kind,api_version,...},
           install_mode, config_questions[], cr_example, notes}
        or None if the operator can't be found / has no usable operand.
        """
        if not self.can_autoground():
            return None

        desc = self.vision.get_operator_self_description(name_fragment)
        # Also look up the catalog metadata (channel, source, package) needed to write a
        # Subscription for a not-yet-installed operator.
        pkg_meta = None
        try:
            pkg_meta = self.vision.find_package_manifest(name_fragment)
        except Exception:
            pkg_meta = None

        if not desc and not pkg_meta:
            log.info("Auto-ground: no CSV or PackageManifest found for '%s'", name_fragment)
            return None

        # If not installed yet, we may have catalog metadata but no examples. Use whatever
        # we have; examples improve the result but aren't strictly required.
        desc = desc or {
            "display_name": pkg_meta.get("display_name") if pkg_meta else name_fragment,
            "csv_name": None, "version": None, "examples": [], "owned_crds": [],
            "supports_all_namespaces": True, "supports_single_namespace": False,
        }

        operand, example = self._choose_primary_operand(desc)
        if not operand:
            log.info("Auto-ground: operator '%s' exposes no owned CRD/operand", name_fragment)
            return None

        crd_name = operand.get("name")
        schema = None
        if crd_name:
            schema = self.vision.get_crd_schema(crd_name)

        questions = self._derive_questions(schema, example)
        install_mode = ("AllNamespaces" if desc.get("supports_all_namespaces")
                        else "SingleNamespace")

        result = {
            "source": "auto",
            "display_name": desc.get("display_name") or name_fragment,
            "csv_name": desc.get("csv_name"),
            "version": desc.get("version"),
            "install_mode": install_mode,
            "operand": {
                "kind": operand.get("kind"),
                "api_version": self._api_version_from_example(example, operand),
                "crd_name": crd_name,
                "description": operand.get("description", ""),
                "workload_weight": self._guess_weight(example),
            },
            "config_questions": questions,
            "cr_example": example,
            "notes": (f"Auto-grounded from the operator's own metadata. Questions derived "
                      f"from its CRD schema and sample resource."),
        }
        # Merge catalog metadata (for the Subscription) when available.
        if pkg_meta:
            result["package_name"] = pkg_meta.get("package_name")
            result["channel"] = pkg_meta.get("channel")
            result["catalog_source"] = pkg_meta.get("catalog_source")
            result["catalog_source_namespace"] = pkg_meta.get("catalog_source_namespace")
        return result

    # ── operand selection ──

    def _choose_primary_operand(self, desc) -> (Optional[Dict[str, Any]], Optional[Dict[str, Any]]):
        """Pick the operator's primary operand. Prefer an owned CRD that also has a
        matching alm-example (so we have both schema and a sample). Returns (crd, example)."""
        owned = desc.get("owned_crds", [])
        examples = desc.get("examples", [])
        ex_by_kind = {}
        for ex in examples:
            k = ex.get("kind")
            if k and k not in ex_by_kind:
                ex_by_kind[k] = ex

        # First choice: an owned CRD that has a sample example.
        for crd in owned:
            if crd.get("kind") in ex_by_kind:
                return crd, ex_by_kind[crd["kind"]]
        # Else: first owned CRD, with any example of that kind if present.
        if owned:
            crd = owned[0]
            return crd, ex_by_kind.get(crd.get("kind"))
        # Else: an example with no matching owned CRD listed.
        if examples:
            ex = examples[0]
            return {"kind": ex.get("kind"), "name": None, "description": ""}, ex
        return None, None

    def _api_version_from_example(self, example, operand) -> Optional[str]:
        if example and example.get("apiVersion"):
            return example["apiVersion"]
        # Build from CRD name + version if no example.
        v = operand.get("version")
        crd_name = operand.get("name") or ""
        if v and "." in crd_name:
            group = crd_name.split(".", 1)[1]
            return f"{group}/{v}"
        return None

    # ── question derivation ──

    def _derive_questions(self, schema, example) -> List[Dict[str, Any]]:
        """Turn the CRD's required/important spec fields into config questions, using
        field descriptions as the prompt text and the alm-example values as defaults."""
        questions: List[Dict[str, Any]] = []
        example_spec = (example or {}).get("spec", {}) if example else {}

        if schema and schema.get("schema"):
            spec_schema = schema["schema"]
            props = spec_schema.get("properties", {}) or {}
            required = set(spec_schema.get("required", []) or [])

            # Ask about required scalar fields first (the things the operator demands).
            for field in sorted(props.keys(), key=lambda f: (f not in required, f)):
                if field in SKIP_FIELDS:
                    continue
                p = props[field] or {}
                ftype = p.get("type")
                # Only ask about scalar fields automatically; nested objects/arrays are
                # left to the example default to avoid overwhelming the user.
                if ftype not in TYPE_TO_INPUT:
                    continue
                if field not in required and len(questions) >= 6:
                    continue  # cap optional questions to keep the form sane
                default = example_spec.get(field, p.get("default"))
                questions.append({
                    "key": field,
                    "question": self._humanize(field, p.get("description")),
                    "input": TYPE_TO_INPUT[ftype],
                    "required": field in required,
                    "default": default,
                })

        # Always make sure the user can name the instance + pick a namespace.
        if not any(q["key"] == "instance_name" for q in questions):
            questions.insert(0, {
                "key": "instance_name",
                "question": "What should this instance be named?",
                "input": "text", "required": True,
                "default": (example or {}).get("metadata", {}).get("name", "instance"),
            })
        questions.insert(1, {
            "key": "install_namespace",
            "question": "Which namespace should it be installed into?",
            "input": "text", "required": True,
            "default": None,
        })
        return questions

    def _humanize(self, field, description) -> str:
        if description:
            d = description.strip().split(". ")[0]
            if len(d) <= 120:
                return d if d.endswith("?") else d + "?"
        spaced = "".join((" " + c.lower()) if c.isupper() else c for c in field).strip()
        return f"Set '{spaced}'?"

    def _guess_weight(self, example) -> str:
        """Conservatively flag stateful/heavy operands so waits are patient."""
        blob = str(example or "").lower()
        heavy_markers = ("nodeset", "volumeclaim", "persistentvolume", "storage",
                         "replicas", "cluster", "statefulset")
        hits = sum(1 for m in heavy_markers if m in blob)
        if hits >= 2:
            return "heavy"
        if hits == 1:
            return "standard"
        return "light"
