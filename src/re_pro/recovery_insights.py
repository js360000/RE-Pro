from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from .models import AnalysisReport
from .utils import ensure_dir


@dataclass
class InsightArtifact:
    path: Path
    category: str
    description: str


GENERIC_FUNCTION_PREFIXES = ("sub_", "FUN_", "thunk_", "vf_")
STUB_MARKERS = (
    "map this stub to decompiler output",
    "recover original body from decompiler",
    "Pseudo-source synthesized",
    "formatted shipped bundle code, not original source",
    "source maps were not present",
)


def write_recovery_insights(report: AnalysisReport, analysis_index: dict[str, Any], output_dir: Path) -> list[InsightArtifact]:
    insight_root = ensure_dir(output_dir / "usability")
    source_assessments, source_stub_targets = _assess_recovered_sources(report)
    function_assessments, function_stub_targets = _assess_functions(analysis_index)
    graph_manifest = _build_evidence_graph_manifest(report, analysis_index, function_assessments)
    stub_queue = _build_stub_queue(source_stub_targets, function_stub_targets)
    function_page_manifest = _write_function_pages(report, analysis_index, function_assessments, stub_queue, insight_root)
    quality = _build_quality_manifest(
        report=report,
        analysis_index=analysis_index,
        source_assessments=source_assessments,
        function_assessments=function_assessments,
        graph_manifest=graph_manifest,
        stub_queue=stub_queue,
        function_page_manifest=function_page_manifest,
    )

    quality_path = insight_root / "recovery_quality.json"
    quality_md_path = insight_root / "recovery_quality.md"
    graph_path = insight_root / "evidence_graph.json"
    graph_html_path = insight_root / "evidence_graph.html"
    stub_queue_path = insight_root / "stub_elimination_queue.json"
    function_pages_path = insight_root / "function_evidence_pages.json"

    quality_path.write_text(json.dumps(quality, indent=2), encoding="utf-8")
    quality_md_path.write_text(_render_quality_markdown(quality, stub_queue), encoding="utf-8")
    graph_path.write_text(json.dumps(graph_manifest, indent=2), encoding="utf-8")
    graph_html_path.write_text(_render_evidence_graph_html(graph_manifest, stub_queue, function_page_manifest), encoding="utf-8")
    stub_queue_path.write_text(json.dumps(stub_queue, indent=2), encoding="utf-8")
    function_pages_path.write_text(json.dumps(function_page_manifest, indent=2), encoding="utf-8")

    if stub_queue["summary"]["target_count"]:
        report.add_note(
            "Stub elimination queue generated "
            f"{stub_queue['summary']['target_count']} high-value reconstruction target(s)."
        )

    return [
        InsightArtifact(quality_path, "manifest", "Recovery quality manifest"),
        InsightArtifact(quality_md_path, "report", "Recovery quality dashboard"),
        InsightArtifact(graph_path, "manifest", "Evidence graph manifest"),
        InsightArtifact(graph_html_path, "report", "Evidence graph browser"),
        InsightArtifact(stub_queue_path, "manifest", "Stub elimination queue"),
        InsightArtifact(function_pages_path, "manifest", "Function evidence page manifest"),
    ]


def _assess_recovered_sources(report: AnalysisReport) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assessments: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    for source in report.recovered_sources:
        restored_path = Path(source.restored_path)
        text = _read_small_text(restored_path)
        markers = [marker for marker in STUB_MARKERS if marker.lower() in text.lower()]
        generic_count = len(re.findall(r"\b(?:sub|FUN|thunk|vf)_[0-9a-fA-F]{4,}\b", text))
        provenance = _source_provenance(source.original_path, source.source_map, source.restored_path, text)
        confidence = _source_confidence(provenance, markers, generic_count)
        assessment = {
            "original_path": source.original_path,
            "restored_path": source.restored_path,
            "source_map": source.source_map,
            "provenance": provenance,
            "confidence": confidence,
            "stub_marker_count": len(markers),
            "generic_function_reference_count": generic_count,
            "markers": markers,
        }
        assessments.append(assessment)
        if markers or generic_count:
            targets.append(
                {
                    "kind": "source_file",
                    "priority": min(100, 55 + len(markers) * 15 + min(generic_count, 10) * 2),
                    "path": source.restored_path,
                    "label": source.original_path or restored_path.name,
                    "reason": _reason_from_markers(markers, generic_count),
                    "provenance": provenance,
                    "confidence": confidence,
                }
            )
    return assessments, sorted(targets, key=lambda item: (-int(item["priority"]), str(item["label"])))


def _assess_functions(analysis_index: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    functions = [entity for entity in analysis_index.get("entities") or [] if entity.get("kind") == "function"]
    relations = analysis_index.get("relations") or []
    relation_count_by_entity: dict[str, int] = {}
    for relation in relations:
        for endpoint in (relation.get("source"), relation.get("target")):
            if isinstance(endpoint, str):
                relation_count_by_entity[endpoint] = relation_count_by_entity.get(endpoint, 0) + 1

    assessments: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    for entity in functions:
        entity_id = f"{entity.get('kind')}:{entity.get('key')}"
        attributes = entity.get("attributes") or {}
        label = str(entity.get("label", "")).strip()
        address = str(attributes.get("address") or "").strip()
        provenance = _function_provenance(entity)
        confidence = _function_confidence(entity, provenance)
        generic = _is_generic_function_name(label)
        decompiled = bool(attributes.get("decompiled_c"))
        assessment = {
            "entity_id": entity_id,
            "label": label,
            "address": address,
            "class_name": attributes.get("class_name"),
            "tool": attributes.get("tool"),
            "provenance": provenance,
            "confidence": confidence,
            "has_decompiled_body": decompiled,
            "is_generic_name": generic,
            "relation_count": relation_count_by_entity.get(entity_id, 0),
            "source_path": attributes.get("source_path"),
        }
        assessments.append(assessment)
        if generic or attributes.get("decompile_success") is False or (provenance == "rtti-vtable" and not decompiled):
            targets.append(
                {
                    "kind": "function",
                    "priority": _function_priority(assessment),
                    "entity_id": entity_id,
                    "label": label,
                    "address": address,
                    "class_name": attributes.get("class_name"),
                    "reason": _function_target_reason(assessment, attributes),
                    "provenance": provenance,
                    "confidence": confidence,
                    "source_path": attributes.get("source_path"),
                }
            )
    return assessments, sorted(targets, key=lambda item: (-int(item["priority"]), str(item["label"])))


def _build_evidence_graph_manifest(
    report: AnalysisReport,
    analysis_index: dict[str, Any],
    function_assessments: list[dict[str, Any]],
) -> dict[str, Any]:
    entities = analysis_index.get("entities") or []
    relations = analysis_index.get("relations") or []
    entity_counts = (analysis_index.get("summary") or {}).get("entity_counts") or {}
    relation_degree: dict[str, int] = {}
    for relation in relations:
        for endpoint in (relation.get("source"), relation.get("target")):
            if isinstance(endpoint, str):
                relation_degree[endpoint] = relation_degree.get(endpoint, 0) + 1
    entity_by_id = {f"{entity.get('kind')}:{entity.get('key')}": entity for entity in entities}
    hubs = []
    for entity_id, degree in sorted(relation_degree.items(), key=lambda item: (-item[1], item[0]))[:30]:
        entity = entity_by_id.get(entity_id) or {}
        hubs.append(
            {
                "entity_id": entity_id,
                "kind": entity.get("kind"),
                "label": entity.get("label"),
                "degree": degree,
                "attributes": entity.get("attributes") or {},
            }
        )
    high_value_functions = sorted(
        function_assessments,
        key=lambda item: (-int(item.get("relation_count") or 0), item.get("label") or ""),
    )[:40]
    return {
        "target": report.target,
        "output_dir": report.output_dir,
        "entity_counts": entity_counts,
        "relation_count": len(relations),
        "top_hubs": hubs,
        "high_value_functions": high_value_functions,
        "frameworks": report.frameworks,
    }


def _build_quality_manifest(
    *,
    report: AnalysisReport,
    analysis_index: dict[str, Any],
    source_assessments: list[dict[str, Any]],
    function_assessments: list[dict[str, Any]],
    graph_manifest: dict[str, Any],
    stub_queue: dict[str, Any],
    function_page_manifest: dict[str, Any],
) -> dict[str, Any]:
    source_by_provenance = _count_by(source_assessments, "provenance")
    function_by_provenance = _count_by(function_assessments, "provenance")
    function_by_confidence = _count_by(function_assessments, "confidence")
    source_by_confidence = _count_by(source_assessments, "confidence")
    named_functions = [item for item in function_assessments if not item["is_generic_name"]]
    decompiled_functions = [item for item in function_assessments if item["has_decompiled_body"]]
    total_functions = len(function_assessments)
    total_sources = len(source_assessments)
    return {
        "target": report.target,
        "output_dir": report.output_dir,
        "summary": {
            "artifact_count": len(report.artifacts),
            "finding_count": len(report.findings),
            "framework_count": len(report.frameworks),
            "recovered_source_count": total_sources,
            "function_count": total_functions,
            "class_count": (analysis_index.get("summary") or {}).get("entity_counts", {}).get("class", 0),
            "string_count": (analysis_index.get("summary") or {}).get("entity_counts", {}).get("string", 0),
            "relation_count": graph_manifest.get("relation_count", 0),
            "named_function_ratio": _ratio(len(named_functions), total_functions),
            "decompiled_function_ratio": _ratio(len(decompiled_functions), total_functions),
            "stub_target_count": stub_queue["summary"]["target_count"],
            "function_evidence_page_count": function_page_manifest["summary"]["page_count"],
        },
        "source_provenance_counts": source_by_provenance,
        "source_confidence_counts": source_by_confidence,
        "function_provenance_counts": function_by_provenance,
        "function_confidence_counts": function_by_confidence,
        "top_stub_targets": stub_queue["targets"][:25],
        "top_graph_hubs": graph_manifest["top_hubs"][:20],
        "function_evidence_pages": function_page_manifest["pages"][:40],
    }


def _build_stub_queue(source_targets: list[dict[str, Any]], function_targets: list[dict[str, Any]]) -> dict[str, Any]:
    targets = sorted([*source_targets, *function_targets], key=lambda item: (-int(item["priority"]), str(item["label"])))
    return {
        "summary": {
            "target_count": len(targets),
            "source_file_targets": len(source_targets),
            "function_targets": len(function_targets),
        },
        "targets": targets,
        "recommended_workflow": [
            "Run Ghidra targeted decompilation for function targets with concrete addresses.",
            "Use class/vtable evidence to rename generic functions before invoking LLM rewriting.",
            "Open source-file targets and replace marker-heavy pseudo bodies with evidence-backed function pages.",
            "Re-run analysis and compare the quality manifest to verify fewer generic names and stubs.",
        ],
    }


def _render_quality_markdown(quality: dict[str, Any], stub_queue: dict[str, Any]) -> str:
    summary = quality["summary"]
    lines = [
        "# Recovery Quality Dashboard",
        "",
        f"Target: `{quality['target']}`",
        f"Output: `{quality['output_dir']}`",
        "",
        "## Scorecard",
        "",
        f"- Recovered sources: {summary['recovered_source_count']}",
        f"- Functions indexed: {summary['function_count']}",
        f"- Classes indexed: {summary['class_count']}",
        f"- Strings indexed: {summary['string_count']}",
        f"- Graph relations: {summary['relation_count']}",
        f"- Named function ratio: {summary['named_function_ratio']:.1%}",
        f"- Decompiled function ratio: {summary['decompiled_function_ratio']:.1%}",
        f"- Stub elimination targets: {summary['stub_target_count']}",
        f"- Function evidence pages: {summary.get('function_evidence_page_count', 0)}",
        "",
        "## Provenance",
        "",
        "Source provenance: " + _format_counts(quality["source_provenance_counts"]),
        "Function provenance: " + _format_counts(quality["function_provenance_counts"]),
        "",
        "## Highest Priority Stub Targets",
        "",
    ]
    for target in stub_queue["targets"][:20]:
        label = target.get("label") or target.get("entity_id") or target.get("path")
        lines.append(f"- P{target.get('priority')}: {target.get('kind')} `{label}` - {target.get('reason')}")
    if not stub_queue["targets"]:
        lines.append("- No high-priority stub targets detected.")
    lines.extend(["", "## Top Evidence Hubs", ""])
    for hub in quality["top_graph_hubs"][:15]:
        lines.append(f"- degree {hub.get('degree')}: {hub.get('kind')} `{hub.get('label')}`")
    return "\n".join(lines) + "\n"


def _write_function_pages(
    report: AnalysisReport,
    analysis_index: dict[str, Any],
    function_assessments: list[dict[str, Any]],
    stub_queue: dict[str, Any],
    insight_root: Path,
) -> dict[str, Any]:
    page_root = ensure_dir(insight_root / "function_pages")
    entity_by_id = {f"{entity.get('kind')}:{entity.get('key')}": entity for entity in analysis_index.get("entities") or []}
    relation_by_entity: dict[str, list[dict[str, Any]]] = {}
    for relation in analysis_index.get("relations") or []:
        for endpoint in (relation.get("source"), relation.get("target")):
            if isinstance(endpoint, str):
                relation_by_entity.setdefault(endpoint, []).append(relation)
    selected_ids: list[str] = []
    for target in stub_queue.get("targets") or []:
        entity_id = str(target.get("entity_id") or "")
        if entity_id.startswith("function:") and entity_id not in selected_ids:
            selected_ids.append(entity_id)
    for assessment in sorted(function_assessments, key=lambda item: (-int(item.get("relation_count") or 0), item.get("label") or "")):
        entity_id = str(assessment.get("entity_id") or "")
        if entity_id and entity_id not in selected_ids:
            selected_ids.append(entity_id)
        if len(selected_ids) >= 120:
            break

    pages: list[dict[str, Any]] = []
    for entity_id in selected_ids:
        entity = entity_by_id.get(entity_id)
        if not entity:
            continue
        assessment = next((item for item in function_assessments if item.get("entity_id") == entity_id), {})
        related = relation_by_entity.get(entity_id, [])[:80]
        page_name = _safe_file_stem(entity_id) + ".md"
        page_path = page_root / page_name
        page_path.write_text(
            _render_function_page(report, entity_id, entity, assessment, related, entity_by_id),
            encoding="utf-8",
        )
        attrs = entity.get("attributes") or {}
        pages.append(
            {
                "entity_id": entity_id,
                "label": entity.get("label"),
                "address": attrs.get("address"),
                "class_name": attrs.get("class_name"),
                "tool": attrs.get("tool"),
                "confidence": assessment.get("confidence") or _function_confidence(entity, _function_provenance(entity)),
                "provenance": assessment.get("provenance") or _function_provenance(entity),
                "path": str(page_path),
                "file_url": page_path.resolve().as_uri(),
                "relation_count": len(related),
            }
        )
    return {
        "summary": {
            "page_count": len(pages),
            "page_root": str(page_root),
        },
        "pages": pages,
    }


def _render_function_page(
    report: AnalysisReport,
    entity_id: str,
    entity: dict[str, Any],
    assessment: dict[str, Any],
    relations: list[dict[str, Any]],
    entity_by_id: dict[str, dict[str, Any]],
) -> str:
    attrs = entity.get("attributes") or {}
    lines = [
        f"# Function Evidence: {entity.get('label') or entity_id}",
        "",
        f"- Entity: `{entity_id}`",
        f"- Target: `{report.target}`",
        f"- Address: `{attrs.get('address') or ''}`",
        f"- Class: `{attrs.get('class_name') or attrs.get('namespace') or ''}`",
        f"- Tool: `{attrs.get('tool') or ''}`",
        f"- Confidence: `{assessment.get('confidence') or _function_confidence(entity, _function_provenance(entity))}`",
        f"- Provenance: `{assessment.get('provenance') or _function_provenance(entity)}`",
        f"- Source artifact: `{attrs.get('source_path') or ''}`",
        "",
        "## Signature",
        "",
        f"```text\n{attrs.get('signature') or attrs.get('return_type') or entity.get('label') or ''}\n```",
        "",
        "## Related Evidence",
        "",
    ]
    if relations:
        for relation in relations[:40]:
            other_id = relation.get("target") if relation.get("source") == entity_id else relation.get("source")
            other = entity_by_id.get(str(other_id)) or {}
            lines.append(
                f"- `{relation.get('predicate')}` -> {other.get('kind', 'entity')} "
                f"`{other.get('label') or other_id}`"
            )
    else:
        lines.append("- No direct graph relations recorded.")
    callers = attrs.get("callers") or []
    callees = attrs.get("callees") or []
    if callers:
        lines.extend(["", "## Callers", ""])
        for caller in callers[:30]:
            lines.append(f"- `{caller.get('caller_name') or caller.get('name')}` at `{caller.get('caller_entry_point') or caller.get('from_address')}`")
    if callees:
        lines.extend(["", "## Callees", ""])
        for callee in callees[:30]:
            lines.append(f"- `{callee.get('name')}` at `{callee.get('entry_point') or callee.get('from_address')}`")
    decompiled = str(attrs.get("decompiled_c") or "").strip()
    if decompiled:
        lines.extend(["", "## Decompiled Body", "", "```c", decompiled, "```"])
    else:
        lines.extend(
            [
                "",
                "## Next Recovery Action",
                "",
                "- Run targeted decompilation for the recorded address if available.",
                "- Cross-check class/vtable/context relations before accepting a generic function name.",
                "- Use this page as the evidence pack for LLM-assisted source-grade rewriting.",
            ]
        )
    return "\n".join(lines) + "\n"


def _render_evidence_graph_html(
    graph_manifest: dict[str, Any],
    stub_queue: dict[str, Any],
    function_page_manifest: dict[str, Any],
) -> str:
    data = {
        "graph": graph_manifest,
        "stubQueue": stub_queue,
        "functionPages": function_page_manifest,
    }
    data_json = json.dumps(data, ensure_ascii=False)
    target = escape(str(graph_manifest.get("target") or "RE-Pro run"))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RE-Pro Evidence Graph</title>
  <style>
    :root {{
      --bg: #10110f;
      --panel: #191b17;
      --ink: #f2f0df;
      --muted: #aaa58f;
      --line: #33362b;
      --accent: #d6ff64;
      --hot: #ff8a5b;
      --blue: #73d8ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at 15% 15%, rgba(214,255,100,.14), transparent 28rem),
        radial-gradient(circle at 85% 5%, rgba(115,216,255,.10), transparent 24rem),
        linear-gradient(135deg, #10110f, #171916 55%, #0d0e0c);
      color: var(--ink);
      font-family: "Aptos", "Segoe UI", sans-serif;
    }}
    header {{
      padding: 2rem;
      border-bottom: 1px solid var(--line);
    }}
    h1 {{ margin: 0 0 .35rem; font-size: clamp(2rem, 5vw, 4rem); letter-spacing: -.04em; }}
    .sub {{ color: var(--muted); max-width: 78rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(12, 1fr); gap: 1rem; padding: 1rem; }}
    .card {{
      background: rgba(25,27,23,.86);
      border: 1px solid var(--line);
      border-radius: 1.25rem;
      padding: 1rem;
      box-shadow: 0 18px 50px rgba(0,0,0,.25);
    }}
    .span4 {{ grid-column: span 4; }}
    .span6 {{ grid-column: span 6; }}
    .span8 {{ grid-column: span 8; }}
    .span12 {{ grid-column: span 12; }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: .8rem;
      padding: .85rem 1rem;
      background: #0d0e0c;
      color: var(--ink);
      outline: none;
    }}
    input:focus {{ border-color: var(--accent); box-shadow: 0 0 0 3px rgba(214,255,100,.16); }}
    .stat {{ font-size: 2rem; color: var(--accent); font-weight: 800; }}
    .label {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: .08em; }}
    .list {{ display: grid; gap: .7rem; max-height: 42rem; overflow: auto; padding-right: .25rem; }}
    .item {{
      border: 1px solid var(--line);
      border-radius: 1rem;
      padding: .85rem;
      background: rgba(255,255,255,.025);
      cursor: pointer;
      transition: transform .14s ease, border-color .14s ease, background .14s ease;
    }}
    .item:hover {{ transform: translateY(-2px); border-color: var(--accent); background: rgba(214,255,100,.05); }}
    .pill {{ display:inline-block; padding:.15rem .5rem; border-radius:999px; background:#25291d; color:var(--accent); font-size:.76rem; margin-right:.35rem; }}
    .hot {{ color: var(--hot); }}
    .blue {{ color: var(--blue); }}
    pre {{ white-space: pre-wrap; color: #d7d4c2; background: #0d0e0c; border-radius: 1rem; padding: 1rem; overflow: auto; }}
    a {{ color: var(--blue); }}
    @media (max-width: 900px) {{ .span4,.span6,.span8 {{ grid-column: span 12; }} header {{ padding: 1.2rem; }} }}
  </style>
</head>
<body>
  <header>
    <div class="label">RE-Pro Evidence Graph</div>
    <h1>{target}</h1>
    <div class="sub">Search graph hubs, stub targets, and function evidence pages generated from concrete analysis artifacts.</div>
  </header>
  <main class="grid">
    <section class="card span12"><input id="filter" placeholder="Filter by function, class, address, provenance, or reason"></section>
    <section class="card span4"><div class="label">Relations</div><div class="stat" id="relationCount">0</div></section>
    <section class="card span4"><div class="label">Stub Targets</div><div class="stat hot" id="stubCount">0</div></section>
    <section class="card span4"><div class="label">Function Pages</div><div class="stat blue" id="pageCount">0</div></section>
    <section class="card span4"><h2>Top Hubs</h2><div id="hubs" class="list"></div></section>
    <section class="card span4"><h2>Stub Queue</h2><div id="stubs" class="list"></div></section>
    <section class="card span4"><h2>Function Pages</h2><div id="pages" class="list"></div></section>
    <section class="card span12"><h2>Selected Evidence</h2><pre id="detail">Select an item.</pre></section>
  </main>
  <script id="payload" type="application/json">{escape(data_json)}</script>
  <script>
    const payload = JSON.parse(document.getElementById('payload').textContent);
    const graph = payload.graph || {{}};
    const stubs = (payload.stubQueue && payload.stubQueue.targets) || [];
    const pages = (payload.functionPages && payload.functionPages.pages) || [];
    const hubs = graph.top_hubs || [];
    document.getElementById('relationCount').textContent = graph.relation_count || 0;
    document.getElementById('stubCount').textContent = stubs.length;
    document.getElementById('pageCount').textContent = pages.length;
    const detail = document.getElementById('detail');
    function textFor(item) {{ return JSON.stringify(item).toLowerCase(); }}
    function renderList(id, items, render) {{
      const q = document.getElementById('filter').value.trim().toLowerCase();
      const root = document.getElementById(id);
      root.innerHTML = '';
      items.filter(item => !q || textFor(item).includes(q)).slice(0, 80).forEach(item => {{
        const div = document.createElement('div');
        div.className = 'item';
        div.innerHTML = render(item);
        div.onclick = () => detail.textContent = JSON.stringify(item, null, 2);
        root.appendChild(div);
      }});
      if (!root.children.length) root.innerHTML = '<div class="sub">No matches.</div>';
    }}
    function render() {{
      renderList('hubs', hubs, item => `<span class="pill">${{item.kind || 'entity'}}</span><b>${{item.label || item.entity_id}}</b><br><span class="sub">degree ${{item.degree || 0}}</span>`);
      renderList('stubs', stubs, item => `<span class="pill">P${{item.priority || ''}}</span><b>${{item.label || item.entity_id || item.path}}</b><br><span class="sub">${{item.reason || ''}}</span>`);
      renderList('pages', pages, item => `<span class="pill">${{item.confidence || 'unknown'}}</span><b>${{item.label || item.entity_id}}</b><br><a href="${{item.file_url || item.path || '#'}}">${{item.path || ''}}</a>`);
    }}
    document.getElementById('filter').addEventListener('input', render);
    render();
  </script>
</body>
</html>
"""


def _safe_file_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return stem[:140] or "function"


def _source_provenance(original_path: str, source_map: str, restored_path: str, text: str) -> str:
    lowered = " ".join([original_path, source_map, restored_path]).lower()
    if source_map:
        return "source-map-backed"
    if "msvc_rtti" in lowered or "class_pseudo_cpp" in lowered:
        return "rtti-vtable-inferred"
    if "llm_assist" in lowered or "reconstructed_src" in lowered:
        return "llm-assisted"
    if "beautified" in lowered or "bundle" in lowered or "source maps were not present" in text.lower():
        return "bundle-beautified"
    if original_path and Path(original_path).suffix.lower() in {".js", ".ts", ".tsx", ".jsx", ".css", ".html", ".xml", ".json"}:
        return "extracted-source-like"
    return "artifact-derived"


def _source_confidence(provenance: str, markers: list[str], generic_count: int) -> str:
    if markers or generic_count > 8:
        return "low"
    if provenance in {"source-map-backed", "extracted-source-like"}:
        return "high"
    if provenance in {"rtti-vtable-inferred", "llm-assisted", "bundle-beautified"}:
        return "medium"
    return "medium"


def _function_provenance(entity: dict[str, Any]) -> str:
    key = str(entity.get("key") or "")
    attrs = entity.get("attributes") or {}
    if attrs.get("decompiled_c"):
        return "decompiler-backed"
    if key.startswith("msvc_rtti:") or attrs.get("vtable_rva"):
        return "rtti-vtable"
    if key.startswith("class_context:") or attrs.get("class_name"):
        return "class-context"
    if attrs.get("tool"):
        return f"{attrs.get('tool')}-export"
    return "analysis-index"


def _function_confidence(entity: dict[str, Any], provenance: str) -> str:
    attrs = entity.get("attributes") or {}
    if attrs.get("decompiled_c") and not _is_generic_function_name(str(entity.get("label") or "")):
        return "high"
    if provenance in {"rtti-vtable", "class-context", "decompiler-backed"}:
        return "medium"
    return "low" if _is_generic_function_name(str(entity.get("label") or "")) else "medium"


def _function_priority(assessment: dict[str, Any]) -> int:
    priority = 50
    if assessment["is_generic_name"]:
        priority += 20
    if assessment["provenance"] in {"rtti-vtable", "class-context"}:
        priority += 15
    if assessment.get("address"):
        priority += 10
    if assessment.get("relation_count", 0) >= 3:
        priority += 10
    if assessment["has_decompiled_body"]:
        priority -= 20
    return max(1, min(priority, 100))


def _function_target_reason(assessment: dict[str, Any], attributes: dict[str, Any]) -> str:
    reasons = []
    if assessment["is_generic_name"]:
        reasons.append("generic function name")
    if attributes.get("decompile_success") is False:
        reasons.append("decompiler failure")
    if assessment["provenance"] == "rtti-vtable" and not assessment["has_decompiled_body"]:
        reasons.append("class/vtable evidence lacks body")
    return ", ".join(reasons) or "high-value function evidence"


def _reason_from_markers(markers: list[str], generic_count: int) -> str:
    reasons = []
    if markers:
        reasons.append(f"{len(markers)} reconstruction marker(s)")
    if generic_count:
        reasons.append(f"{generic_count} generic function reference(s)")
    return ", ".join(reasons)


def _is_generic_function_name(name: str) -> bool:
    return name.startswith(GENERIC_FUNCTION_PREFIXES) or bool(re.match(r"^(?:sub|FUN|thunk|vf)_[0-9a-fA-F]{4,}$", name))


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _ratio(numerator: int, denominator: int) -> float:
    return 0.0 if denominator <= 0 else numerator / denominator


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _read_small_text(path: Path, *, max_bytes: int = 512_000) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        with path.open("rb") as handle:
            return handle.read(max_bytes).decode("utf-8", errors="ignore")
    except OSError:
        return ""
