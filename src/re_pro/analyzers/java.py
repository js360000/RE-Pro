from __future__ import annotations

import zipfile
from pathlib import Path

from ..sourcemap import restore_sources_from_map
from ..utils import ensure_dir
from .base import Analyzer


class JavaPackageAnalyzer(Analyzer):
    name = "Java archive recovery"

    def analyze(self, context, report) -> None:
        if not context.target.is_file():
            return
        suffix = context.target.suffix.lower()
        if suffix not in {".jar", ".war", ".ear", ".aar"}:
            return
        if not zipfile.is_zipfile(context.target):
            return

        extract_dir = ensure_dir(context.output_dir / "java_archive_extract")
        with zipfile.ZipFile(context.target) as archive:
            archive.extractall(extract_dir)
            members = archive.namelist()

        target_type, framework = self._archive_identity(suffix)
        report.target_type = target_type
        report.add_framework(framework)
        report.add_artifact(str(extract_dir), "directory", "Extracted Java archive")
        report.add_note(f"Java archive extraction produced {len(members)} archive members.")

        manifest_path = extract_dir / "META-INF" / "MANIFEST.MF"
        if manifest_path.exists():
            report.add_artifact(str(manifest_path), "manifest", "Java manifest")
            manifest = self._parse_manifest(manifest_path)
            main_class = manifest.get("Main-Class")
            implementation_title = manifest.get("Implementation-Title")
            implementation_version = manifest.get("Implementation-Version")
            if main_class:
                report.add_note(f"Java main class: {main_class}")
            if implementation_title or implementation_version:
                report.add_note(
                    f"Java archive metadata: title={implementation_title or 'unknown'} version={implementation_version or 'unknown'}."
                )

        class_files = sorted(extract_dir.rglob("*.class"))
        jar_files = sorted(extract_dir.rglob("*.jar"))
        native_libs = sorted(extract_dir.rglob("*.dll")) + sorted(extract_dir.rglob("*.so")) + sorted(extract_dir.rglob("*.dylib"))
        if class_files:
            report.add_note(f"Recovered {len(class_files)} compiled Java/Kotlin class file(s).")
        if jar_files:
            report.add_note(f"Recovered {len(jar_files)} nested JAR file(s).")
        if native_libs:
            report.add_note(f"Recovered {len(native_libs)} native library payload(s) from the Java archive.")

        self._detect_frameworks(extract_dir, members, report)
        self._record_web_artifacts(extract_dir, report)
        self._restore_source_maps(extract_dir, report)
        self._index_java_archive(context, members, class_files, manifest_path if manifest_path.exists() else None)

    @staticmethod
    def _archive_identity(suffix: str) -> tuple[str, str]:
        if suffix == ".war":
            return "java-web-archive", "Java Web Archive (WAR)"
        if suffix == ".ear":
            return "java-enterprise-archive", "Java Enterprise Archive (EAR)"
        if suffix == ".aar":
            return "android-library-archive", "Android Library Archive (AAR)"
        return "java-archive", "Java Archive (JAR)"

    @staticmethod
    def _parse_manifest(path: Path) -> dict[str, str]:
        result: dict[str, str] = {}
        current_key = ""
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return result
        for line in lines:
            if not line:
                current_key = ""
                continue
            if line.startswith(" ") and current_key:
                result[current_key] = result[current_key] + line[1:]
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current_key = key.strip()
            result[current_key] = value.strip()
        return result

    @staticmethod
    def _detect_frameworks(extract_dir: Path, members: list[str], report) -> None:
        lowered_members = [member.lower() for member in members]
        if any(member.startswith("boot-inf/") for member in lowered_members):
            report.add_framework("Java framework: Spring Boot")
        if any(member.startswith("web-inf/") for member in lowered_members):
            report.add_framework("Java framework: Servlet web app")
        if any(member.endswith(".kotlin_module") for member in lowered_members):
            report.add_framework("Java language: Kotlin")
        if any("javafx" in member for member in lowered_members):
            report.add_framework("Java UI toolkit: JavaFX")
        if any("javax/swing" in member or "swing/" in member for member in lowered_members):
            report.add_framework("Java UI toolkit: Swing")
        if any("org/jetbrains/compose" in member for member in lowered_members):
            report.add_framework("Java UI toolkit: Compose Desktop")
        if any(member.endswith("web.xml") for member in lowered_members):
            report.add_note("Servlet deployment descriptor detected: WEB-INF/web.xml.")
        if any(member.endswith("application.properties") or member.endswith("application.yml") for member in lowered_members):
            report.add_artifact(str(extract_dir), "directory", "Java application configuration root")

    @staticmethod
    def _record_web_artifacts(extract_dir: Path, report) -> None:
        for relative in [
            Path("WEB-INF") / "web.xml",
            Path("META-INF") / "resources",
            Path("BOOT-INF") / "classes" / "static",
        ]:
            candidate = extract_dir / relative
            if candidate.exists():
                report.add_artifact(str(candidate), "directory", f"Java web asset root: {relative.as_posix()}")

    @staticmethod
    def _restore_source_maps(extract_dir: Path, report) -> None:
        map_files = sorted(extract_dir.rglob("*.map"))
        if not map_files:
            return
        recovered_root = ensure_dir(extract_dir.parent / "recovered_sources")
        restored_total = 0
        for map_file in map_files:
            restored_sources, notes = restore_sources_from_map(map_file, recovered_root)
            for source in restored_sources:
                report.add_recovered_source(
                    original_path=source.original_path,
                    restored_path=source.restored_path,
                    source_map=source.source_map,
                )
            restored_total += len(restored_sources)
            report.notes.extend(notes)
        if restored_total:
            report.add_finding(
                "Java archive source map restoration succeeded",
                f"Recovered {restored_total} original source files from shipped Java archive web source maps.",
                severity="info",
            )

    @staticmethod
    def _index_java_archive(context, members: list[str], class_files: list[Path], manifest_path: Path | None) -> None:
        target_id = context.analysis_index.make_id("target", str(context.target))
        archive_id = context.analysis_index.add_entity(
            "format",
            f"java-archive:{context.target.name}",
            "Java archive",
            attributes={
                "entry_count": len(members),
                "class_count": len(class_files),
                "suffix": context.target.suffix.lower(),
            },
        )
        context.analysis_index.add_relation(target_id, "has_format", archive_id)
        for class_file in class_files[:300]:
            class_name = class_file.stem
            relative_path = class_file.relative_to(context.output_dir / "java_archive_extract")
            class_id = context.analysis_index.add_entity(
                "java_class",
                str(relative_path).lower(),
                class_name,
                attributes={"path": str(class_file), "relative_path": str(relative_path)},
            )
            context.analysis_index.add_relation(target_id, "contains_class", class_id)
        if manifest_path is not None:
            manifest_id = context.analysis_index.add_entity(
                "artifact",
                str(manifest_path),
                manifest_path.name,
                attributes={"path": str(manifest_path), "category": "manifest"},
            )
            context.analysis_index.add_relation(target_id, "produced_artifact", manifest_id)
