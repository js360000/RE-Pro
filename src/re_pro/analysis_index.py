from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IndexEntity:
    kind: str
    key: str
    label: str
    attributes: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "key": self.key,
            "label": self.label,
            "attributes": self.attributes,
        }


@dataclass
class IndexRelation:
    source: str
    predicate: str
    target: str
    attributes: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "predicate": self.predicate,
            "target": self.target,
            "attributes": self.attributes,
        }


class AnalysisIndex:
    def __init__(self) -> None:
        self._entities: dict[str, IndexEntity] = {}
        self._relations: dict[tuple[str, str, str], IndexRelation] = {}

    @staticmethod
    def make_id(kind: str, key: str) -> str:
        return f"{kind}:{key}"

    def add_entity(
        self,
        kind: str,
        key: str,
        label: str,
        *,
        attributes: dict[str, object] | None = None,
    ) -> str:
        entity_id = self.make_id(kind, key)
        entity = self._entities.get(entity_id)
        if entity is None:
            entity = IndexEntity(kind=kind, key=key, label=label, attributes={})
            self._entities[entity_id] = entity
        elif label and entity.label != label:
            entity.label = label
        if attributes:
            entity.attributes.update({k: v for k, v in attributes.items() if v is not None})
        return entity_id

    def add_relation(
        self,
        source_id: str,
        predicate: str,
        target_id: str,
        *,
        attributes: dict[str, object] | None = None,
    ) -> None:
        relation_key = (source_id, predicate, target_id)
        relation = self._relations.get(relation_key)
        if relation is None:
            relation = IndexRelation(source=source_id, predicate=predicate, target=target_id, attributes={})
            self._relations[relation_key] = relation
        if attributes:
            relation.attributes.update({k: v for k, v in attributes.items() if v is not None})

    def ensure_target(self, path: str, target_type: str) -> str:
        return self.add_entity("target", path, path, attributes={"target_type": target_type})

    def to_dict(self) -> dict[str, object]:
        entities = [entity.to_dict() for entity in sorted(self._entities.values(), key=lambda item: (item.kind, item.key))]
        relations = [
            relation.to_dict()
            for relation in sorted(self._relations.values(), key=lambda item: (item.source, item.predicate, item.target))
        ]
        summary: dict[str, int] = {}
        for entity in entities:
            summary[entity["kind"]] = summary.get(entity["kind"], 0) + 1
        return {
            "summary": {
                "entity_counts": summary,
                "relation_count": len(relations),
            },
            "entities": entities,
            "relations": relations,
        }
