from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_pro.ddl import parse_ddl_from_bytes, parse_ddl_text, write_ddl_struct_sources
from tests import _path_setup  # noqa: F401


class DdlParserTests(unittest.TestCase):
    def test_parse_text_ddl_struct_and_enum(self) -> None:
        parsed = parse_ddl_text(
            """
            enum WeaponKind { Pistol = 1, Rifle = 2 };
            struct PlayerState {
                uint32 entity_id;
                float health;
                vec3 position;
                string display_name;
                uint8 inventory[16];
            };
            """,
            source_name="player.ddl",
        )

        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["summary"]["struct_count"], 1)
        self.assertEqual(parsed["summary"]["enum_count"], 1)
        self.assertEqual(parsed["structs"][0]["name"], "PlayerState")
        self.assertEqual(parsed["structs"][0]["fields"][0]["name"], "entity_id")
        self.assertEqual(parsed["structs"][0]["fields"][4]["array"], "16")
        self.assertEqual(parsed["structs"][0]["fields"][2]["cxx_type"], "std::array<float, 3>")
        self.assertGreaterEqual(parsed["structs"][0]["estimated_size"], 40)

    def test_parse_json_reflection_schema_with_offsets(self) -> None:
        parsed = parse_ddl_text(
            json.dumps(
                {
                    "structs": [
                        {
                            "name": "RenderMaterial",
                            "fields": [
                                {"name": "material_id", "type": "uint32", "offset": 0},
                                {"name": "roughness", "type": "float", "offset": 4},
                                {"name": "tint", "type": "array", "items": {"type": "number", "format": "float"}, "maxItems": 4, "offset": 8},
                            ],
                        }
                    ]
                }
            ),
            source_name="reflection_schema.json",
        )

        self.assertTrue(parsed["ok"])
        material = parsed["structs"][0]
        self.assertEqual(material["name"], "RenderMaterial")
        self.assertEqual(material["fields"][0]["offset"], 0)
        self.assertEqual(material["fields"][2]["array_count"], 4)
        self.assertEqual(material["fields"][2]["estimated_size"], 16)
        self.assertEqual(material["estimated_size"], 24)

    def test_tabular_reflection_records_recover_layout(self) -> None:
        parsed = parse_ddl_text(
            """
            RuntimeActor|actor_id|uint32|0|4
            RuntimeActor|team_id|uint16|4|2
            RuntimeActor|health|float|8|4
            """,
            source_name="runtime_strings.txt",
        )

        self.assertTrue(parsed["ok"])
        actor = parsed["structs"][0]
        self.assertEqual(actor["kind"], "tabular_reflection")
        self.assertEqual(actor["fields"][1]["offset_hex"], "0x4")
        self.assertEqual(actor["estimated_size"], 12)

    def test_flatbuffers_table_recovers_vectors_and_references(self) -> None:
        parsed = parse_ddl_text(
            """
            namespace Game.Data;
            table WeaponDef {
                id:uint32;
                display_name:string;
                damage:float = 20.0;
                tags:[string];
            }
            table Loadout {
                primary:WeaponDef;
                inventory:[WeaponDef];
            }
            root_type Loadout;
            """,
            source_name="weapons.fbs",
        )

        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["summary"]["struct_count"], 2)
        loadout = next(struct for struct in parsed["structs"] if struct["name"] == "Loadout")
        inventory = next(field for field in loadout["fields"] if field["name"] == "inventory")
        self.assertEqual(inventory["type"], "WeaponDef")
        self.assertEqual(inventory["array"], "dynamic")
        with tempfile.TemporaryDirectory() as temp_dir:
            generated = write_ddl_struct_sources(parsed, Path(temp_dir), prefix="fbs")
            loadout_header = next(path for path in generated if "Loadout" in path.name).read_text(encoding="utf-8")
            self.assertIn("std::vector<WeaponDef> inventory;", loadout_header)

    def test_protobuf_message_recovers_repeated_fields_and_tags(self) -> None:
        parsed = parse_ddl_text(
            """
            syntax = "proto3";
            message ActorSnapshot {
              uint32 actor_id = 1;
              repeated float world_position = 2 [packed = true];
              string archetype = 3;
            }
            enum ActorState { UNKNOWN = 0; ALIVE = 1; DEAD = 2; }
            """,
            source_name="actor.proto",
        )

        self.assertTrue(parsed["ok"])
        actor = parsed["structs"][0]
        self.assertEqual(actor["name"], "ActorSnapshot")
        self.assertEqual(actor["fields"][0]["field_id"], 1)
        self.assertEqual(actor["fields"][1]["array"], "dynamic")
        self.assertEqual(actor["fields"][1]["field_id"], 2)

    def test_unreal_reflection_macros_are_stripped(self) -> None:
        parsed = parse_ddl_text(
            """
            USTRUCT(BlueprintType)
            struct FWeaponRuntimeData {
                GENERATED_BODY()
                UPROPERTY(EditAnywhere)
                int32 Damage;
                UPROPERTY()
                TArray<FName> Tags;
                UPROPERTY()
                FVector Location;
            };
            """,
            source_name="WeaponRuntimeData.h",
        )

        self.assertTrue(parsed["ok"])
        weapon = parsed["structs"][0]
        self.assertEqual(weapon["name"], "FWeaponRuntimeData")
        field_names = {field["name"] for field in weapon["fields"]}
        self.assertIn("Damage", field_names)
        self.assertIn("Tags", field_names)
        self.assertIn("Location", field_names)

    def test_binary_string_table_recovers_offsets_and_sizes(self) -> None:
        blob = b"\x00".join(
            [
                b"RuntimeActor",
                b"actor_id",
                b"uint32",
                b"0",
                b"4",
                b"health",
                b"float",
                b"8",
                b"4",
            ]
        )

        parsed = parse_ddl_from_bytes(blob, source_name="runtime_region.bin")

        self.assertTrue(parsed["ok"])
        actor = parsed["structs"][0]
        self.assertEqual(actor["fields"][0]["offset_hex"], "0x0")
        self.assertEqual(actor["fields"][1]["offset_hex"], "0x8")
        self.assertEqual(actor["estimated_size"], 12)

    def test_binary_string_table_can_infer_runtime_structs(self) -> None:
        blob = b"\x00".join(
            [
                b"RuntimeWeapon",
                b"id",
                b"uint32",
                b"damage",
                b"float",
                b"displayName",
                b"string",
            ]
        )

        parsed = parse_ddl_from_bytes(blob, source_name="runtime_region.bin")

        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["structs"][0]["name"], "RuntimeWeapon")
        self.assertGreaterEqual(parsed["structs"][0]["field_count"], 3)

    def test_write_recovered_pseudo_header(self) -> None:
        parsed = parse_ddl_text(
            "struct InventoryEntry { uint32 item_id; uint16 count; };",
            source_name="inventory.ddl",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            generated = write_ddl_struct_sources(parsed, Path(temp_dir), prefix="inventory")

            self.assertEqual(len(generated), 1)
            header = generated[0].read_text(encoding="utf-8")
            self.assertIn("struct InventoryEntry", header)
            self.assertIn("uint32_t item_id;", header)
            self.assertIn("Estimated layout size", header)


if __name__ == "__main__":
    unittest.main()
