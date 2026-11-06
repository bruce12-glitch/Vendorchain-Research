"""Offline CycloneDX 1.5 schema validation with vendored upstream references."""
import json
from pathlib import Path
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]/'schemas'


def validate_sbom(value):
    if value.get('bomFormat') != 'CycloneDX' or value.get('specVersion') != '1.5':
        raise ValueError('pinned schema accepts CycloneDX 1.5 only; add a reviewed schema for another version')
    registry = Registry()
    for name in ('bom-1.5.schema.json','spdx.schema.json','jsf-0.82.schema.json'):
        schema = json.loads((ROOT/name).read_text())
        resource = Resource.from_contents(schema)
        registry = registry.with_resource('http://cyclonedx.org/schema/'+name, resource)
    schema = json.loads((ROOT/'bom-1.5.schema.json').read_text())
    Draft7Validator(schema, registry=registry).validate(value)
