import json
from pathlib import Path
from typing import Any

import pytest
from bae6_sdk_core import identity

SCHEMAS = Path(__file__).resolve().parents[4] / "contracts" / "schemas"


def load(name: str) -> dict[str, Any]:
    schema: dict[str, Any] = json.loads((SCHEMAS / name).read_text())
    return schema


def schema_keys(name: str) -> tuple[set[str], set[str]]:
    schema = load(name)
    parts = [load(ref["$ref"]) for ref in schema.get("allOf", [])] + [schema]
    keys = {k for p in parts for k in p["properties"]}
    required = {k for p in parts for k in p.get("required", [])}
    return keys, required


@pytest.mark.parametrize(
    ("schema", "typed"),
    [
        ("principal.json", identity.Principal),
        ("external-identity.json", identity.ExternalIdentity),
        ("resource.json", identity.Resource),
        ("delegation.json", identity.Delegation),
        ("execution-context.json", identity.ExecutionContext),
        ("bae6-token-claims.json", identity.Bae6TokenClaims),
        ("event-correlation.json", identity.EventCorrelation),
        ("authorization-event.json", identity.AuthorizationEvent),
        ("usage-event.json", identity.UsageEvent),
        ("quota-decision.json", identity.QuotaDecision),
    ],
)
def test_typed_dict_fields_and_optionality_match_the_schema(schema: str, typed: Any) -> None:
    keys, required = schema_keys(schema)
    assert set(typed.__annotations__) == keys
    assert set(typed.__required_keys__) == required
