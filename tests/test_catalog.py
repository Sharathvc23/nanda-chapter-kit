from .conftest import make_agent, register


def test_catalog_lists_chapter_and_admitted_members_only(open_client):
    a, probe = make_agent(), make_agent("TEST-conformance")
    register(open_client, a)
    register(open_client, probe)
    cat = open_client.get("/.well-known/ai-catalog.json").json()
    ids = [e["identifier"] for e in cat["entries"]]
    assert ids[0] == "test-chapter" and a.agent_id in ids and probe.agent_id not in ids
    assert cat["host"] == "chapter.example.org"
    member = next(e for e in cat["entries"] if e["identifier"] == a.agent_id)
    assert member["url"] == f"https://chapter.example.org/cards/{a.agent_id}.json"


def test_member_card_points_at_mailbox_and_carries_air_urn(open_client):
    a = make_agent()
    register(open_client, a)
    card = open_client.get(f"/cards/{a.agent_id}.json").json()
    assert card["url"] == f"https://chapter.example.org/a2a/@{a.agent_id}"
    assert card["_meta"]["identifier"] == f"urn:air:chapter.example.org:agent:{a.agent_id}"
    assert open_client.get("/cards/TEST-nope.json").status_code == 404


def test_chapter_agent_card_and_well_known(open_client):
    card = open_client.get("/.well-known/agent.json").json()
    assert card["_meta"]["identifier"] == "urn:air:chapter.example.org:catalog:root"
    assert {s["id"] for s in card["skills"]} >= {"join", "directory", "mailbox", "council"}
    wk = open_client.get("/.well-known/nanda-agent.json").json()
    assert wk["did"] == card["_meta"]["did"] and wk["registries"]["nanda_index"]["locator"] == card["_meta"]["identifier"]
    nj = open_client.get("/.well-known/nanda.json").json()
    assert nj["registry_id"] == "test-chapter" and "ai-catalog" in nj["capabilities"]
