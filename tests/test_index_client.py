from nanda_chapter.index_client import IndexClient

from .conftest import make_cfg


def test_payload_uses_air_locator_and_registry_path(tmp_path):
    ic = IndexClient(make_cfg(tmp_path))
    assert ic.locator == "urn:air:chapter.example.org:catalog:root"
    p = ic.org_payload()
    assert p["hosting_path"] == "registry" and p["domain"] == "chapter.example.org"
    assert p["registry_url"] == "https://chapter.example.org" and "nanda-chapter" in p["tags"]
    assert ic.register(dry_run=True)["payload"] == p


def test_preflight_names_every_blocker(tmp_path):
    ic = IndexClient(make_cfg(tmp_path, PUBLIC_URL="http://localhost:8080", CHAPTER_DOMAIN="localhost", CONTACT_EMAIL=""))
    problems = ic.preflight()
    assert any("https" in x for x in problems) and any("DNS" in x for x in problems) and any("CONTACT_EMAIL" in x for x in problems)
