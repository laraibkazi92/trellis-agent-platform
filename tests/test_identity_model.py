from core.models import Identity, IdentityType

def test_identity_from_string_user():
    id_str = "user-123"
    identity = Identity.from_string(id_str)
    assert identity.id == "user-123"
    assert identity.type == IdentityType.USER
    assert identity.to_legacy_string() == "user-123"
    assert identity.get_etcd_path("secrets") == "/identities/user/user-123/secrets"

def test_identity_from_string_agent():
    id_str = "svc_agent_daily-report"
    identity = Identity.from_string(id_str)
    assert identity.id == "daily-report"
    assert identity.type == IdentityType.WORKFLOW
    assert identity.to_legacy_string() == "svc_agent_daily-report"
    assert identity.get_etcd_path("secrets") == "/identities/agent/daily-report/secrets"

def test_identity_from_string_system():
    id_str = "system"
    identity = Identity.from_string(id_str)
    assert identity.id == "system"
    assert identity.type == IdentityType.SYSTEM
    assert identity.to_legacy_string() == "system"
    assert identity.get_etcd_path("variables") == "/identities/system/system/variables"
