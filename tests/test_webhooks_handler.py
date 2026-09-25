import asyncio
import threading
from types import SimpleNamespace

from core.background import webhooks


class FakeRequest:
    def __init__(self, body, headers):
        self._body = body
        self.headers = headers

    async def body(self):
        return self._body


def test_receive_webhook_offloads_etcd_reads_and_enqueues(monkeypatch):
    loop_thread = threading.get_ident()
    recorded = {}

    class FakeIdentity:
        def get_agent_config(self, name):
            recorded["config_thread"] = threading.get_ident()
            return {
                "name": name,
                "type": "background_agent",
                "trigger": {"type": "webhook", "provider": "generic", "secret": "env:TEST_WEBHOOK_SECRET"},
            }

        def get_disabled_workflows(self):
            recorded["disabled_thread"] = threading.get_ident()
            return []

    monkeypatch.setenv("TEST_WEBHOOK_SECRET", "tok")
    monkeypatch.setattr(webhooks, "identity_mgr", FakeIdentity())

    enqueued = {}

    async def fake_kiq(agent_name, prompt, user_id):
        enqueued.update(agent_name=agent_name, prompt=prompt, user_id=user_id)
        return SimpleNamespace(task_id="t-1")

    monkeypatch.setattr(webhooks, "run_background_agent", SimpleNamespace(kiq=fake_kiq))

    request = FakeRequest(b'{"event": "ping"}', {"Authorization": "tok"})
    result = asyncio.run(webhooks.receive_webhook("wf-a", request))

    assert result == {"status": "accepted", "task_id": "t-1"}
    assert enqueued["agent_name"] == "wf-a"
    assert enqueued["user_id"] == "webhook"
    assert recorded["config_thread"] != loop_thread
    assert recorded["disabled_thread"] != loop_thread
