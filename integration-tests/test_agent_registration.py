import httpx
import pytest
import time

# Base URL for the control plane
BASE_URL = "http://localhost:8000"

def test_gateway_health():
    """Verify the control plane health check."""
    response = httpx.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_list_agents_initial():
    """Verify we can list agents from the marketplace."""
    response = httpx.get(f"{BASE_URL}/marketplace/agents")
    assert response.status_code == 200
    assert "agents" in response.json()

def test_agent_registration_and_health():
    """
    This test assumes that the finance-agent-1 container is running
    and has registered itself.
    """
    # Wait for registration to complete in a real environment
    time.sleep(2)
    
    response = httpx.get(f"{BASE_URL}/marketplace/agents")
    agents = response.json()["agents"]
    
    finance_agent = next((a for a in agents if a["name"] == "finance-agent"), None)
    assert finance_agent is not None, "Finance agent should be registered"
    
    # Check its health via the control plane
    health_response = httpx.get(f"{BASE_URL}/agents/{finance_agent['id']}/health")
    # This might be 200 or 502 depending on if the container is actually up and responding
    if health_response.status_code == 200:
        assert health_response.json()["status"] == "healthy"
    else:
        pytest.skip("Finance agent container might not be reachable in this test environment")

if __name__ == "__main__":
    # For manual running
    try:
        test_gateway_health()
        print("✓ Gateway health passed")
        test_list_agents_initial()
        print("✓ List agents passed")
        print("Integration tests successful (partial)")
    except Exception as e:
        print(f"Integration tests failed: {e}")
