import sys
import os
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import etcd3gw

# Add control-plane to path
sys.path.append(os.path.join(os.getcwd(), 'control-plane'))

from app import models

DATABASE_URL = "postgresql://user:password@localhost:5432/agent_registry"
ETCD_URL = "http://localhost:2379"

def seed():
    try:
        engine = create_engine(DATABASE_URL)
        Session = sessionmaker(bind=engine)
        db = Session()
    except Exception as e:
        print(f"Database connection failed: {e}")
        return

    # Create finance-agent
    agent = db.query(models.Agent).filter(models.Agent.name == "finance-agent").first()
    if not agent:
        agent = models.Agent(
            name="finance-agent",
            model_provider="openai",
            model_name="gpt-4o-mini",
            system_prompt="You are a financial analysis assistant. Use tools when necessary.",
            docker_container_name="finance-agent-1",
            status="inactive"
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)
        print(f"Created agent {agent.name}")

    # Create sentiment-analysis tool
    tool = db.query(models.Tool).filter(models.Tool.name == "analyze-sentiment").first()
    if not tool:
        tool = models.Tool(
            name="analyze-sentiment",
            description="Analyze sentiment of financial text.",
            tool_directory="tools/finance/analyze-sentiment",
            entry_point_module="main",
            entry_point_function="analyze_sentiment",
            etcd_secret_key="tools/finance/credentials",
            is_active=True
        )
        db.add(tool)
        db.commit()
        db.refresh(tool)
        print(f"Created tool {tool.name}")

    # Link tool to agent
    link = db.query(models.AgentToolLink).filter(
        models.AgentToolLink.agent_id == agent.id,
        models.AgentToolLink.tool_id == tool.id
    ).first()
    if not link:
        link = models.AgentToolLink(agent_id=agent.id, tool_id=tool.id)
        db.add(link)
        db.commit()
        print(f"Linked tool {tool.name} to agent {agent.name}")

    # Seed etcd
    try:
        host_port = ETCD_URL.replace("http://", "").replace("https://", "")
        host, port = host_port.split(":") if ":" in host_port else (host_port, "2379")
        client = etcd3gw.client(host=host, port=int(port))
        
        # Tool credentials
        tool_cred = {"api_key": "test_finance_key"}
        client.put("tools/finance/credentials", json.dumps(tool_cred))
        print("Seeded etcd with tool credentials.")

        # OpenAI key
        openai_key = os.environ.get("OPENAI_API_KEY", "sk-test-key")
        openai_cred = {"key": openai_key}
        client.put("providers/openai/api_key", json.dumps(openai_cred))
        print("Seeded etcd with OpenAI credentials.")
    except Exception as e:
        print(f"Etcd seed failed: {e}")

    db.close()

if __name__ == "__main__":
    seed()
