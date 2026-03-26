from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship, Mapped, mapped_column
from datetime import datetime
import uuid
from .database import Base

class Tool(Base):
    """Granular tool functions available in the All Tools MCP Server"""
    __tablename__ = 'tools'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_directory: Mapped[str] = mapped_column(String(512), nullable=False)
    entry_point_module: Mapped[str] = mapped_column(String(255), nullable=False)
    entry_point_function: Mapped[str] = mapped_column(String(255), nullable=False)
    etcd_secret_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    etcd_secret_key_reference: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent_tools = relationship("AgentToolLink", back_populates="tool")

class Agent(Base):
    """Agent definitions and configurations"""
    __tablename__ = 'agents'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_token: Mapped[str] = mapped_column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    model_provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default='inactive')
    docker_container_name: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    port_openai: Mapped[int] = mapped_column(Integer, default=8000)
    port_mcp: Mapped[int] = mapped_column(Integer, default=8001)
    port_a2a: Mapped[int] = mapped_column(Integer, default=8002)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tool_links = relationship("AgentToolLink", back_populates="agent")
    deployments = relationship("Deployment", back_populates="agent")

class AgentToolLink(Base):
    """Many-to-Many mapping: Tools assigned to Agents from All Tools MCP Server"""
    __tablename__ = 'agent_tool_links'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[int] = mapped_column(Integer, ForeignKey('agents.id'), nullable=False)
    tool_id: Mapped[int] = mapped_column(Integer, ForeignKey('tools.id'), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    agent = relationship("Agent", back_populates="tool_links")
    tool = relationship("Tool", back_populates="agent_tools")

class Deployment(Base):
    """Track agent deployments and their status"""
    __tablename__ = 'deployments'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[int] = mapped_column(Integer, ForeignKey('agents.id'), nullable=False)
    container_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    docker_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    health_status: Mapped[str] = mapped_column(String(50), default='unknown')
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = relationship("Agent", back_populates="deployments")
