"""
Standardized message format for inter-model communication.
Ensures consistent data flow between DeepSeek, K2.5, Claude,
and the orchestrator, regardless of which model processes it.
"""
import json
from datetime import datetime
from typing import Any, Optional


class ARXONMessage:
    """Standardized message envelope for all inter-model communication."""

    def __init__(self, sender: str, receiver: str, msg_type: str,
                 content: Any, engagement_id: str = "",
                 parent_id: str = "", metadata: dict = None):
        self.id = f"msg_{int(datetime.utcnow().timestamp() * 1000)}"
        self.timestamp = datetime.utcnow().isoformat()
        self.sender = sender          # "orchestrator", "deepseek-reasoner", "kimi-k2.5", etc.
        self.receiver = receiver      # target model/component
        self.msg_type = msg_type      # "recon_request", "plan", "exploit_code", "verification", etc.
        self.content = content
        self.engagement_id = engagement_id
        self.parent_id = parent_id    # for chaining messages
        self.metadata = metadata or {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "receiver": self.receiver,
            "type": self.msg_type,
            "content": self.content,
            "engagement_id": self.engagement_id,
            "parent_id": self.parent_id,
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_prompt_context(self) -> str:
        """Format message as context for an LLM prompt."""
        return f"""[Message from {self.sender} | Type: {self.msg_type} | {self.timestamp}]
{json.dumps(self.content, indent=2, default=str) if isinstance(self.content, dict) else self.content}"""

    @classmethod
    def from_dict(cls, data: dict) -> 'ARXONMessage':
        msg = cls(
            sender=data["sender"],
            receiver=data["receiver"],
            msg_type=data["type"],
            content=data["content"],
            engagement_id=data.get("engagement_id", ""),
            parent_id=data.get("parent_id", ""),
            metadata=data.get("metadata", {})
        )
        msg.id = data.get("id", msg.id)
        msg.timestamp = data.get("timestamp", msg.timestamp)
        return msg


class MessageBus:
    """Simple in-memory message bus for tracking all inter-model communication."""

    def __init__(self):
        self.messages = []
        self.subscribers = {}

    def publish(self, message: ARXONMessage):
        self.messages.append(message)
        # Notify subscribers
        for pattern, callbacks in self.subscribers.items():
            if pattern == "*" or pattern == message.msg_type:
                for cb in callbacks:
                    cb(message)

    def subscribe(self, msg_type: str, callback):
        self.subscribers.setdefault(msg_type, []).append(callback)

    def get_chain(self, message_id: str) -> list:
        """Get full message chain (parent -> children)."""
        chain = []
        current = next((m for m in self.messages if m.id == message_id), None)
        while current:
            chain.insert(0, current)
            current = next((m for m in self.messages if m.id == current.parent_id), None)
        # Also get children
        children = [m for m in self.messages if m.parent_id == message_id]
        chain.extend(children)
        return chain

    def get_context_window(self, engagement_id: str,
                           last_n: int = 10) -> str:
        """Get recent message context for an engagement (for LLM prompts)."""
        relevant = [m for m in self.messages
                    if m.engagement_id == engagement_id][-last_n:]
        return "\n\n".join(m.to_prompt_context() for m in relevant)
