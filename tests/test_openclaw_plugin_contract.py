from __future__ import annotations

import json
import subprocess
from pathlib import Path

from agentguard_core import GuardEvent


PLUGIN_ROOT = Path("packages/agentguard-openclaw-plugin")


def _node_json(script: str) -> dict:
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_openclaw_tool_call_mapping_matches_guard_event_contract() -> None:
    event = _node_json(
        f"""
        import {{ buildToolCallGuardEvent }} from './{PLUGIN_ROOT}/dist/mapping.js';
        console.log(JSON.stringify(buildToolCallGuardEvent(
          {{
            toolName: 'read_file',
            params: {{ path: '/private/token.txt' }},
            toolCallId: 'call_contract',
            runId: 'run_contract',
            derivedPaths: ['/private/token.txt']
          }},
          {{ agentId: 'openclaw-main', sessionId: 'sess_contract', sessionKey: 'session-key' }}
        )));
        """
    )

    parsed = GuardEvent.model_validate(event)

    assert parsed.event_type == "tool_call_proposed"
    assert parsed.runtime == "openclaw"
    assert parsed.payload.tool.name == "read_file"
    assert parsed.payload.tool.call_id == "call_contract"


def test_openclaw_message_send_mapping_matches_guard_event_contract() -> None:
    event = _node_json(
        f"""
        import {{ buildMessageSendGuardEvent }} from './{PLUGIN_ROOT}/dist/mapping.js';
        console.log(JSON.stringify(buildMessageSendGuardEvent(
          {{
            to: 'reviewer@example.com',
            content: 'send summary to reviewer@example.com'
          }},
          {{ channelId: 'email', sessionKey: 'session-key', messageId: 'msg_contract' }}
        )));
        """
    )

    parsed = GuardEvent.model_validate(event)

    assert parsed.event_type == "message_send_proposed"
    assert parsed.runtime == "openclaw"
    assert parsed.payload.channel == "email"
    assert parsed.payload.recipient == "reviewer@example.com"
