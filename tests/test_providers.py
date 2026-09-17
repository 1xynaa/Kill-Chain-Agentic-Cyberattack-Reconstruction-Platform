import json

from backend.app.providers import decision_from_message


def test_decision_from_tool_call_normalizes_provider_message():
    message = {
        "content": None,
        "tool_calls": [
            {
                "function": {
                    "name": "tshark_details",
                    "arguments": json.dumps({"thought": "Inspect packet details", "done": False}),
                }
            }
        ],
    }
    assert json.loads(decision_from_message(message)) == {
        "thought": "Inspect packet details",
        "tool": "tshark_details",
        "done": False,
    }
