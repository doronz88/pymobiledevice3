import asyncio
from typing import Any

import pytest
from bpylist2 import archiver

from pymobiledevice3.services.accessibilityaudit import (
    AccessibilityAudit,
    AXAuditInspectorFocus_v1,
    AXAuditNode_v1,
    Direction,
    deserialize_object,
)

ELEMENT = bytes.fromhex("27000000006441A27C0000020600000000000000")


class _FakeAudit(AccessibilityAudit):
    """`AccessibilityAudit` with the DTX transport replaced by a recorder."""

    def __init__(self, replies: dict[str, Any], events: list[tuple[str, list[Any]]]) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], bool]] = []
        self._replies = replies
        self._event_queue = asyncio.Queue()
        self._events = events

    async def _ensure_ready(self) -> None:
        pass

    async def _invoke(self, selector: str, *args: Any, expects_reply: bool = True) -> Any:
        self.calls.append((selector, args, expects_reply))
        if selector == "deviceInspectorMoveWithOptions:":
            assert self._event_queue is not None
            for event in self._events:
                self._event_queue.put_nowait(event)
        return self._replies.get(selector)


def _focus_event(element: bytes, caption: str) -> tuple[str, list[Any]]:
    return (
        "hostInspectorCurrentElementChanged:",
        [
            [
                {
                    "ObjectType": "AXAuditInspectorFocus_v1",
                    "Value": {
                        "ObjectType": "passthrough",
                        "Value": {
                            "CaptionTextValue_v1": {"ObjectType": "passthrough", "Value": caption},
                            "ElementValue_v1": {
                                "ObjectType": "AXAuditElement_v1",
                                "Value": {
                                    "ObjectType": "passthrough",
                                    "Value": {
                                        "PlatformElementValue_v1": {"ObjectType": "passthrough", "Value": element}
                                    },
                                },
                            },
                        },
                    },
                }
            ]
        ],
    )


def test_serialize_element_and_attribute() -> None:
    assert AccessibilityAudit._serialize_element(ELEMENT) == {
        "ObjectType": "AXAuditElement_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {"PlatformElementValue_v1": {"ObjectType": "passthrough", "Value": ELEMENT}},
        },
    }
    assert AccessibilityAudit._serialize_attribute("Label") == {
        "ObjectType": "AXAuditElementAttribute_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {"AttributeNameValue_v1": {"ObjectType": "passthrough", "Value": "Label"}},
        },
    }


def test_serialized_arguments_survive_keyed_archiving() -> None:
    for arg in (AccessibilityAudit._serialize_element(ELEMENT), AccessibilityAudit._serialize_attribute("Value")):
        assert archiver.unarchive(archiver.archive(arg)) == arg


@pytest.mark.asyncio
async def test_element_attributes_invokes_value_for_attribute_and_decodes_reply() -> None:
    audit = _FakeAudit({"deviceElement:valueForAttribute:": {"ObjectType": "passthrough", "Value": "Flashlight"}}, [])

    assert await audit.element_attributes(ELEMENT, ["Label"]) == {"Label": "Flashlight"}
    assert audit.calls == [
        (
            "deviceElement:valueForAttribute:",
            (AccessibilityAudit._serialize_element(ELEMENT), AccessibilityAudit._serialize_attribute("Label")),
            True,
        )
    ]


@pytest.mark.asyncio
async def test_element_attribute_without_value_is_none() -> None:
    audit = _FakeAudit({}, [])
    assert await audit.element_attribute(ELEMENT, "Identifier") is None


def _hierarchy_node_reply(element: bytes) -> dict[str, Any]:
    """The archived ``AXAuditNode_v1`` shape the daemon returns for ``_AXHierarchyElementsAttribute``."""
    return {
        "ObjectType": "AXAuditNode_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {
                "HumanReadableRoleDescriptionValue_v1": {"ObjectType": "passthrough", "Value": "Button"},
                "HumanReadableDescriptionValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": "Show Notifications Button",
                },
                "IsIgnoredValue_v1": {"ObjectType": "passthrough", "Value": False},
                "AuditElementValue_v1": {
                    "ObjectType": "AXAuditElement_v1",
                    "Value": {
                        "ObjectType": "passthrough",
                        "Value": {"PlatformElementValue_v1": {"ObjectType": "passthrough", "Value": element}},
                    },
                },
            },
        },
    }


def test_deserialize_hierarchy_node_does_not_raise() -> None:
    # Regression: an AXAuditNode_v1 object (returned by _AXHierarchyElementsAttribute) used to raise
    # KeyError('AXAuditNode_v1') because the type was missing from SERIALIZABLE_OBJECTS.
    node = deserialize_object(_hierarchy_node_reply(ELEMENT))

    assert isinstance(node, AXAuditNode_v1)
    assert node.role_description == "Button"
    assert node.description == "Show Notifications Button"
    assert node.is_ignored is False
    assert node.element is not None and node.element.identifier == ELEMENT
    assert node.to_dict() == {
        "platform_identifier": ELEMENT.hex().upper(),
        "description": "Show Notifications Button",
        "role_description": "Button",
        "is_ignored": False,
    }


@pytest.mark.asyncio
async def test_element_attribute_decodes_hierarchy_node() -> None:
    audit = _FakeAudit({"deviceElement:valueForAttribute:": _hierarchy_node_reply(ELEMENT)}, [])

    node = await audit.element_attribute(ELEMENT, "_AXHierarchyElementsAttribute")

    assert isinstance(node, AXAuditNode_v1)
    assert node.element is not None and node.element.identifier == ELEMENT


@pytest.mark.asyncio
async def test_move_focus_and_wait_returns_focused_element() -> None:
    audit = _FakeAudit({}, [("hostAppStateChanged:", [[]]), _focus_event(ELEMENT, "Flashlight, Off, Button")])

    focus = await audit.move_focus_and_wait(Direction.Next)

    assert isinstance(focus, AXAuditInspectorFocus_v1)
    assert focus.caption == "Flashlight, Off, Button"
    assert focus.element is not None and focus.element.identifier == ELEMENT
    move = [call for call in audit.calls if call[0] == "deviceInspectorMoveWithOptions:"]
    assert move[0][1][0]["Value"]["direction"]["Value"] == Direction.Next.value


@pytest.mark.asyncio
async def test_move_focus_and_wait_times_out_when_focus_does_not_move() -> None:
    audit = _FakeAudit({}, [])
    with pytest.raises(TimeoutError):
        await audit.move_focus_and_wait(Direction.First, timeout=0.05)
