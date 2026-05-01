import sys
import types


def _install_langgraph_stub() -> None:
    langgraph_module = types.ModuleType("langgraph")
    langgraph_graph_module = types.ModuleType("langgraph.graph")
    langgraph_checkpoint_module = types.ModuleType("langgraph.checkpoint")
    langgraph_checkpoint_memory_module = types.ModuleType("langgraph.checkpoint.memory")

    class _DummyMemorySaver:
        pass

    langgraph_graph_module.END = "END"
    langgraph_graph_module.StateGraph = object
    langgraph_checkpoint_memory_module.MemorySaver = _DummyMemorySaver
    sys.modules.setdefault("langgraph", langgraph_module)
    sys.modules.setdefault("langgraph.graph", langgraph_graph_module)
    sys.modules.setdefault("langgraph.checkpoint", langgraph_checkpoint_module)
    sys.modules.setdefault("langgraph.checkpoint.memory", langgraph_checkpoint_memory_module)


def _install_dispatcher_stub() -> None:
    dispatcher_module = types.ModuleType("app.services.worker_dispatcher")
    dispatcher_module.execute_tool_with_workers = lambda *args, **kwargs: {"status": "executed"}
    sys.modules.setdefault("app.services.worker_dispatcher", dispatcher_module)


_install_langgraph_stub()
_install_dispatcher_stub()

from app.graph.mission import PENTEST_PHASES
from app.services.tool_catalog import TOOL_CATALOG
from app.graph.workflow import _tools_for_group
from app.workers.worker_groups import CANONICAL_GROUP_TOOLS


def test_phase_catalog_and_worker_groups_cover_the_same_tools() -> None:
    phase_tools = {tool for phase in PENTEST_PHASES for tool in phase.get("tools", [])}
    worker_tools = {tool for tools in CANONICAL_GROUP_TOOLS.values() for tool in tools}
    prompt_tools = set(TOOL_CATALOG.keys())

    assert worker_tools - phase_tools == set()
    assert phase_tools - worker_tools == set()
    assert worker_tools - prompt_tools == set()
    assert prompt_tools - worker_tools == set()


def test_graph_nodes_can_select_every_phase_tool_they_own() -> None:
    by_node: dict[str, set[str]] = {}
    for phase in PENTEST_PHASES:
        by_node.setdefault(str(phase["node"]), set()).update(phase.get("tools", []))

    for node, expected_tools in by_node.items():
        selectable = set(_tools_for_group("unit", node))
        assert expected_tools <= selectable
