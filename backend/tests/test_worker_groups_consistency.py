from app.workers.worker_groups import (
	CANONICAL_GROUP_TOOLS,
	SCHEDULED_WORKER_GROUPS,
	UNIT_WORKER_GROUPS,
	get_canonical_group_tools,
)


def test_unit_and_scheduled_have_same_tools_by_group() -> None:
	for group_name in ["recon", "osint", "vuln"]:
		assert UNIT_WORKER_GROUPS[group_name]["tools"] == SCHEDULED_WORKER_GROUPS[group_name]["tools"]


def test_alias_groups_match_primary_groups() -> None:
	assert UNIT_WORKER_GROUPS["reconhecimento"]["tools"] == UNIT_WORKER_GROUPS["recon"]["tools"]
	assert SCHEDULED_WORKER_GROUPS["reconhecimento"]["tools"] == SCHEDULED_WORKER_GROUPS["recon"]["tools"]
	assert UNIT_WORKER_GROUPS["analise_vulnerabilidade"]["tools"] == UNIT_WORKER_GROUPS["vuln"]["tools"]
	assert SCHEDULED_WORKER_GROUPS["analise_vulnerabilidade"]["tools"] == SCHEDULED_WORKER_GROUPS["vuln"]["tools"]


def test_canonical_groups_have_no_duplicates() -> None:
	for tools in CANONICAL_GROUP_TOOLS.values():
		assert len(tools) == len(set(tools))


def test_get_canonical_group_tools_returns_copy() -> None:
	first = get_canonical_group_tools()
	second = get_canonical_group_tools()
	assert first == second
	first["recon"].append("fake-tool")
	assert "fake-tool" not in second["recon"]
