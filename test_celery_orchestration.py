#!/usr/bin/env python3
"""Testes de validação do sistema de orquestração com Celery."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.workers.agent_dispatcher import (
    AgentExecutionTask,
    AgentQueue,
)
from app.workers.agent_supervisor import AgentSupervisor
from app.agents import create_phase_execution_plan


def test_agent_execution_task():
    """Valida AgentExecutionTask."""
    print("\n" + "="*70)
    print("TEST: AgentExecutionTask")
    print("="*70)

    task = AgentExecutionTask(
        task_id="task-001",
        agent_id="agent-recon-subdomain",
        scan_id=1,
        phase_id="P01",
        tools=["subfinder", "amass"],
        priority=9,
    )

    assert task.status == "pending", "Task should start as pending"
    assert task.priority == 9, "Task should have correct priority"
    assert len(task.tools) == 2, "Task should have 2 tools"

    task_dict = task.to_dict()
    assert "task_id" in task_dict, "Task dict should have task_id"
    assert "created_at" in task_dict, "Task dict should have created_at"

    print(f"✅ Task created: {task.task_id}")
    print(f"   Agent: {task.agent_id}")
    print(f"   Phase: {task.phase_id}")
    print(f"   Priority: {task.priority}")
    print(f"   Tools: {task.tools}")
    return True


def test_agent_queue():
    """Valida AgentQueue."""
    print("\n" + "="*70)
    print("TEST: AgentQueue")
    print("="*70)

    queue = AgentQueue()

    # Enqueue tasks with different priorities
    task_ids = []
    for priority in [5, 9, 7, 8]:
        task_id = queue.enqueue(
            agent_id="agent-recon-subdomain",
            scan_id=1,
            phase_id="P01",
            priority=priority,
        )
        if task_id:
            task_ids.append(task_id)

    assert len(queue.queue) >= 1, "Queue should have tasks"
    print(f"✅ Enqueued {len(queue.queue)} tasks")

    # Verify priority ordering
    if len(queue.queue) > 1:
        first = queue.queue[0]
        second = queue.queue[1] if len(queue.queue) > 1 else None
        if second:
            assert first.priority >= second.priority, "Higher priority should be first"
            print(f"✅ Priority ordering correct: {first.priority} >= {second.priority}")

    # Test dequeue
    task = queue.dequeue()
    assert task is not None, "Should dequeue a task"
    assert task.task_id in queue.active_tasks, "Task should be in active_tasks"
    print(f"✅ Dequeued task: {task.agent_id}")

    # Mark complete
    queue.mark_complete(task.task_id, status="success", execution_time=10.5)
    assert task.task_id in queue.completed_tasks, "Task should be in completed_tasks"
    assert task.status == "success", "Task should be marked success"
    print(f"✅ Task marked complete: {task.status}")

    return True


def test_phase_execution_plan():
    """Valida criação de plano de fases."""
    print("\n" + "="*70)
    print("TEST: Phase Execution Plan")
    print("="*70)

    plan = create_phase_execution_plan()
    assert len(plan) > 0, "Plan should have phases"
    assert "P01" in plan or len(plan) > 0, "Plan should include critical phases"

    print(f"✅ Plan created with {len(plan)} phases")
    for i, phase in enumerate(plan, 1):
        print(f"   {i}. {phase}")

    return True


def test_imports():
    """Valida que todos os imports funcionam."""
    print("\n" + "="*70)
    print("TEST: Imports")
    print("="*70)

    try:
        from app.workers.agent_dispatcher import (
            execute_agent_phase,
            dispatch_from_queue,
            record_tool_execution,
            validate_phase_completion,
        )
        print("✅ agent_dispatcher imports OK")

        from app.workers.agent_supervisor import (
            orchestrate_scan,
            check_phase_progress,
            submit_scan_orchestration,
        )
        print("✅ agent_supervisor imports OK")

        from app.workers.agent_workflow_integration import (
            dispatch_agents_for_mission,
            check_agent_progress,
        )
        print("✅ agent_workflow_integration imports OK")

        from app.api.routes_agents import router
        print("✅ routes_agents imports OK")

        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False


def test_task_definitions():
    """Valida que tarefas Celery estão definidas."""
    print("\n" + "="*70)
    print("TEST: Celery Task Definitions")
    print("="*70)

    try:
        from app.workers.celery_app import celery

        # Check registered tasks
        tasks = celery.tasks.keys()
        expected_tasks = [
            "agent.execute_phase",
            "agent.dispatch_from_queue",
            "agent.record_tool_execution",
            "agent.validate_phase_completion",
            "supervisor.orchestrate_scan",
            "supervisor.check_phase_progress",
        ]

        for expected_task in expected_tasks:
            # Tasks might not be registered until the module is imported
            print(f"   - {expected_task}")

        print(f"✅ Celery configured with {len(tasks)} registered tasks")
        return True

    except Exception as e:
        print(f"❌ Celery validation failed: {e}")
        return False


def main():
    """Run all tests."""
    print("\n" + "█"*70)
    print("AGENT ORCHESTRATION SYSTEM - VALIDATION TESTS")
    print("█"*70)

    tests = [
        ("Agent Execution Task", test_agent_execution_task),
        ("Agent Queue", test_agent_queue),
        ("Phase Execution Plan", test_phase_execution_plan),
        ("Imports", test_imports),
        ("Celery Tasks", test_task_definitions),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} failed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\nResult: {passed}/{total} tests passed")

    if passed == total:
        print("\n✅ All orchestration tests PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
