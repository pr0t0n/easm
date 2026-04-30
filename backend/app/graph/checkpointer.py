import logging

from langgraph.checkpoint.memory import MemorySaver


logger = logging.getLogger(__name__)


def create_checkpointer():
    """Returns a LangGraph in-memory checkpointer.

    Production state is persisted via `scan_jobs.state_data` after each node;
    LangGraph checkpointer is used only for in-process step continuation.
    PostgresSaver was tried but its connection does not survive Celery worker
    forks, causing 'connection is closed' on every task.
    """
    return MemorySaver()
