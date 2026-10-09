import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings  # noqa: E402
from core.models import Resource  # noqa: E402
from core.pipeline import run_scan  # noqa: E402
from rag.retriever import Retriever  # noqa: E402
from rules import CloudEnv  # noqa: E402


@pytest.fixture(scope="session")
def scan():
    return run_scan()


@pytest.fixture(scope="session")
def retriever():
    return Retriever(settings.KNOWLEDGE_DIR)
