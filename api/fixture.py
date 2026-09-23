from pathlib import Path

from fixtures.bradbury.service import fixture_service as _fixture_service

_fixture_service.MANIFEST_PATH = Path(__file__).with_name("agentseal-manifest-v1.json")
handler = _fixture_service._Handler
