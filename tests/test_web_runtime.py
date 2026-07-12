import tempfile
import unittest
from pathlib import Path

from app.web_runtime import WebBuildError, ensure_frontend_bundle, frontend_is_ready


class WebRuntimeTests(unittest.TestCase):
    def test_existing_bundle_skips_node_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "web" / "dist"
            (dist / "assets").mkdir(parents=True)
            (dist / "index.html").write_text("<html></html>", encoding="utf-8")

            self.assertTrue(frontend_is_ready(root))
            self.assertFalse(ensure_frontend_bundle(root))

    def test_missing_web_source_has_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(WebBuildError, "Web source directory is incomplete"):
                ensure_frontend_bundle(Path(directory))


if __name__ == "__main__":
    unittest.main()
