import re
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class DocumentationTests(unittest.TestCase):
    def test_relative_markdown_links_resolve(self):
        failures = []
        for markdown in ROOT.rglob("*.md"):
            if any(
                part in {".git", ".venv", "build", "dist"}
                for part in markdown.parts
            ):
                continue
            content = markdown.read_text(encoding="utf-8")
            for raw_target in LINK_RE.findall(content):
                target = raw_target.strip().split()[0].strip("<>")
                if not target or target.startswith(
                    ("http://", "https://", "mailto:", "#")
                ):
                    continue
                target = unquote(target.split("#", 1)[0])
                if not target:
                    continue
                resolved = (markdown.parent / target).resolve()
                try:
                    resolved.relative_to(ROOT.resolve())
                except ValueError:
                    failures.append(
                        f"{markdown.relative_to(ROOT)} -> {raw_target} escapes repository"
                    )
                    continue
                if not resolved.exists():
                    failures.append(
                        f"{markdown.relative_to(ROOT)} -> {raw_target}"
                    )
        self.assertEqual([], failures, "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
