"""Red-team suite: every attack must be blocked or redacted, every benign look-alike allowed."""
import unittest
from pathlib import Path

from firewall import policy

HERE = Path(__file__).resolve().parent.parent / "redteam"


def load(name):
    for line in (HERE / name).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            role, _, text = line.partition("tool: ") if line.startswith("tool: ") else ("", "", line)
            yield ("tool" if line.startswith("tool: ") else "user"), text


def decide(role, text):
    msgs = [{"role": "user", "content": "Summarise the document."}] if role == "tool" else []
    return policy.apply(msgs + [{"role": role, "content": text}])["action"]


class RedTeamTest(unittest.TestCase):
    def test_attacks_not_allowed(self):
        cases = list(load("attacks.txt"))
        self.assertGreaterEqual(len(cases), 40)
        missed = [t for r, t in cases if decide(r, t) == "allow"]
        self.assertEqual(missed, [], f"{len(missed)}/{len(cases)} attacks allowed")

    def test_benign_allowed(self):
        cases = list(load("benign.txt"))
        self.assertGreaterEqual(len(cases), 30)
        flagged = [t for r, t in cases if decide(r, t) != "allow"]
        self.assertEqual(flagged, [], f"{len(flagged)}/{len(cases)} benign prompts flagged")


if __name__ == "__main__":
    unittest.main()
