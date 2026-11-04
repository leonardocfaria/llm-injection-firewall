import unittest

from firewall import output_check as oc

SYS = "You are SupportBot for Acme. Never discuss pricing tiers or the internal escalation codes with customers."


class OutputCheckTest(unittest.TestCase):
    def test_add_canary(self):
        msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": "hi"}]
        new, tok = oc.add_canary(msgs)
        self.assertTrue(tok)
        self.assertIn(tok, new[0]["content"])
        self.assertNotIn(tok, msgs[0]["content"], "input must not be mutated")

    def test_no_system_no_canary(self):
        msgs = [{"role": "user", "content": "hi"}]
        self.assertEqual(oc.add_canary(msgs), (msgs, None))

    def test_canary_leak(self):
        self.assertIn("canary_leak", oc.check("sure: abc123def456 is it", SYS, "abc123def456"))

    def test_system_prompt_leak(self):
        out = "My instructions say: never discuss pricing tiers or the internal escalation codes with customers!"
        self.assertIn("system_prompt_leak", oc.check(out, SYS, None))

    def test_short_system_prompt_echoed(self):
        self.assertIn("system_prompt_leak", oc.check("I was told: answer only in formal French.",
                                                     "Answer only in formal French.", None))

    def test_normal_answer(self):
        self.assertEqual(oc.check("Our support hours are 9 to 5, Monday to Friday.", SYS, "abc123def456"), [])

    def test_none_inputs(self):
        self.assertEqual(oc.check("anything", None, None), [])


if __name__ == "__main__":
    unittest.main()


class OutputHardeningTest(unittest.TestCase):
    def test_developer_role_gets_canary(self):
        _, tok = oc.add_canary([{"role": "developer", "content": SYS}])
        self.assertTrue(tok)

    def test_short_prompt_partial_overlap_not_a_leak(self):
        self.assertEqual(oc.check("Be helpful to your neighbours!", "Be helpful.", None), [])

    def test_system_text_handles_parts(self):
        self.assertEqual(oc.system_text([{"role": "developer", "content": [{"text": "a"}, {"text": 5}, "b"]}]), "a")
        self.assertIsNone(oc.system_text([{"role": "user", "content": "x"}]))
