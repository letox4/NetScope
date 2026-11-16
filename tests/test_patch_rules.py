import unittest

from core.interceptor import FridaInterceptor, MAX_PATCH_RULES


class FakeExports:
    def __init__(self):
        self.rules = None

    def set_rules(self, rules):
        self.rules = rules
        return len(rules)


class FakeScript:
    def __init__(self):
        self.exports_sync = FakeExports()


class PatchRuleTests(unittest.TestCase):
    def setUp(self):
        self.interceptor = FridaInterceptor(
            on_event=lambda event: None,
            on_status=lambda status: None,
            on_log=lambda message: None,
        )
        self.script = FakeScript()
        self.interceptor._script = self.script

    def test_normalizes_hex_and_installs_equal_length_rule(self):
        installed = self.interceptor.set_patch_rules([{
            'hex_match': 'AA bb',
            'hex_replace': 'cc DD',
        }])
        self.assertEqual(installed, 1)
        self.assertEqual(self.script.exports_sync.rules, [{
            'hex_match': 'aabb',
            'hex_replace': 'ccdd',
        }])

    def test_rejects_malformed_or_unequal_rules(self):
        for rule in (
                {'hex_match': 'gg', 'hex_replace': 'aa'},
                {'hex_match': 'aa', 'hex_replace': 'bbcc'},
                {'hex_match': '', 'hex_replace': ''}):
            with self.subTest(rule=rule):
                with self.assertRaises(ValueError):
                    self.interceptor.set_patch_rules([rule])
        self.assertIsNone(self.script.exports_sync.rules)

    def test_rejects_rule_count_above_agent_limit(self):
        rules = [
            {'hex_match': 'aa', 'hex_replace': 'bb'}
            for _ in range(MAX_PATCH_RULES + 1)
        ]
        with self.assertRaisesRegex(ValueError, 'máximo'):
            self.interceptor.set_patch_rules(rules)
        self.assertIsNone(self.script.exports_sync.rules)


if __name__ == '__main__':
    unittest.main()
