import unittest
from tools import scan_vulnerabilities


class TestScanner(unittest.TestCase):
    def test_hardcoded_secret(self):
        result = scan_vulnerabilities('API_KEY = "super-secret-123"')
        self.assertTrue(any(f["category"] == "Hardcoded secret/credential"
                            for f in result["findings"]))

    def test_eval(self):
        result = scan_vulnerabilities("eval(user_input)")
        self.assertTrue(any(f["category"] == "Dynamic code execution"
                            for f in result["findings"]))

    def test_sql_injection(self):
        code = 'query = "SELECT * FROM users WHERE id=" + user_id'
        result = scan_vulnerabilities(code)
        self.assertTrue(any(f["category"] == "SQL injection"
                            for f in result["findings"]))

    def test_shell_true(self):
        result = scan_vulnerabilities("subprocess.run(cmd, shell=True)")
        self.assertTrue(any(f["category"] == "Command injection"
                            for f in result["findings"]))

    def test_pickle(self):
        result = scan_vulnerabilities("pickle.loads(data)")
        self.assertTrue(any(f["category"] == "Insecure deserialization"
                            for f in result["findings"]))

    def test_weak_hash(self):
        result = scan_vulnerabilities("hashlib.md5(password)")
        self.assertTrue(any(f["category"] == "Weak/deprecated hashing"
                            for f in result["findings"]))

    def test_clean_code(self):
        result = scan_vulnerabilities("print('Hello, world!')")
        self.assertEqual(result["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
