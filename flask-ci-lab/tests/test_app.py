import unittest
import requests

class TestFlaskApp(unittest.TestCase):
    def test_root(self):
        response = requests.get("http://localhost:5000/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Hello, world!"})

if __name__ == '__main__':
    unittest.main()

