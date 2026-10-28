import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from prooftrail import server as server_module
from prooftrail.server import make_server


class TestRequestThrottle(unittest.TestCase):
    def test_address_over_limit_gets_429(self):
        # Narrow the cap for the test; production default is 300/min/IP.
        orig_max = server_module.REQUEST_MAX_PER_IP
        server_module.REQUEST_MAX_PER_IP = 3
        tmp = tempfile.TemporaryDirectory()
        try:
            server, _ = make_server("127.0.0.1", 0,
                                    str(Path(tmp.name) / "state.json"))
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port,
                                                  timeout=30)
                statuses = []
                for _ in range(4):
                    conn.request("GET", "/api/health")
                    resp = conn.getresponse()
                    resp.read()
                    statuses.append(resp.status)
                conn.close()
                self.assertEqual(statuses, [200, 200, 200, 429])
            finally:
                server.shutdown()
                server.server_close()
        finally:
            server_module.REQUEST_MAX_PER_IP = orig_max
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
