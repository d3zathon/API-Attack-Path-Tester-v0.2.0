import time
from urllib.parse import urljoin

import httpx

from apiat.models.schema import Observation, Role


class HttpClient:
    def __init__(self, base_url: str, timeout: float = 10.0, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=False)
        self.requests_sent = 0

    def request(self, role: Role, method: str, path: str, *, path_values=None, params=None, json_body=None) -> Observation:
        rendered = path
        for key, value in (path_values or {}).items():
            rendered = rendered.replace("{" + key + "}", str(value))
        url = urljoin(self.base_url, rendered.lstrip("/"))
        start = time.perf_counter()
        try:
            response = self.client.request(
                method,
                url,
                headers=role.headers,
                params=params,
                json=json_body,
            )
            try:
                body = response.json()
            except ValueError:
                body = response.text
            return Observation(response.status_code, dict(response.headers), body, (time.perf_counter() - start) * 1000)
        except Exception as exc:
            return Observation(0, {}, {"error": str(exc)}, (time.perf_counter() - start) * 1000)
        finally:
            self.requests_sent += 1
