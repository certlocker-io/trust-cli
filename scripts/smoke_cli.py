#!/usr/bin/env python3
"""Build/run the actual Linux CLI against an isolated, synthetic Edge HTTP server.

Exercises PKCE login, token/secret creation, get, update/put and cleanup.
This is a contract test, not evidence of a live Edge login or live 2FA.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from urllib.parse import parse_qs, urlencode, urlsplit


def main():
    assets, login, requests = {}, {}, []

    class Edge(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query)
            login.update({key: values[0] for key, values in query.items()})
            self.send_response(302)
            self.send_header('Location', login['redirect_uri'] + '?' + urlencode(
                {'state': login['state'], 'code': 'synthetic-code'}))
            self.end_headers()

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                path = self.path.removeprefix('/edge/rest/')
                requests.append(path)
                if path == 'security/v1/cli-token' and not body:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error_message":"missing code"}')
                    return
                if path == 'security/v1/cli-token':
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(body['code_verifier'].encode()).digest()).decode().rstrip('=')
                    assert challenge == login['code_challenge']
                    assert body['state'] == login['state']
                    assert body['redirect_uri'] == login['redirect_uri']
                    assert body['code'] == 'synthetic-code'
                    result = {'session_token': 'synthetic-session', 'email': 'fixture@example.test'}
                else:
                    assert self.headers['Authorization'] == 'Bearer synthetic-session'
                    if path == 'security/v1/sign-out':
                        result = {'success': True}
                    else:
                        resource, action, *tail = path.split('/')
                        if action == 'create':
                            identity = resource + '-fixture'
                            assets[identity] = dict(body, id=identity)
                            result = assets[identity]
                        elif action == 'detail':
                            result = assets[tail[0]]
                        elif action == 'modify':
                            assert body['id'] in assets
                            assets[body['id']] = body
                            result = body
                        elif action == 'revoke':
                            del assets[body['id']]
                            result = {'success': True}
                        else:
                            raise AssertionError('unexpected action')
                raw = json.dumps(result).encode()
                self.send_response(200)
            except Exception:
                raw = b'{"error_message":"fixture contract mismatch"}'
                self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Edge)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='trust-cli-smoke-') as temporary:
            directory = Path(temporary)
            binary = directory / 'trust'
            subprocess.run(['go', 'build', '-o', str(binary), './cmd/trust'],
                           cwd=Path(__file__).resolve().parents[1], check=True)
            # Intercept browser launch only for this subprocess. The synthetic
            # UI redirects to the CLI's real loopback callback.
            browser = directory / 'xdg-open'
            browser.write_text('#!' + sys.executable + '\nimport sys, urllib.request\nurllib.request.urlopen(sys.argv[1], timeout=10).close()\n')
            browser.chmod(0o700)
            env = {k: v for k, v in os.environ.items() if not k.startswith('TRUST_')}
            env.update(XDG_CONFIG_HOME=str(directory / 'config'), PATH=str(directory) + os.pathsep + env['PATH'])
            base = 'http://127.0.0.1:' + str(server.server_port)

            def run(*arguments, body=None):
                result = subprocess.run([str(binary), '--edge', base + '/edge/rest', '--ui', base,
                                         '--output', 'json', *arguments], env=env, input=body,
                                        capture_output=True, text=True, timeout=30)
                assert result.returncode == 0, 'CLI command failed: ' + ' '.join(arguments[:2])
                return json.loads(result.stdout) if result.stdout.strip() else None

            run('auth', 'login', '--timeout', '15s')
            credentials = directory / 'config/trust/credentials.json'
            assert credentials.stat().st_mode & 0o777 == 0o600
            assert run('auth', 'whoami')['email'] == 'fixture@example.test'
            run('tokens', 'create', '--name', 'synthetic-token', '--type', 'SECRET', '--duration', '1', '--unit', 'HOURS')
            assert run('tokens', 'get', 'token-fixture')['id'] == 'token-fixture'
            run('secrets', 'create', '--name', 'synthetic-secret', '--type', 'PASSWORD', '--secret', 'synthetic-value')
            run('secrets', 'put', 'secret-fixture', '--body', '-', body=json.dumps(
                {'name': 'synthetic-secret', 'secret_type': 'PASSWORD', 'secret': 'updated-synthetic-value', 'description': 'updated'}))
            assert assets['secret-fixture']['secret'] == 'updated-synthetic-value'
            assert run('secrets', 'get', 'secret-fixture')['description'] == 'updated'
            run('tokens', 'update', 'token-fixture', '--body', '-', body=json.dumps(
                {'name': 'synthetic-token', 'token_type': 'SECRET', 'description': 'updated'}))
            assert run('tokens', 'get', 'token-fixture')['description'] == 'updated'
            run('secrets', 'revoke', 'secret-fixture')
            run('tokens', 'revoke', 'token-fixture')
            assert not assets
            run('auth', 'logout')
            assert not credentials.exists()
            print(json.dumps({'environment': 'local HTTP fixture', 'binary': 'compiled from current source',
                              'pkce_login': True, 'credential_permissions_0600': True,
                              'token_create_get_update_revoke': True, 'secret_create_get_put_revoke': True,
                              'logout_cleanup': True, 'requests': requests}, indent=2))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
