"""Gateway configuration must retain the token obtained for that gateway."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('cached_issuer', ['https://old-cluster/realms/openshell', 'https://new-cluster/realms/openshell'])
def test_configure_keeps_gateway_login_token(tmp_path, cached_issuer):
    home = tmp_path / 'home'
    cached = home / '.config/openshell/oidc'
    cached.mkdir(parents=True)
    (cached / 'token.json').write_text(json.dumps({'issuer_url': cached_issuer, 'access_token': 'stale-token'}))
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    ca = scripts / 'extract-gateway-ca.sh'
    ca.write_text('#!/bin/sh\nmkdir -p "$(dirname "$OUT_FILE")"\nprintf ca > "$OUT_FILE"\n')
    ca.chmod(0o755)
    fakebin = tmp_path / 'bin'
    fakebin.mkdir()
    oc = fakebin / 'oc'
    oc.write_text('#!/bin/sh\nprintf https://new-gateway\n')
    oc.chmod(0o755)
    cli = fakebin / 'openshell'
    cli.write_text('''#!/bin/sh
if [ "$1 $2" = "gateway add" ]; then
  mkdir -p "$HOME/.config/openshell/gateways/test"
  printf '{"access_token":"fresh-token"}' > "$HOME/.config/openshell/gateways/test/oidc_token.json"
fi
''')
    cli.chmod(0o755)
    env = dict(os.environ, HOME=str(home), PATH=f'{fakebin}:{os.environ["PATH"]}')
    result = subprocess.run(['make', '-f', str(ROOT / 'Makefile-quickstart'),
                             'openshell-saw-configure-gateway', 'OPENSHELL_SAW_NAME=test',
                             'OIDC_ISSUER=https://new-cluster/realms/openshell',
                             f'OIDC_TOKEN_DIR={cached}', f'SCRIPTS_DIR={scripts}/'],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    saved = json.loads((home / '.config/openshell/gateways/test/oidc_token.json').read_text())
    assert saved['access_token'] == 'fresh-token'
