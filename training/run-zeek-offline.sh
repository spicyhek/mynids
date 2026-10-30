#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'Usage: bash run-zeek-offline.sh INPUT_CAPTURE NEW_OUTPUT_DIRECTORY\n' >&2
  exit 2
fi

capture_path=$(realpath -- "$1")
output_path=$(realpath -m -- "$2")
policy_path=$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/zeek-tunnel-policy.zeek")
image_ref='zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0'
if [[ ! -f "$capture_path" || -e "$output_path" ]]; then
  printf 'Input must exist and output directory must be new.\n' >&2
  exit 2
fi
install -d -m 700 -- "$output_path"

python3 - "$capture_path" "$output_path" "$image_ref" "$policy_path" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

capture, output, image, policy = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
with capture.open('rb') as handle:
    digest = hashlib.file_digest(handle, 'sha256').hexdigest()
policy_digest = hashlib.sha256(policy.read_bytes()).hexdigest()
image_id = subprocess.check_output(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], text=True).strip()
metadata = {'input_name': capture.name, 'input_bytes': capture.stat().st_size, 'input_sha256': digest,
            'image': image, 'local_image_id': image_id, 'started_utc': datetime.now(timezone.utc).isoformat(),
            'zeek_arguments': ['-C', '-r', '/input/capture', 'local', '/policy/tunnel-policy.zeek',
                               'LogAscii::use_json=T', 'LogAscii::json_timestamps=JSON::TS_EPOCH'],
            'policy_name': policy.name, 'policy_sha256': policy_digest,
            'network': 'none', 'memory_limit': '1g', 'cpu_limit': 1, 'checksum_ignoring': True}
(output / 'run-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
PY

docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --memory 1g --cpus 1 --pids-limit 128 --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:size=64m \
  --mount "type=bind,src=$capture_path,dst=/input/capture,readonly" \
  --mount "type=bind,src=$policy_path,dst=/policy/tunnel-policy.zeek,readonly" \
  --mount "type=bind,src=$output_path,dst=/output" --workdir /output \
  "$image_ref" /usr/local/zeek/bin/zeek -C -r /input/capture local /policy/tunnel-policy.zeek \
  LogAscii::use_json=T LogAscii::json_timestamps=JSON::TS_EPOCH \
  >"$output_path/console.log" 2>&1

python3 - "$output_path" <<'PY'
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
metadata = json.loads((output / 'run-metadata.json').read_text())
metadata['completed_utc'] = datetime.now(timezone.utc).isoformat()
metadata['exit_code'] = 0
metadata['files_sha256'] = {}
for path in output.glob('*.log'):
    with path.open('rb') as handle:
        metadata['files_sha256'][path.name] = hashlib.file_digest(handle, 'sha256').hexdigest()
(output / 'run-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(json.dumps({'status': 'completed', 'output_files': len(metadata['files_sha256'])}))
PY
