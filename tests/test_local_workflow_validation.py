import os
import stat
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/github/validate-workflow-locally.sh"


def test_local_workflow_validation_uses_only_safe_act_arguments(tmp_path):
    capture = tmp_path / "act-arguments"
    fake_act = tmp_path / "act"
    fake_act.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$CAPTURE_PATH\"\n",
        encoding="utf-8",
    )
    fake_act.chmod(fake_act.stat().st_mode | stat.S_IXUSR)

    result = subprocess.run(
        [str(SCRIPT)],
        cwd=ROOT,
        env={**os.environ, "ACT_BIN": str(fake_act), "CAPTURE_PATH": str(capture)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert capture.read_text(encoding="utf-8").splitlines() == [
        "pull_request",
        "--dryrun",
        "--strict",
        "--validate",
        "--secret-file",
        "/dev/null",
        "--env-file",
        "/dev/null",
        "--input-file",
        "/dev/null",
        "--var-file",
        "/dev/null",
        "--workflows",
        ".github/workflows/pipeline.yml",
    ]
