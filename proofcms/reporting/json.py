from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from .console import redact_output


def write_json_report(path: Path | str, report: dict, overwrite: bool = False):
    """Atomically write a redacted JSON report without implicit overwrite."""
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if report_path.exists() and not overwrite:
        raise FileExistsError(f"report already exists: {report_path}")
    content = json.dumps(redact_output(report), indent=2, ensure_ascii=False)
    fd, temporary = tempfile.mkstemp(prefix=f".{report_path.name}.", suffix=".tmp", dir=report_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, report_path)
        else:
            try:
                os.link(temporary, report_path)
                os.unlink(temporary)
            except PermissionError:
                # Hard links can be denied on managed Windows folders even
                # when ordinary file creation is allowed. O_EXCL preserves
                # the no-implicit-overwrite contract without the
                # exists()+replace() race.
                out_fd = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    with os.fdopen(out_fd, "wb") as out, open(temporary, "rb") as src:
                        shutil.copyfileobj(src, out)
                        out.flush()
                        os.fsync(out.fileno())
                except Exception:
                    try:
                        os.unlink(report_path)
                    except FileNotFoundError:
                        pass
                    raise
                os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return report_path
