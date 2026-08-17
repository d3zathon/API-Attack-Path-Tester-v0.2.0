from pathlib import Path

from apiat.cli.main import build_parser
from apiat.reporting.json_report import write_json
from apiat.models.schema import ScanResult


def test_cli_uses_apiat_program_name():
    parser = build_parser()
    assert parser.prog == "apiat"


def test_scan_report_creates_parent(tmp_path: Path):
    result = ScanResult("http://example.test", [], [], 0, 0)
    output = tmp_path / "nested" / "report.json"
    write_json(result, str(output))
    assert output.exists()
