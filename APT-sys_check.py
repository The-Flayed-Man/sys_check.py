#!/your/custom/python/path/python3

from __future__ import annotations

import csv
import math
import os
import shlex
import subprocess
import sys
import zipfile

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape


# ==============================================================
# VALIDATION COMMANDS
# ==============================================================

OPTIONS_FIND_COMMAND = r'''find /apps/logs/$MIAX_ENV/startup_v2/$(date "+%Y-%m-%d")/ -maxdepth 1 -type f \( -name "app_startup_complete.flag" -o -name "pull_complete.flag" -o -name "injectBusinessLogic_complete.flag" \)'''
CTP_FIND_COMMAND = r'''find /apps/logs/ctp_startup/$(date "+%Y-%m-%d") -type f \( -path "*/flags-app_startup/app_startup_complete.flag" -o -path "*/flags-injection/ctp_inject_spins_complete.flag" -o -path "*/flags-validation/ctp_operational.flag" \)'''


OPTIONS_FLAGS = (
    "app_startup_complete.flag",
    "pull_complete.flag",
    "injectBusinessLogic_complete.flag",
)

CTP_FLAGS = (
    "app_startup_complete.flag",
    "ctp_inject_spins_complete.flag",
    "ctp_operational.flag",
)

OPTIONS_STARTUP_SCRIPTS = {
    "app_startup_complete.flag": "prepAppsForStartup.sh",
    "pull_complete.flag": "getMorningSpins.sh",
    "injectBusinessLogic_complete.flag": "injectBusinessLogic.sh",
}

TP_STARTUP_SCRIPTS = {
    "app_startup_complete.flag": "TP Start Apps",
    "ctp_inject_spins_complete.flag": "TP Inject Spins",
    "ctp_operational.flag": "TP Validation",
}


def get_stuck_startup_scripts(exchange: Exchange, result: CheckResult) -> str:
    if result.passed:
        return ""
    if not result.missing_flags:
        return "Unable to determine - remote check failed"
    mapping = (
        TP_STARTUP_SCRIPTS
        if exchange.expected_flags == CTP_FLAGS
        else OPTIONS_STARTUP_SCRIPTS
    )
    return "\n".join(
        mapping.get(flag, "Unknown script: " + flag)
        for flag in result.missing_flags
    )


# ==============================================================
# EXCHANGE CONFIGURATION
# ==============================================================

@dataclass(frozen=True)
class Exchange:
    name: str
    server: str
    find_command: str
    expected_flags: tuple[str, ...]
    iam: str = ""
    ctrl: str = ""


EXCHANGES = (
    Exchange(
        name="SIMU",
        server="",
        iam="jcopeland",
        ctrl="",
        find_command=OPTIONS_FIND_COMMAND,
        expected_flags=OPTIONS_FLAGS,
    )
)


# ==============================================================
# RESULT OBJECT
# ==============================================================

@dataclass
class CheckResult:
    exchange: str
    server: str
    passed: bool
    message: str

    found_flags: tuple[str, ...] = ()
    missing_flags: tuple[str, ...] = ()

    stuck_startup_script: str = ""
    exchange_startup_issue: str = ""
    resolution_status: str = ""
    sysops_member: str = ""


# ==============================================================
# SSH AND VALIDATION
# ==============================================================

def build_remote_command(exchange: Exchange) -> str:
    if exchange.iam and exchange.ctrl:
        assignments = (
            f"IAM={shlex.quote(exchange.iam)} "
            f"CTRL={shlex.quote(exchange.ctrl)}"
        )

        return (
            f"{assignments} "
            f"bash -ilc {shlex.quote(exchange.find_command)}"
        )

    return f"bash -ilc {shlex.quote(exchange.find_command)}"


def check_exchange(exchange: Exchange) -> CheckResult:
    print("=" * 70)
    print(f"Exchange: {exchange.name}")
    print(f"Server:   {exchange.server}")
    print("=" * 70)

    ssh_command = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        exchange.server,
        build_remote_command(exchange),
    ]

    try:
        completed = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )

    except subprocess.TimeoutExpired:
        message = (
            "RED - The Startup Process is NOT completed. "
            "The SSH connection timed out."
        )

        print(message)
        print()

        return CheckResult(
            exchange=exchange.name,
            server=exchange.server,
            passed=False,
            message=message,
        )

    except FileNotFoundError:
        message = (
            "RED - The Startup Process is NOT completed. "
            "The ssh command was not found."
        )

        print(message)
        print()

        return CheckResult(
            exchange=exchange.name,
            server=exchange.server,
            passed=False,
            message=message,
        )

    except OSError as error:
        message = (
            "RED - The Startup Process is NOT completed. "
            f"SSH error: {error}"
        )

        print(message)
        print()

        return CheckResult(
            exchange=exchange.name,
            server=exchange.server,
            passed=False,
            message=message,
        )

    if completed.returncode != 0:
        error_text = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"Remote command returned code {completed.returncode}"
        )

        error_text = (
            error_text
            .replace("\r", " ")
            .replace("\n", " ")
        )

        message = (
            "RED - The Startup Process is NOT completed. "
            f"Remote check failed: {error_text}"
        )

        print(message)
        print()

        return CheckResult(
            exchange=exchange.name,
            server=exchange.server,
            passed=False,
            message=message,
        )

    file_paths = [
        line.strip()
        for line in completed.stdout.replace("\r", "").splitlines()
        if line.strip().startswith("/")
    ]

    expected_flags = set(exchange.expected_flags)

    found_flags = {
        os.path.basename(file_path)
        for file_path in file_paths
        if os.path.basename(file_path) in expected_flags
    }

    ordered_found = tuple(
        flag
        for flag in exchange.expected_flags
        if flag in found_flags
    )

    ordered_missing = tuple(
        flag
        for flag in exchange.expected_flags
        if flag not in found_flags
    )

    if file_paths:
        print("Files found:")

        for file_path in file_paths:
            print(f"  {file_path}")
    else:
        print("No matching validation files were found.")

    print()

    if not ordered_missing:
        message = (
            "GREEN - The Startup Process is Completed."
        )

        print(message)
        print()

        return CheckResult(
            exchange=exchange.name,
            server=exchange.server,
            passed=True,
            message=message,
            found_flags=ordered_found,
        )

    if len(ordered_missing) == 1:
        message = (
            "RED - The Startup Process is NOT completed. "
            "The following flag is missing: "
            f"{ordered_missing[0]}"
        )
    else:
        message = (
            "RED - The Startup Process is NOT completed. "
            "The following flags are missing: "
            + ", ".join(ordered_missing)
        )

    print(message)
    print()

    return CheckResult(
        exchange=exchange.name,
        server=exchange.server,
        passed=False,
        message=message,
        found_flags=ordered_found,
        missing_flags=ordered_missing,
    )


# ==============================================================
# INTERACTIVE FOLLOW-UP QUESTIONS
# ==============================================================

def ask_required(question: str) -> str:
    while True:
        answer = input(question).strip()

        if answer:
            return answer

        print("Please enter a response.")


def collect_follow_up_information(
    results: list[CheckResult],
) -> None:
    failed_results = [
        result
        for result in results
        if not result.passed
    ]

    if not failed_results:
        print("=" * 70)
        print("All exchanges passed.")
        print("No follow-up information is required.")
        print("=" * 70)
        print()
        return

    print("=" * 70)
    print("FOLLOW-UP INFORMATION REQUIRED")
    print("=" * 70)

    for result in failed_results:
        print()
        print(f"Exchange: {result.exchange}")
        print(f"Status:   {result.message}")

        if result.missing_flags:
            print("Missing flags:")

            for flag in result.missing_flags:
                print(f"  {flag}")

        print()

        try:
            print("Associated startup scripts:")
            print(result.stuck_startup_script)

            result.exchange_startup_issue = ask_required(
                "What Exchange startup issue was identified? "
            )

            result.resolution_status = ask_required(
                "What is the current resolution status? "
            )

            result.sysops_member = ask_required(
                "Who is the owner working on the issue? "
            )

        except (EOFError, KeyboardInterrupt):
            print()
            print("Input was interrupted.")

            result.exchange_startup_issue = "Not provided"
            result.resolution_status = "Unknown"
            result.sysops_member = "Not assigned"

    print()


# ==============================================================
# CSV REPORT
# ==============================================================

def write_csv_report(
    results: list[CheckResult],
    output_path: Path,
) -> None:
    with output_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(
            (
                "EXCHANGE NAME",
                "EXCHANGE STARTUP STATUS",
                "STUCK STARTUP SCRIPT",
                "EXCHANGE STARTUP ISSUE",
                "RESOLUTION STATUS",
                "OWNER",
            )
        )

        for result in results:
            writer.writerow(
                (
                    result.exchange,
                    result.message,
                    result.stuck_startup_script,
                    result.exchange_startup_issue,
                    result.resolution_status,
                    result.sysops_member,
                )
            )


# ==============================================================
# EXCEL HELPERS
# ==============================================================

def clean_xml_text(value: str) -> str:
    cleaned_value = "".join(
        character
        for character in str(value)
        if character in "\t\n\r" or ord(character) >= 0x20
    )

    return escape(cleaned_value)


def excel_cell(
    reference: str,
    value: str,
    style: int,
) -> str:
    safe_value = clean_xml_text(value)

    return (
        f'<c r="{reference}" s="{style}" t="inlineStr">'
        f'<is><t xml:space="preserve">'
        f"{safe_value}"
        f"</t></is>"
        f"</c>"
    )


def estimate_wrapped_lines(
    text: str,
    approximate_characters_per_line: int,
) -> int:
    if not text:
        return 1

    line_count = 0

    for paragraph in text.splitlines() or [""]:
        line_count += max(
            1,
            math.ceil(
                len(paragraph)
                / approximate_characters_per_line
            ),
        )

    return line_count


def calculate_row_height(result: CheckResult) -> float:
    values_and_widths = (
        (result.exchange, 22),
        (result.message, 55),
        (result.stuck_startup_script, 30),
        (result.exchange_startup_issue, 45),
        (result.resolution_status, 28),
        (result.sysops_member, 30),
    )

    required_lines = max(
        estimate_wrapped_lines(value, width)
        for value, width in values_and_widths
    )

    return min(
        300,
        max(35, required_lines * 15 + 10),
    )


# ==============================================================
# EXCEL REPORT
# Creates a real XLSX file without openpyxl.
# ==============================================================

def write_excel_report(
    results: list[CheckResult],
    output_path: Path,
) -> None:
    rows = []

    rows.append(
        '<row r="1" ht="45" customHeight="1">'
        + excel_cell(
            "A1",
            "EXCHANGE NAME",
            1,
        )
        + excel_cell(
            "B1",
            "EXCHANGE STARTUP STATUS",
            1,
        )
        + excel_cell(
            "C1",
            "STUCK STARTUP SCRIPT",
            1,
        )
        + excel_cell(
            "D1",
            "EXCHANGE STARTUP ISSUE",
            1,
        )
        + excel_cell(
            "E1",
            "RESOLUTION STATUS",
            1,
        )
        + excel_cell(
            "F1",
            "OWNER",
            1,
        )
        + "</row>"
    )

    for row_number, result in enumerate(results, start=2):
        status_style = 2 if result.passed else 3
        row_height = calculate_row_height(result)

        rows.append(
            f'<row r="{row_number}" '
            f'ht="{row_height}" customHeight="1">'
            + excel_cell(
                f"A{row_number}",
                result.exchange,
                4,
            )
            + excel_cell(
                f"B{row_number}",
                result.message,
                status_style,
            )
            + excel_cell(
                f"C{row_number}",
                result.stuck_startup_script,
                4,
            )
            + excel_cell(
                f"D{row_number}",
                result.exchange_startup_issue,
                4,
            )
            + excel_cell(
                f"E{row_number}",
                result.resolution_status,
                4,
            )
            + excel_cell(
                f"F{row_number}",
                result.sysops_member,
                4,
            )
            + "</row>"
        )

    final_row = max(1, len(results) + 1)

    worksheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <dimension ref="A1:F{final_row}"/>

  <sheetViews>
    <sheetView workbookViewId="0">
      <pane
        ySplit="1"
        topLeftCell="A2"
        activePane="bottomLeft"
        state="frozen"
      />
    </sheetView>
  </sheetViews>

  <sheetFormatPr defaultRowHeight="15"/>

  <cols>
    <col min="1" max="1" width="22" customWidth="1"/>
    <col min="2" max="2" width="60" customWidth="1"/>
    <col min="3" max="3" width="35" customWidth="1"/>
    <col min="4" max="4" width="55" customWidth="1"/>
    <col min="5" max="5" width="35" customWidth="1"/>
    <col min="6" max="6" width="40" customWidth="1"/>
  </cols>

  <sheetData>
    {''.join(rows)}
  </sheetData>

  <autoFilter ref="A1:F{final_row}"/>
</worksheet>
"""

    styles_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font>
      <sz val="11"/>
      <name val="Calibri"/>
    </font>

    <font>
      <b/>
      <color rgb="FFFFFFFF"/>
      <sz val="11"/>
      <name val="Calibri"/>
    </font>
  </fonts>

  <fills count="5">
    <fill>
      <patternFill patternType="none"/>
    </fill>

    <fill>
      <patternFill patternType="gray125"/>
    </fill>

    <fill>
      <patternFill patternType="solid">
        <fgColor rgb="FF1F4E78"/>
        <bgColor indexed="64"/>
      </patternFill>
    </fill>

    <fill>
      <patternFill patternType="solid">
        <fgColor rgb="FF00B050"/>
        <bgColor indexed="64"/>
      </patternFill>
    </fill>

    <fill>
      <patternFill patternType="solid">
        <fgColor rgb="FFFF0000"/>
        <bgColor indexed="64"/>
      </patternFill>
    </fill>
  </fills>

  <borders count="1">
    <border>
      <left/>
      <right/>
      <top/>
      <bottom/>
      <diagonal/>
    </border>
  </borders>

  <cellStyleXfs count="1">
    <xf
      numFmtId="0"
      fontId="0"
      fillId="0"
      borderId="0"
    />
  </cellStyleXfs>

  <cellXfs count="5">
    <xf
      numFmtId="0"
      fontId="0"
      fillId="0"
      borderId="0"
      xfId="0"
    />

    <xf
      numFmtId="0"
      fontId="1"
      fillId="2"
      borderId="0"
      xfId="0"
      applyFont="1"
      applyFill="1"
      applyAlignment="1"
    >
      <alignment
        horizontal="center"
        vertical="center"
        wrapText="1"
      />
    </xf>

    <xf
      numFmtId="0"
      fontId="1"
      fillId="3"
      borderId="0"
      xfId="0"
      applyFont="1"
      applyFill="1"
      applyAlignment="1"
    >
      <alignment
        vertical="top"
        wrapText="1"
      />
    </xf>

    <xf
      numFmtId="0"
      fontId="1"
      fillId="4"
      borderId="0"
      xfId="0"
      applyFont="1"
      applyFill="1"
      applyAlignment="1"
    >
      <alignment
        vertical="top"
        wrapText="1"
      />
    </xf>

    <xf
      numFmtId="0"
      fontId="0"
      fillId="0"
      borderId="0"
      xfId="0"
      applyAlignment="1"
    >
      <alignment
        vertical="top"
        wrapText="1"
      />
    </xf>
  </cellXfs>

  <cellStyles count="1">
    <cellStyle
      name="Normal"
      xfId="0"
      builtinId="0"
    />
  </cellStyles>
</styleSheet>
"""

    content_types_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default
    Extension="rels"
    ContentType="application/vnd.openxmlformats-package.relationships+xml"
  />

  <Default
    Extension="xml"
    ContentType="application/xml"
  />

  <Override
    PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
  />

  <Override
    PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
  />

  <Override
    PartName="/xl/styles.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"
  />

  <Override
    PartName="/docProps/core.xml"
    ContentType="application/vnd.openxmlformats-package.core-properties+xml"
  />

  <Override
    PartName="/docProps/app.xml"
    ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"
  />
</Types>
"""

    package_relationships_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship
    Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"
  />

  <Relationship
    Id="rId2"
    Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
    Target="docProps/core.xml"
  />

  <Relationship
    Id="rId3"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"
    Target="docProps/app.xml"
  />
</Relationships>
"""

    workbook_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook
  xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
>
  <sheets>
    <sheet
      name="Startup Validation"
      sheetId="1"
      r:id="rId1"
    />
  </sheets>
</workbook>
"""

    workbook_relationships_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship
    Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"
  />

  <Relationship
    Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
    Target="styles.xml"
  />
</Relationships>
"""

    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    core_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
>
  <dc:creator>Startup Validation Report</dc:creator>

  <cp:lastModifiedBy>
    Startup Validation Report
  </cp:lastModifiedBy>

  <dcterms:created xsi:type="dcterms:W3CDTF">
    {timestamp}
  </dcterms:created>

  <dcterms:modified xsi:type="dcterms:W3CDTF">
    {timestamp}
  </dcterms:modified>
</cp:coreProperties>
"""

    app_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties
  xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
  xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
>
  <Application>
    Python Startup Validation Report
  </Application>
</Properties>
"""

    with zipfile.ZipFile(
        output_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as workbook:
        workbook.writestr(
            "[Content_Types].xml",
            content_types_xml,
        )

        workbook.writestr(
            "_rels/.rels",
            package_relationships_xml,
        )

        workbook.writestr(
            "docProps/core.xml",
            core_xml,
        )

        workbook.writestr(
            "docProps/app.xml",
            app_xml,
        )

        workbook.writestr(
            "xl/workbook.xml",
            workbook_xml,
        )

        workbook.writestr(
            "xl/_rels/workbook.xml.rels",
            workbook_relationships_xml,
        )

        workbook.writestr(
            "xl/styles.xml",
            styles_xml,
        )

        workbook.writestr(
            "xl/worksheets/sheet1.xml",
            worksheet_xml,
        )


# ==============================================================
# EMAIL REPORT
# ==============================================================

def email_excel_report(excel_path: Path) -> bool:
    mailtool = "/apps/ops/python3-libs/mailtool.py"
    recipient = "jcopeland@MIAXGlobal.com"
    sender = "jcopeland@MIAXGlobal.com"
    subject = "TSD SIMU MORNING REPORT"

    mail_command = [
        mailtool,
        "-t",
        recipient,
        "-l",
        str(excel_path.resolve()),
        "-s",
        subject,
        "-f",
        sender,
        "-x",
    ]

    print(f"Emailing Excel report to {recipient}...")

    try:
        completed = subprocess.run(
            mail_command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    except FileNotFoundError:
        print(
            "Email failed: mailtool was not found at "
            f"{mailtool}"
        )

        return False

    except subprocess.TimeoutExpired:
        print("Email failed: mailtool timed out.")
        return False

    except OSError as error:
        print(f"Email failed: {error}")
        return False

    if completed.returncode != 0:
        print("Email failed.")

        if completed.stdout.strip():
            print(completed.stdout.strip())

        if completed.stderr.strip():
            print(completed.stderr.strip())

        return False

    print(
        "Excel report emailed successfully to "
        f"{recipient}"
    )

    return True


# ==============================================================
# MAIN
# ==============================================================

def main() -> int:
    results = []

    for exchange in EXCHANGES:
        result = check_exchange(exchange)
        result.stuck_startup_script = get_stuck_startup_scripts(exchange, result)
        results.append(result)

    # Ask follow-up questions before creating the reports.
    collect_follow_up_information(results)

    report_date = date.today().isoformat()

    csv_path = Path(
        f"startup_validation_{report_date}.csv"
    )

    excel_path = Path(
        f"startup_validation_{report_date}.xlsx"
    )

    write_csv_report(
        results,
        csv_path,
    )

    write_excel_report(
        results,
        excel_path,
    )

    # Email only after all user responses are in the report.
    email_sent = email_excel_report(excel_path)

    passed_count = sum(
        1
        for result in results
        if result.passed
    )

    failed_count = len(results) - passed_count

    print()
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print(f"Total exchanges:  {len(results)}")
    print(f"Passed exchanges: {passed_count}")
    print(f"Failed exchanges: {failed_count}")
    print()

    print("Reports created:")
    print(f"  CSV:   {csv_path.resolve()}")
    print(f"  Excel: {excel_path.resolve()}")

    if email_sent:
        print("  Email: Sent successfully")
    else:
        print("  Email: FAILED")

    print()

    if failed_count == 0 and email_sent:
        print("Overall status: GREEN")
        return 0

    print("Overall status: RED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
