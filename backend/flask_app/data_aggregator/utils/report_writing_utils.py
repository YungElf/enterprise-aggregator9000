import base64
import csv
import io
import logging
import os
import re
import zipfile
import tempfile
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Tuple, Union

from dotenv import load_dotenv

from .env_utils import get_my_env

# Local defaults to replace external constants
REPORTS_REPO_NAME = "local-reports"
REPORTS_FOLDER = "reports"
FILE_RETENTION_DAYS = 30
PVC_BASE_PATH = "/tmp"
SURVEY_TYPE_LITERALS = str

my_env = get_my_env()

log = logging.getLogger()


# Minimal local replacement for missing proxy_management.models.developer_app.DeveloperApp
@dataclass
class DeveloperAppLocal:
    # Keep only fields we touch in helper functions
    uris: List[str]


# Minimal helpers to replace flask_app.web.utils.misc_utils

def get_current_date() -> str:
    return datetime.utcnow().strftime("%Y%m%d")


def days_between_dates(date1_yyyymmdd: str, date2_yyyymmdd: str) -> int:
    try:
        d1 = datetime.strptime(date1_yyyymmdd, "%Y%m%d")
        d2 = datetime.strptime(date2_yyyymmdd, "%Y%m%d")
        return abs((d2 - d1).days)
    except Exception:
        return 0


# Minimal local GithubService that reads/writes from the filesystem under REPORTS_FOLDER
class GithubService:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.getcwd()
        self.repo_root = os.path.join(self.base_dir, REPORTS_FOLDER)
        os.makedirs(self.repo_root, exist_ok=True)

    def get_repo(self, _name: str):
        os.makedirs(self.repo_root, exist_ok=True)
        return self

    @dataclass
    class _Entry:
        path: str
        name: str
        last_modified_datetime: Optional[datetime] = None

    def _abs(self, rel_path: str) -> str:
        return os.path.join(self.base_dir, rel_path)

    def get_file(self, rel_path: str) -> Union[None, _Entry, List[_Entry]]:
        abs_path = self._abs(rel_path)
        if os.path.isdir(abs_path):
            entries = []
            for name in os.listdir(abs_path):
                p = os.path.join(rel_path, name)
                st = os.stat(self._abs(p))
                entries.append(self._Entry(path=p, name=name, last_modified_datetime=datetime.fromtimestamp(st.st_mtime)))
            return entries
        if os.path.isfile(abs_path):
            st = os.stat(abs_path)
            return self._Entry(path=rel_path, name=os.path.basename(rel_path), last_modified_datetime=datetime.fromtimestamp(st.st_mtime))
        return None

    def get_raw_file_content(self, rel_path: str) -> str:
        with open(self._abs(rel_path), "r", newline="") as f:
            return f.read()

    def commit_file(self, rel_path: str, content: str) -> None:
        abs_path = self._abs(rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", newline="") as f:
            f.write(content)

    def delete_file(self, rel_path: str) -> None:
        abs_path = self._abs(rel_path)
        if os.path.isfile(abs_path):
            os.remove(abs_path)


def format_uris(devapp: Any):
    uris = getattr(devapp, "uris", None)
    if isinstance(uris, list):
        devapp.__dict__['uris'] = ', '.join(sorted(uris))
    return devapp


def format_csv_cell(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    formatted_text = ansi_escape.sub("", text)
    return formatted_text.replace("'", '')


def get_local_file_path(report_type):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, '..', '..', '..', '..', 'reports', report_type, my_env)


def get_pv_file_path(report_type) -> str:
    base_dir = PVC_BASE_PATH
    report_path = os.path.join(base_dir, 'reports', report_type, my_env)
    if not os.path.exists(report_path):
        os.makedirs(report_path)
    return str(report_path)


def get_git_file_path(report_type, file_name):
    return os.path.join('reports', report_type, my_env, file_name)


def write_local_file(csv_rows, file_name, report_type):
    file_path = os.path.join(get_local_file_path(report_type), file_name)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        for row in csv_rows:
            writer.writerow([format_csv_cell(str(cell)) for cell in row])
    log.debug(f"File written to local file {file_name}")


def write_latest_zipped_pv_file(csv_content, report_type):
    report_path = get_pv_file_path(report_type)
    output = io.StringIO()
    writer = csv.writer(output, delimiter=',', quoting=csv.QUOTE_MINIMAL, escapechar='\\', quotechar='"', lineterminator='\r\n')
    for row in csv_content:
        writer.writerow([format_csv_cell(str(cell)) for cell in row])
    csv_content = output.getvalue()
    latest_name = f"{report_type}_{my_env}_latest.csv"
    zip_name = latest_name.replace('.csv', '.zip')
    zipped_content = create_zip_file_from_string(latest_name, csv_content)
    zipped_content = base64.b64encode(zipped_content).decode()
    with open(os.path.join(report_path, zip_name), 'w', newline='') as f:
        f.write(zipped_content)
        log.debug(f"File written to zip file{zip_name}")


def write_pv_file(csv_rows, file_name, report_type):
    report_path = get_pv_file_path(report_type)
    with open(os.path.join(report_path, file_name), 'w', newline='') as f:
        for row in csv_rows:
            writer = csv.writer(f, delimiter=',', quoting=csv.QUOTE_MINIMAL, escapechar='\\', quotechar='"', lineterminator='\r\n')
            writer.writerow([format_csv_cell(str(cell)) for cell in row])
        log.debug(f"File written to pv file{file_name}")


def write_github_file(csv_rows, dated_file_name, report_type):
    with tempfile.NamedTemporaryFile(mode='w+', newline='', delete=False) as tmpfile:
        writer = csv.writer(tmpfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, escapechar='\\', quotechar='"', lineterminator='\r\n')
        for row in csv_rows:
            writer.writerow([format_csv_cell(str(cell)) for cell in row])
        tmpfile.flush()
        tmpfile.seek(0)
        csv_content = tmpfile.read()
    g = GithubService()
    try:
        g.commit_file(get_git_file_path(report_type, dated_file_name), csv_content)
        latest_name = f"{report_type}_{my_env}_latest.csv"
        zip_name = latest_name.replace('.csv', '.zip')
        zipped_content = create_zip_file_from_string(latest_name, csv_content)
        zipped_content = base64.b64encode(zipped_content).decode()
        g.commit_file(get_git_file_path(report_type, zip_name), zipped_content)
    except Exception as e:
        log.error(f"Unknown error committing file to {REPORTS_REPO_NAME}/{get_git_file_path(report_type, dated_file_name)}: {e}")
        return
    log.debug(f"File committed to {REPORTS_REPO_NAME}/{get_git_file_path(report_type, dated_file_name)}")


def load_latest_report(report_type: SURVEY_TYPE_LITERALS) -> Tuple[list, Optional[datetime]]:
    g = GithubService()
    g.get_repo(REPORTS_REPO_NAME)
    try:
        latest_file = g.get_file(os.path.join(REPORTS_FOLDER, report_type, my_env, f"{report_type}_{my_env}_latest.zip"))
        if latest_file and isinstance(latest_file, GithubService._Entry):
            csv_content = g.get_raw_file_content(latest_file.path)
            reader = csv.reader(csv_content.splitlines(), delimiter=',', quoting=csv.QUOTE_MINIMAL, escapechar='\\', quotechar='"', lineterminator='\r\n')
            output = []
            for row in reader:
                output.append(row)
            return output, latest_file.last_modified_datetime

    except Exception as e:
        log.debug(f"No latest report found for {report_type}" + str(e))
    return [], None


def stream_latest_report(report_type: SURVEY_TYPE_LITERALS):
    g = GithubService()
    g.get_repo(REPORTS_REPO_NAME)
    try:
        latest_file = g.get_file(os.path.join(REPORTS_FOLDER, report_type, my_env, f"{report_type}_{my_env}_latest.zip"))
        if latest_file and isinstance(latest_file, GithubService._Entry):
            csv_content = g.get_raw_file_content(latest_file.path)
            csv_buffer = io.StringIO(csv_content)
            reader = csv.reader(csv_buffer)
            for row in reader:
                yield row
    except Exception as e:
        log.debug(f"No latest report found for {report_type}" + str(e))


def write_csv_file(csv_rows, environment, report_type: SURVEY_TYPE_LITERALS) -> None:
    current_date = get_current_date()
    dated_file_name = f"{report_type}_{environment}_{current_date}.csv"
    if my_env == 'e0':
        write_local_file(csv_rows, dated_file_name, report_type)
    else:
        write_github_file(csv_rows, dated_file_name, report_type)
        # write_pv_file(csv_rows, dated_file_name, report_type)


def remove_old_survey_files(report_type: SURVEY_TYPE_LITERALS = None) -> int:
    current_date = get_current_date()
    g = GithubService()
    g.get_repo(REPORTS_REPO_NAME)
    count = 0
    try:
    if report_type:
        report_types = [report_type]
    else:
        reports_folder = os.path.join(REPORTS_FOLDER, my_env)
            items = g.get_file(reports_folder) or []
            report_types = [file.name for file in items if isinstance(items, list)]
        for rpt_type in report_types:
            files = g.get_file(os.path.join(REPORTS_FOLDER, rpt_type, my_env)) or []
            for file in files if isinstance(files, list) else []:
            file_date = re.search(r'\d{8}', file.name)
            if 'latest' not in file.name and (file_date and days_between_dates(file_date.group(0), current_date) > FILE_RETENTION_DAYS):
                g.delete_file(file.path)
                log.debug(f"Deleted old survey file: {file.name}")
                count += 1
    except Exception as e:
        log.debug(f"Error while cleaning old survey files: {e}")
    log.debug(f"Deleted {count} old survey files")
    return count


def csv_columns_equal(column1, column2):
    return [x.replace("\"", "").replace("'", "").strip() for x in column1] == [x.replace("\"", "").replace("'", "").strip() for x in column2]


def create_zip_file_from_string(file_name: str, content: str) -> bytes:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(file_name, content)
    return zip_buffer.getvalue()


def extract_file_from_zip(zip_content: bytes, expected_filename: str) -> str:
    with io.BytesIO(zip_content) as zip_buffer:
        with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
            with zip_file.open(expected_filename) as csv_file:
                return csv_file.read().decode()


if __name__ == '__main__':
    load_dotenv()
    remove_old_survey_files()
