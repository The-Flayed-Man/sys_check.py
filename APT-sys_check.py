import argparse
import curses
import os
import re
import subprocess
import signal
import shlex
import tempfile
import bisect
import unicodedata
import threading
import time
from datetime import datetime
from collections import deque

DEFAULT_COMMAND = '/apps/miaxprod/scripts/miax_status'
APP_RE = re.compile(r'(?P<host>\S+)\s+(?P<id>\d+_[A-Za-z0-9]+_\d+)\s+(?P<version>\S+)(?P<rest>.*)', re.I)
STATUS_RE = re.compile(r'\[(running|down|starting|stopping|stopped|failed)\]', re.I)
PID_RE = re.compile(r'\bpid=(\d+)\b', re.I)
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
DEMO = 'dch4t1fgw01 00_FOI_183 3.34.0 pid=2954301 10:02 [running]\ndch4t1fgw02 00_FOI_185 3.34.0 pid=2910915 10:02 [running]\ndny4e1eqs01p 00_OFXD_018 3.0.0 [down]\ndny4t1inj01 01_INJ_001 4.12.0 pid=2874412 10:04 [running]\ndny4t1inj02 01_INJ_002 4.12.0 [starting]\n'

def parse_apps(output):
    result = {}
    for raw in output.splitlines():
        m = APP_RE.search(ANSI_RE.sub('', raw).strip())
        if not m:
            continue
        status = STATUS_RE.search(m.group('rest'))
        pid = PID_RE.search(m.group('rest'))
        cloud, app, instance = m.group('id').split('_', 2)
        row = {'host': m.group('host'), 'id': m.group('id'), 'cloud': cloud,
               'app': app, 'instance': instance, 'version': m.group('version'),
               'pid': pid.group(1) if pid else '-',
               'status': status.group(1).upper() if status else 'UNKNOWN'}
        result[row['id']] = row
    return result

# Cloudless rows use 0_FOI_1; application inventory uses 00_FOI_001.
CLOUDLESS_RE = re.compile(r'\b(?P<cloud>0)_(?P<app>[A-Za-z0-9]+)_(?P<instance>\d+)\b.*?\[(?P<state>[^]]+)\]', re.I)


def normalize_id(cloud, app, instance):
    return '{:02d}_{}_{:03d}'.format(int(cloud), app.upper(), int(instance))


def stream_state(raw):
    value = ANSI_RE.sub('', raw).upper()
    if 'SYNCING' in value and 'GAPPING' in value:
        return 'SYNC+GAP'
    if 'GAPPING' in value:
        return 'GAPPING'
    if 'SYNCING' in value:
        return 'SYNCING'
    if re.search(r'\b(FAIL|FAILED|FAILURE|ERROR)\b', value):
        return 'FAILED'
    if re.search(r'\bDOWN\b', value):
        return 'DOWN'
    if re.search(r'\bCURRENT\b', value):
        return 'CURRENT'
    return 'UNKNOWN'


def matched_stream_state(match):
    # The transport/result outcome overrides a quoted state on clouded rows.
    if match.groupdict().get('outcome', '').upper() in ('FAILURE', 'FAILED'):
        return 'FAILED'
    return stream_state(match.group('state'))


def parse_cloudless(output):
    result = {}
    for raw in output.splitlines():
        m = CLOUDLESS_RE.search(ANSI_RE.sub('', raw))
        if m:
            key = normalize_id(m.group('cloud'), m.group('app'), m.group('instance'))
            result[key] = matched_stream_state(m)
    return result


# Clouded bulk rows: 01_BOD_001 : 'Current' SUCCESS (50 usec)
CLOUDED_RE = re.compile(
    r"\b(?P<cloud>\d+)_(?P<app>[A-Za-z0-9]+)_(?P<instance>\d+)\s*:\s*"
    r"['\"](?P<state>[^'\"]+)['\"]\s+(?P<outcome>SUCCESS|FAILURE|FAILED)\b", re.I)
TARGET_RE = re.compile(
    r"(?:^|\s|:)['\"](?P<state>CURRENT|SYNCING(?:\s*\+\s*GAPPING|\s+AND\s+GAPPING)?|GAPPING|DOWN|FAILED?)['\"]\s+(?P<outcome>SUCCESS|FAILURE|FAILED)\b", re.I)
# An sc target can report only FAILURE (1001020 usec), without an app identifier.
BARE_STREAM_RESULT_RE = re.compile(r'^\s*(?P<state>FAILURE|FAILED|FAIL|DOWN)\s*\(\d+\s+usec\)\s*$', re.I | re.M)
CLOUDLESS_TARGET_RE = re.compile(r'^\s*\[\s*(?P<state>down|current|syncing|gapping|failed|failure)\s*\]\s*$', re.I | re.M)

CLOUDED_FAILURE_RE = re.compile(
    r"\b(?P<cloud>\d+)_(?P<app>[A-Za-z0-9]+)_(?P<instance>\d+)\s*:\s*"
    r"(?P<state>FAILURE|FAILED|FAIL)\s*\(\d+\s+usec\)", re.I)


def parse_clouded(output):
    result = {}
    for raw in output.splitlines():
        clean = ANSI_RE.sub('', raw)
        m = CLOUDED_RE.search(clean) or CLOUDED_FAILURE_RE.search(clean)
        if m:
            result[normalize_id(m.group('cloud'), m.group('app'), m.group('instance'))] = matched_stream_state(m)
    return result

def parse_target_stream(output, app_id=None):
    # Only recognize actual stream results, not shell startup/help text.
    clean = ANSI_RE.sub('', output)
    identified = parse_clouded(clean)
    identified.update(parse_cloudless(clean))
    if app_id is not None and identified:
        return identified.get(app_id, 'UNKNOWN')
    matches = []
    for pattern in (TARGET_RE, CLOUDED_RE, BARE_STREAM_RESULT_RE, CLOUDLESS_TARGET_RE):
        for m in pattern.finditer(clean):
            matches.append((m.start(), matched_stream_state(m)))
    return max(matches, key=lambda x: x[0])[1] if matches else 'UNKNOWN'


def stream_command(args):
    # Load the existing sc Bash function without invoking the login menu.
    # sc arguments are restricted to alphanumeric tokens.
    if not all(re.fullmatch(r'[A-Za-z0-9]+', str(x)) for x in args):
        raise ValueError('Invalid stream command argument')
    command = ('source "$HOME/Sysops_Production_Library" || exit; '
               'sc ' + ' '.join(str(x) for x in args))
    return ['bash', '--noprofile', '--norc', '-c', command]


def stream_group(row):
    groups = row.get('_inventory_groups', [])
    return groups[0] if groups else None


def group_stream_command(group, cloud, app, instance):
    if (not valid_group_name(group) or not str(cloud).isdigit() or
            not str(instance).isdigit() or not re.fullmatch(r'[A-Za-z0-9]+', app)):
        raise ValueError('Invalid group stream command argument')
    tokens = ['-g', group, str(int(cloud)), app, str(int(instance))]
    command = ('source "$HOME/Sysops_Production_Library" || exit; sc ' +
               ' '.join(shlex.quote(token) for token in tokens))
    return ['bash', '--noprofile', '--norc', '-c', command]


def command_result(argv, timeout, accept_inventory_nonzero=False, accept_stream_nonzero=False):
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, start_new_session=(os.name == 'posix'))
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # sc may spawn children: reap the whole query group before another starts.
            if os.name == 'posix':
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                proc.kill()
            proc.communicate()
            return None, 'Query timed out after {}s'.format(timeout)
    except OSError as exc:
        return None, str(exc)
    if proc.returncode:
        # Nonzero exit codes can be legitimate health results, not execution errors.
        # Accept only recognized stream evidence, never arbitrary shell/menu output.
        if accept_stream_nonzero and (parse_clouded(stdout) or
                                      parse_cloudless(stdout) or
                                      parse_target_stream(stdout) != 'UNKNOWN'):
            return stdout, None
        # miax_status may return 1 when applications are DOWN while still
        # providing a valid inventory.
        if accept_inventory_nonzero and parse_apps(stdout):
            return stdout, None
        return None, 'exit {}: {}'.format(proc.returncode, (stderr.strip() or stdout.strip())[:140])
    return stdout, None

LOG_LEVELS = ('ERROR', 'WARNING', 'INFO', 'ALL')
LOG_PATH = '/logs/miax.log'
# One scan, four independent bounded histories. Literal application matching
# avoids treating the inventory name as a shell or regular-expression command.
LOG_AWK = '\nfunction save(level, text, slot) {\n    count[level]++\n    slot = (count[level] - 1) % keep\n    if (length(text) > width) {\n        text = substr(text, 1, width) " [LINE TRUNCATED]"\n        clipped[level]++\n    }\n    history[level SUBSEP slot] = text\n}\nindex($0, app) {\n    save(4, $0)\n    lower = tolower($0)\n    if (index(lower, "error")) save(1, $0)\n    if (index(lower, "warning")) save(2, $0)\n    if (index(lower, "info")) save(3, $0)\n}\nEND {\n    for (level = 1; level <= 4; level++) {\n        start = count[level] > keep ? count[level] - keep : 0\n        for (i = start; i < count[level]; i++)\n            print level "\\t" history[level SUBSEP (i % keep)]\n        printf "COUNT\\t%d\\t%d\\t%d\\n", level, count[level], clipped[level]\n    }\n}\n'


def log_host(host):
    # Inventory hostnames only: no SSH options, user names or shell syntax.
    if len(host) > 253 or not all(re.fullmatch(
            r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
            for label in host.split('.')):
        raise ValueError('Invalid inventory hostname')
    labels = host.split('.')
    if not labels[0].lower().endswith('-a'):
        labels[0] += '-a'
    if len(labels[0]) > 63:
        raise ValueError('SSH hostname label is too long after adding -a')
    return '.'.join(labels)


def log_command(row, args):
    host = log_host(row['host'])
    match = row['id'] if args.log_match == 'id' else row['app']
    if not re.fullmatch(r'[A-Za-z0-9_]+', match):
        raise ValueError('Invalid application log filter')
    if args.log_ssh_user and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', args.log_ssh_user):
        raise ValueError('Invalid SSH user name')
    remote = ('LC_ALL=C awk -v app={app} -v keep={keep} -v width={width} '
              '{program} {path}').format(
                  app=shlex.quote(match), keep=int(args.log_history),
                  width=int(args.log_line_length), program=shlex.quote(LOG_AWK),
                  path=shlex.quote(LOG_PATH))
    argv = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout={}'.format(args.log_connect_timeout),
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=2']
    if args.log_ssh_user:
        argv += ['-l', args.log_ssh_user]
    return argv + ['--', host, remote]


def clean_log_line(line):
    # Log payloads must never write terminal escape/control sequences.
    line = ANSI_RE.sub('', line).expandtabs(4)
    return ''.join(ch if ch.isprintable() else '?' for ch in line)


def read_log_result(source, history):
    lines = [deque(maxlen=history) for _ in LOG_LEVELS]
    tags = tuple(str(i + 1) for i in range(len(LOG_LEVELS)))
    totals, clipped, metadata = [0] * len(LOG_LEVELS), [0] * len(LOG_LEVELS), set()
    for raw in source:
        raw = raw.rstrip('\r\n')
        tag, sep, text = raw.partition('\t')
        if tag in tags and sep:
            lines[int(tag) - 1].append(clean_log_line(text))
        elif tag == 'COUNT':
            parts = text.split('\t')
            if len(parts) != 3 or parts[0] not in tags:
                raise ValueError('Invalid log count result')
            index = int(parts[0]) - 1
            totals[index], clipped[index] = int(parts[1]), int(parts[2])
            if min(totals[index], clipped[index]) < 0:
                raise ValueError('Invalid negative log count')
            metadata.add(index)
    if metadata != set(range(len(LOG_LEVELS))):
        raise ValueError('Incomplete log response (no successful log scan confirmed)')
    if any(len(lines[i]) != min(totals[i], history) for i in range(len(LOG_LEVELS))):
        raise ValueError('Incomplete log history response')
    return [list(section) for section in lines], totals, clipped


def stop_log_process(proc):
    # Only terminate this locally spawned read-only SSH query, never an app.
    try:
        if os.name == 'posix':
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except OSError:
        pass
    proc.communicate()


def collect_logs(row, args, cancel):
    if cancel.is_set():
        raise RuntimeError('Log request cancelled')
    argv = log_command(row, args)
    # Bounded remote output is spooled to local temporary files, avoiding PIPE
    # deadlocks and an unbounded communicate() buffer for long histories.
    with tempfile.TemporaryFile(mode='w+b') as output, tempfile.TemporaryFile(mode='w+b') as errors:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                start_new_session=(os.name == 'posix'))
        deadline = time.monotonic() + args.log_timeout
        while True:
            if cancel.is_set():
                stop_log_process(proc)
                raise RuntimeError('Log request cancelled')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_log_process(proc)
                raise RuntimeError('Log query timed out after {}s'.format(args.log_timeout))
            try:
                proc.communicate(timeout=min(0.2, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if proc.returncode:
            errors.seek(0)
            detail = errors.read(2048).decode('utf-8', 'replace').strip()
            raise RuntimeError('SSH/log scan exit {}: {}'.format(
                proc.returncode, detail or 'No error details'))
        output.seek(0)
        decoded = (line.decode('utf-8', 'replace') for line in output)
        return read_log_result(decoded, args.log_history)


class LogReader(object):
    'One on-demand log worker, independent of production stream polling.'
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.row = None
        self.generation = 0
        self.filter_mode = None
        self.lines = [[] for _ in LOG_LEVELS]
        self.totals = [0] * len(LOG_LEVELS)
        self.clipped = [0] * len(LOG_LEVELS)
        self.checked = 0.0
        self.checked_wall = ''
        self.busy = False
        self.error = None
        self.pending = False
        self.next_allowed = 0.0
        self.next_auto = 0.0
        self.cancel_event = threading.Event()
        self.thread = None

    def select(self, row):
        with self.lock:
            self.cancel_event.set()
            self.generation += 1
            if (self.row is None or self.filter_mode != self.args.log_match or
                    (self.row['id'], self.row['host']) != (row['id'], row['host'])):
                self.lines = [[] for _ in LOG_LEVELS]
                self.totals = [0] * len(LOG_LEVELS)
                self.clipped = [0] * len(LOG_LEVELS)
                self.checked = 0.0
                self.checked_wall = ''
            self.row = dict(row)
            self.filter_mode = self.args.log_match
            self.error = None
            self.pending = True

    def refresh(self):
        with self.lock:
            if not self.busy:
                self.pending = True

    def cancel(self):
        with self.lock:
            self.pending = False
            self.cancel_event.set()

    def close(self):
        self.cancel()
        if self.thread:
            self.thread.join(timeout=1.0)

    def tick(self):
        now = time.monotonic()
        with self.lock:
            if self.row is None or self.busy:
                return
            auto_due = bool(self.args.log_refresh) and now >= self.next_auto
            if not (self.pending or auto_due) or now < self.next_allowed:
                return
            self.pending = False
            self.busy = True
            self.cancel_event = threading.Event()
            task = (dict(self.row), self.generation, self.cancel_event,
                    argparse.Namespace(**vars(self.args)))
            self.thread = threading.Thread(target=self._worker, args=task, daemon=True)
            self.thread.start()

    def _worker(self, row, generation, cancel, config):
        result, error = None, None
        try:
            if config.demo:
                history = config.log_history
                result = ([["{} {} {} demonstration log {:05d}".format(
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'), row['id'], level, i)
                    for i in range(1, min(history, 500) + 1)] for level in LOG_LEVELS],
                    [min(history, 500)] * len(LOG_LEVELS), [0] * len(LOG_LEVELS))
            else:
                result = collect_logs(row, config, cancel)
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                if generation == self.generation and not cancel.is_set():
                    if result is not None:
                        self.lines, self.totals, self.clipped = result
                        self.checked = time.monotonic()
                        self.checked_wall = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.error = error
                # Failed refreshes keep the last successful snapshot visible.
                self.busy = False
                self.next_allowed = time.monotonic() + self.args.log_min_refresh
                self.next_auto = time.monotonic() + self.args.log_refresh


class LogLayout(object):
    # Index wrapped rows without storing a second copy of the whole history.
    def __init__(self, lines, width, wrap=True):
        self.lines = lines
        self.width = max(2, width)
        self.wrap = wrap
        self.ends = []
        self.ascii = []
        total = 0
        for text in lines:
            try:
                text.encode('ascii')
                simple = True
            except UnicodeEncodeError:
                simple = False
            self.ascii.append(simple)
            count = (max(1, (len(text) + self.width - 1) // self.width) if simple else
                     len(wrap_log_line(text, self.width))) if wrap else 1
            total += count
            self.ends.append(total)
        self.total = total

    def locate(self, visual_row):
        if not self.lines:
            return 0, 0
        visual_row = min(max(0, visual_row), self.total - 1)
        index = bisect.bisect_right(self.ends, visual_row)
        return index, visual_row - (self.ends[index - 1] if index else 0)

    def anchor(self, visual_row):
        index, part = self.locate(visual_row)
        if not self.lines or not self.wrap:
            return index, 0
        if self.ascii[index]:
            return index, part * self.width
        chunks = wrap_log_line(self.lines[index], self.width)
        return index, sum(len(chunk) for chunk in chunks[:part])

    def anchored_row(self, anchor):
        if not self.lines:
            return 0
        index, offset = anchor
        index = min(index, len(self.lines) - 1)
        before = self.ends[index - 1] if index else 0
        if not self.wrap:
            return before
        if self.ascii[index]:
            part = offset // self.width
        else:
            part, consumed = 0, 0
            for chunk in wrap_log_line(self.lines[index], self.width):
                if consumed + len(chunk) > offset:
                    break
                consumed += len(chunk)
                part += 1
        return min(self.ends[index] - 1, before + part)

    def rows(self, start, height):
        if not self.lines or height <= 0:
            return []
        index, part = self.locate(start)
        result = []
        while index < len(self.lines) and len(result) < height:
            text = self.lines[index]
            if not self.wrap:
                chunks = [text]
            elif self.ascii[index]:
                # Slice only the visible tail of this message.
                limit = min(self.ends[index] - (self.ends[index - 1] if index else 0),
                            part + height - len(result))
                for chunk_index in range(part, limit):
                    result.append((text[chunk_index * self.width:(chunk_index + 1) * self.width], index))
                index += 1
                part = 0
                continue
            else:
                chunks = wrap_log_line(text, self.width)
            for chunk in chunks[part:part + height - len(result)]:
                result.append((chunk, index))
            index += 1
            part = 0
        return result


def wrap_log_line(text, width):
    # Standard-library display-cell handling, including wide and combining text.
    width = max(2, width)
    result, current, used = [], [], 0
    for char in text:
        cells = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1)
        if current and used + cells > width:
            result.append(''.join(current))
            current, used = [], 0
        current.append(char)
        used += cells
    if current or not result:
        result.append(''.join(current))
    return result


class LogScroll(object):
    def __init__(self):
        self.focus = 0
        self.top = [None] * len(LOG_LEVELS)  # None follows the newest retained lines.
        self.left = [0] * len(LOG_LEVELS)

    def position(self, section, count, height):
        maximum = max(0, count - height)
        if self.top[section] is None:
            return maximum
        self.top[section] = min(maximum, max(0, self.top[section]))
        return self.top[section]

    def move(self, delta, count, height):
        current = self.position(self.focus, count, height)
        self.top[self.focus] = min(max(0, count - height), max(0, current + delta))


def draw_logs(win, monitor, reader, row):
    scroll = LogScroll()
    layouts = [None] * len(LOG_LEVELS)
    wrap = getattr(monitor.args, 'log_wrap', True)
    reader.select(row)
    try:
        while True:
            monitor.tick(row)
            reader.tick()
            with reader.lock:
                lines = reader.lines  # Snapshots are replaced, never mutated.
                totals = list(reader.totals)
                clipped = list(reader.clipped)
                checked = reader.checked_wall
                busy, error = reader.busy, reader.error
                pending = reader.pending
                wait = max(0, int(reader.next_allowed - time.monotonic()) + 1)
            h, w = win.getmaxyx()
            for section in range(len(LOG_LEVELS)):
                old = layouts[section]
                if (old is None or old.lines is not lines[section] or
                        old.width != max(2, w - 1) or old.wrap != wrap):
                    anchor = old.anchor(scroll.top[section]) if old is not None and scroll.top[section] is not None else None
                    layouts[section] = LogLayout(lines[section], w - 1, wrap)
                    if anchor is not None:
                        scroll.top[section] = layouts[section].anchored_row(anchor)
            win.erase()
            try:
                host = log_host(row['host'])
            except ValueError:
                host = 'INVALID HOST'
            safe_add(win, 0, 0, 'APPLICATION LOGS | {} | SSH {} | READ-ONLY{}'.format(
                row['id'], host, ' | DEMO' if monitor.args.demo else ''), 1, True)
            match = row['id'] if monitor.args.log_match == 'id' else row['app']
            safe_add(win, 1, 0, '{} | literal filter {} | latest {} lines/section'.format(
                LOG_PATH, match, monitor.args.log_history), 1)
            safe_add(win, 2, 0, 'Last successful: {} | {}'.format(checked or 'NEVER',
                'COLLECTING' if busy else ('QUEUED ({}s)'.format(wait) if pending else 'SNAPSHOT')),
                4 if busy or pending else 2)
            heights = [0] * len(LOG_LEVELS)
            if h >= 20:
                space = h - 7
                y = 3
                for section, label in enumerate(LOG_LEVELS):
                    block = space // len(LOG_LEVELS) + (1 if section < space % len(LOG_LEVELS) else 0)
                    height = max(0, block - 1)
                    heights[section] = height
                    layout = layouts[section]
                    start = scroll.position(section, layout.total, height)
                    displayed = layout.rows(start, height)
                    first = displayed[0][1] + 1 if displayed else 0
                    last = displayed[-1][1] + 1 if displayed else 0
                    title = '{} {} | retained {}/{} | messages {}-{} | {}{}'.format(
                        '>' if scroll.focus == section else ' ', label,
                        len(lines[section]), totals[section], first, last,
                        'WRAP ON' if wrap else 'column {}'.format(scroll.left[section] + 1),
                        ' | truncated lines {}'.format(clipped[section]) if clipped[section] else '')
                    safe_add(win, y, 0, title, 1 if scroll.focus == section else 4, True)
                    for index, item in enumerate(displayed):
                        text = item[0] if wrap else item[0][scroll.left[section]:]
                        safe_add(win, y + 1 + index, 0, text,
                                 3 if section == 0 else 4 if section == 1 else 2, cell_fitted=wrap)
                    if not lines[section] and height:
                        safe_add(win, y + 1, 0, 'Awaiting log scan' if not checked else 'No matching lines', 4)
                    y += block
            else:
                safe_add(win, 4, 0, 'Resize terminal to at least 20 rows for all four sections.', 4)
            safe_add(win, h - 4, 0, clean_log_line(error) if error else
                     'Stream and inventory monitoring continue. Refresh preserves logs on failure.',
                     3 if error else 1)
            safe_add(win, h - 3, 0, 'TAB / 1 2 3 4 Section | UP/DOWN Scroll | PgUp/PgDn Page | HOME/END Oldest/Newest', 1)
            safe_add(win, h - 2, 0, 'W Wrap | LEFT/RIGHT Pan when unwrapped | R Refresh | M ID/Type | ESC/Q/ENTER Back', 1)
            safe_add(win, h - 1, 0, 'History: current miax.log only; oldest at top, newest at bottom. No remote writes.', 1)
            win.refresh()
            key = win.getch()
            if key in (27, ord('q'), ord('Q'), 10, 13, curses.KEY_ENTER):
                break
            if key == 9:
                scroll.focus = (scroll.focus + 1) % len(LOG_LEVELS)
            elif key in (ord('1'), ord('2'), ord('3'), ord('4')):
                scroll.focus = key - ord('1')
            elif key == curses.KEY_BTAB:
                scroll.focus = (scroll.focus - 1) % len(LOG_LEVELS)
            elif key in (curses.KEY_UP, ord('k')):
                scroll.move(-1, layouts[scroll.focus].total, heights[scroll.focus])
            elif key in (curses.KEY_DOWN, ord('j')):
                scroll.move(1, layouts[scroll.focus].total, heights[scroll.focus])
            elif key == curses.KEY_PPAGE:
                scroll.move(-max(1, heights[scroll.focus]), layouts[scroll.focus].total, heights[scroll.focus])
            elif key == curses.KEY_NPAGE:
                scroll.move(max(1, heights[scroll.focus]), layouts[scroll.focus].total, heights[scroll.focus])
            elif key == curses.KEY_HOME:
                scroll.top[scroll.focus] = 0
            elif key == curses.KEY_END:
                scroll.top[scroll.focus] = None
            elif key in (ord('w'), ord('W')):
                wrap = not wrap
                monitor.args.log_wrap = wrap
            elif key == curses.KEY_LEFT and not wrap:
                scroll.left[scroll.focus] = max(0, scroll.left[scroll.focus] - 8)
            elif key == curses.KEY_RIGHT and not wrap:
                longest = max([len(line) for line in lines[scroll.focus]] or [0])
                scroll.left[scroll.focus] = min(max(0, longest - 1), scroll.left[scroll.focus] + 8)
            elif key in (ord('m'), ord('M')):
                monitor.args.log_match = 'type' if monitor.args.log_match == 'id' else 'id'
                reader.select(row)
                scroll = LogScroll()
            elif key in (ord('r'), ord('R')):
                reader.refresh()
            time.sleep(0.1)
    finally:
        reader.cancel()


def valid_group_name(value):
    return bool(value and value.strip() and len(value) <= 256 and
                all(char.isprintable() for char in value))


def merge_inventory_sources(sources, groups):
    merged, conflicts = {}, []
    for source in [None] + list(groups):
        for key, original in sources.get(source, {}).items():
            previous = merged.get(key)
            if previous and previous['host'] != original['host']:
                conflicts.append('{} has conflicting hosts in {}'.format(key, source or 'default'))
                continue
            row = dict(original)
            memberships = list(previous.get('_inventory_groups', [])) if previous else []
            if source is not None and source not in memberships:
                memberships.append(source)
            row['_inventory_groups'] = memberships
            row['_inventory_default'] = source is None or bool(previous and previous.get('_inventory_default'))
            merged[key] = row
    return merged, conflicts


def app_status_command(args, row):
    groups = row.get('_inventory_groups', [])
    if groups and not row.get('_inventory_default', False):
        # Only the known group syntax is assumed; do not combine undocumented
        # -g/-c/-t/-i flags. Select the requested row from the returned inventory.
        return [args.command, '-g', groups[0]]
    return [args.command, '-c', str(int(row['cloud'])),
            '-t', row['app'], '-i', str(int(row['instance']))]


class Monitor(object):
    def __init__(self, args):
        self.args = args
        self.logs = LogReader(args)
        self.args.group = list(getattr(args, 'group', []))
        self.lock = threading.Lock()
        self.inventory_sources = {}
        self.inventory_source_checked = {}
        self.inventory_source_errors = {}
        self.full_requested = False
        self.rows = {}
        self.full_checked = 0.0
        self.full_attempted = 0.0
        self.full_error = 'Awaiting first inventory'
        self.full_busy = False
        self.target_id = None
        self.target_checked = 0.0
        self.target_attempted = 0.0
        self.target_error = None
        self.target_busy = False
        self.target_row = None
        self.stream_rows = {}
        self.stream_row_checked = {}  # Last known status timestamp per application
        self.stream_checked = 0.0
        self.stream_attempted = 0.0
        self.stream_error = 'Awaiting cloud stream collection'
        self.stream_cloud_errors = {}
        self.stream_cloud_checked = {}
        self.stream_busy = False
        self.stream_target_id = None
        self.stream_target_state = None
        self.stream_target_checked = 0.0
        self.stream_target_attempted = 0.0
        self.stream_target_error = None
        self.stream_target_busy = False
        self.stop_event = threading.Event()
        self.stream_wake = threading.Event()
        self.stream_manual = deque()
        self.stream_manual_ids = set()
        self.stream_bulk_requested = True
        self.stream_missing = set()
        self.stream_target_attempts = {}
        self.stream_row_errors = {}
        self.stream_completed = 0
        self.stream_total = 0
        self.stream_next_target = 0.0
        self.stream_last_bulk_end = 0.0
        self.stream_pending_clouds = deque()
        self.stream_allow_target = False
        self.stream_active_cloud = None
        self.stream_thread = threading.Thread(target=self._stream_loop, daemon=True)
        self.stream_thread.start()
        self.request_full()
        # Bulk stream collection begins after inventory discovers the clouds.

    def request_full(self):
        with self.lock:
            if self.full_busy:
                return
            self.full_busy = True
            self.full_requested = False
            self.full_attempted = time.monotonic()
        threading.Thread(target=self._full_worker, daemon=True).start()

    def _full_worker(self):
        if self.args.group:
            self._group_full_worker()
            return
        rows, error = None, None
        try:
            if self.args.demo:
                rows = parse_apps(DEMO)
            else:
                output, error = command_result([self.args.command], self.args.full_timeout,
                                               accept_inventory_nonzero=True)
                if output is not None:
                    rows = parse_apps(output)
            if rows is not None and not rows:
                error = 'No recognized application rows (verify command output)'
            if rows is not None and any(r['status'] == 'UNKNOWN' for r in rows.values()):
                error = 'Some application statuses could not be parsed'
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                if rows:
                    if set(rows) != set(self.rows):
                        self.stream_bulk_requested = True
                        self.stream_wake.set()
                    self.rows = rows
                    self.full_checked = time.monotonic()
                self.full_error = error
                self.full_busy = False

    def add_group(self, group):
        group = group.strip()
        if not valid_group_name(group):
            raise ValueError('Group name must be printable, nonempty and at most 256 characters')
        with self.lock:
            if None not in self.inventory_sources and self.rows:
                self.inventory_sources[None] = {key: dict(row) for key, row in self.rows.items()
                    if row.get('_inventory_default', True)}
            if group not in self.args.group:
                self.args.group = self.args.group + [group]
            self.full_requested = True
        self.request_full()

    def _group_full_worker(self):
        # Group scans are additional discovery sources, not a view-only filter.
        with self.lock:
            groups = list(self.args.group)
        try:
            for source in [None] + groups:
                if self.stop_event.is_set():
                    break
                error, rows = None, None
                try:
                    if self.args.demo:
                        rows = parse_apps(DEMO)
                    else:
                        argv = [self.args.command] + (['-g', source] if source is not None else [])
                        output, error = command_result(argv, self.args.full_timeout,
                                                       accept_inventory_nonzero=True)
                        if output is not None:
                            rows = parse_apps(output)
                    if rows is not None and not rows:
                        error = 'No recognized application rows'
                    if rows and any(row['status'] == 'UNKNOWN' for row in rows.values()):
                        error = 'Some application statuses could not be parsed'
                except Exception as exc:
                    error = '{}: {}'.format(type(exc).__name__, exc)
                with self.lock:
                    if rows:
                        self.inventory_sources[source] = rows
                        self.inventory_source_checked[source] = time.monotonic()
                    if error:
                        self.inventory_source_errors[source] = error
                    else:
                        self.inventory_source_errors.pop(source, None)
                    merged, conflicts = merge_inventory_sources(self.inventory_sources, self.args.group)
                    if merged:
                        if set(merged) != set(self.rows):
                            self.stream_bulk_requested = True
                            self.stream_wake.set()
                        changed_routes = {key for key, row in merged.items() if
                            stream_group(row) != stream_group(self.rows.get(key, {}))}
                        if changed_routes:
                            self.stream_bulk_requested = True
                            self.stream_wake.set()
                        for key in changed_routes:
                            self.stream_target_attempts.pop(key, None)
                        self.stream_missing.update(key for key, row in merged.items() if stream_group(row))
                        self.rows = merged
                    if rows:
                        self.full_checked = time.monotonic()
                    errors = ['{}: {}'.format(name if name is not None else 'default', message)
                              for name, message in self.inventory_source_errors.items()]
                    self.full_error = '; '.join(errors + conflicts) or None
        except Exception as exc:
            with self.lock:
                self.full_error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                self.full_busy = False


    def request_target(self, row):
        with self.lock:
            if self.target_busy:
                return
            self.target_busy = True
            self.target_id = row['id']
            self.target_attempted = time.monotonic()
            self.target_error = None
            self.target_row = None
        threading.Thread(target=self._target_worker, args=(dict(row),), daemon=True).start()

    def _target_worker(self, row):
        found, error = None, None
        try:
            if self.args.demo:
                parsed = parse_apps(DEMO)
            else:
                argv = app_status_command(self.args, row)
                output, error = command_result(argv, self.args.target_timeout,
                                                accept_inventory_nonzero=True)
                parsed = parse_apps(output) if output is not None else {}
            found = parsed.get(row['id'])
            if not error and not found:
                error = 'Selected instance not found in targeted output'
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                # A selection change cannot overwrite the details of a newer target.
                if self.target_id == row['id']:
                    self.target_row = found
                    self.target_error = error
                    self.target_checked = time.monotonic() if found else 0.0
                self.target_busy = False

    def request_stream_bulk(self):
        with self.lock:
            if not self.stream_busy:
                self.stream_bulk_requested = True
        self.stream_wake.set()

    def close(self):
        self.logs.close()
        self.stop_event.set()
        self.stream_wake.set()
        # An in-flight read-only query finishes or reaches its configured timeout.
        self.stream_thread.join(timeout=1.0)

    def _stream_loop(self):
        while not self.stop_event.is_set():
            now = time.monotonic()
            row, cloud = None, None
            with self.lock:
                if not self.stream_busy and self.rows and (self.stream_bulk_requested or
                        now - self.stream_last_bulk_end >= self.args.stream_bulk_refresh):
                    self.stream_pending_clouds = deque(sorted(set(
                        r['cloud'] for r in self.rows.values() if not stream_group(r))))
                    self.stream_cloud_errors = {key: message for key, message in self.stream_cloud_errors.items()
                        if key in self.stream_pending_clouds}
                    self.stream_total = len(self.stream_pending_clouds)
                    self.stream_completed = 0
                    self.stream_busy = bool(self.stream_pending_clouds)
                    self.stream_missing.update(key for key, row in self.rows.items() if stream_group(row))
                    if not self.stream_busy:
                        self.stream_last_bulk_end = now
                    self.stream_bulk_requested = False
                    self.stream_attempted = now
                    self.stream_allow_target = False
                    self.stream_error = None
                # One fallback may run between cloud commands. Manual S also
                # runs at cloud boundaries, rather than waiting for all clouds.
                may_target = (not self.stream_busy or self.stream_allow_target or
                              bool(self.stream_manual))
                if may_target and now >= self.stream_next_target:
                    while self.stream_manual:
                        key = self.stream_manual.popleft()
                        self.stream_manual_ids.discard(key)
                        if key in self.rows:
                            row = dict(self.rows[key])
                            break
                    if row is None:
                        eligible = [key for key in self.stream_missing if key in self.rows and
                            now - self.stream_target_attempts.get(key, -float('inf')) >=
                            self.args.stream_target_refresh]
                        if eligible:
                            key = min(eligible, key=lambda k: (self.stream_target_attempts.get(k, 0), k))
                            row = dict(self.rows[key])
                    if row is not None:
                        self.stream_target_busy = True
                        self.stream_target_id = row['id']
                        self.stream_target_attempted = now
                        self.stream_target_attempts[row['id']] = now
                        self.stream_target_error = None
                        self.stream_allow_target = False
                if row is None and self.stream_pending_clouds:
                    cloud = self.stream_pending_clouds.popleft()
                    self.stream_active_cloud = cloud
            if row is not None:
                self._stream_target_worker(row)
                with self.lock:
                    self.stream_next_target = time.monotonic() + self.args.stream_target_spacing
            elif cloud is not None:
                self._stream_bulk_worker(cloud)
            else:
                self.stream_wake.wait(0.25)
                self.stream_wake.clear()

    def _stream_bulk_worker(self, cloud):
        # Only one cloud per scheduler turn. Do not block fallbacks behind a
        # 25-cloud sweep (formerly as much as 25 * 90 seconds).
        found, error = {}, None
        try:
            with self.lock:
                has_regular_rows = any(row['cloud'] == cloud and not stream_group(row)
                                       for row in self.rows.values())
            if not has_regular_rows:
                return
            if self.args.demo:
                if cloud == '00':
                    output = ('0_FOI_183 stream status on all clouds [CURRENT]\n'
                              '0_FOI_185 stream status on all clouds [SYNCING]\n'
                              '0_OFXD_18 stream status on all clouds [GAPPING]')
                else:
                    output = "{}_INJ_001 : 'Current' SUCCESS (51 usec)".format(cloud)
            else:
                output, error = command_result(
                    stream_command([str(int(cloud)), 'all', 'all']),
                    self.args.stream_bulk_timeout, accept_stream_nonzero=True)
            if not error:
                found = parse_cloudless(output) if cloud == '00' else parse_clouded(output)
                with self.lock:
                    known_ids = {key for key, row in self.rows.items() if not stream_group(row)}
                found = {key: value for key, value in found.items()
                         if value not in (None, 'UNKNOWN') and key in known_ids and
                         key.split('_', 1)[0] == cloud}
                if not found:
                    error = 'No recognized stream rows'
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                found = {key: value for key, value in found.items()
                         if key in self.rows and not stream_group(self.rows[key])}
                if found:
                    verified = time.monotonic()
                    self.stream_rows.update(found)
                    self.stream_checked = verified
                    self.stream_cloud_checked[cloud] = verified
                    for key in found:
                        self.stream_row_checked[key] = verified
                        self.stream_row_errors.pop(key, None)
                # Enqueue this cloud's missing rows now, not at sweep end.
                cloud_ids = {key for key, row in self.rows.items()
                             if row['cloud'] == cloud and not stream_group(row)}
                self.stream_missing.difference_update(cloud_ids)
                self.stream_missing.update(cloud_ids - set(found))
                if error:
                    self.stream_cloud_errors[cloud] = error
                else:
                    self.stream_cloud_errors.pop(cloud, None)
                self.stream_error = ('{} cloud error(s): {}'.format(
                    len(self.stream_cloud_errors), ', '.join(sorted(self.stream_cloud_errors)))
                    if self.stream_cloud_errors else None)
                self.stream_completed += 1
                self.stream_allow_target = True
                self.stream_active_cloud = None
                if not self.stream_pending_clouds:
                    self.stream_busy = False
                    self.stream_last_bulk_end = time.monotonic()

    def request_stream_target(self, row):
        # Manual S requests use the same serialized, rate-limited worker.
        with self.lock:
            key = row['id']
            if key not in self.stream_manual_ids and not (
                    self.stream_target_busy and self.stream_target_id == key):
                self.stream_manual.append(key)
                self.stream_manual_ids.add(key)
        self.stream_wake.set()

    def _stream_target_worker(self, row):
        state, error = None, None
        try:
            if self.args.demo:
                state = {'01_INJ_001': 'CURRENT', '01_INJ_002': 'SYNC+GAP',
                         '00_FOI_183': 'CURRENT', '00_FOI_185': 'SYNCING',
                         '00_OFXD_018': 'GAPPING'}.get(row['id'], 'UNKNOWN')
            else:
                group = stream_group(row)
                argv = (group_stream_command(group, row['cloud'], row['app'], row['instance']) if group else
                        stream_command([str(int(row['cloud'])), row['app'], str(int(row['instance']))]))
                output, error = command_result(argv, self.args.stream_target_timeout,
                                               accept_stream_nonzero=True)
                if output is not None:
                    if row['cloud'] == '00':
                        state = parse_cloudless(output).get(row['id'])
                        # Some targeted cloudless commands return a different identifier format.
                        if state is None:
                            state = parse_target_stream(output, row['id'])
                    else:
                        state = parse_target_stream(output, row['id'])
                if state in (None, 'UNKNOWN') and not error:
                    error = 'Unrecognized stream output'
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                # Cache every recognized result, even after selection changes.
                # A failed/unrecognized probe must not erase the last known state.
                current_route = stream_group(self.rows.get(row['id'], {}))
                route_matches = current_route == stream_group(row)
                if state not in (None, 'UNKNOWN') and not error and route_matches:
                    self.stream_rows[row['id']] = state
                    self.stream_row_checked[row['id']] = time.monotonic()
                    self.stream_checked = self.stream_row_checked[row['id']]
                    self.stream_row_errors.pop(row['id'], None)
                if error and route_matches:
                    self.stream_row_errors[row['id']] = error
                if self.stream_target_id == row['id']:
                    self.stream_target_state = state
                    self.stream_target_error = error
                    self.stream_target_checked = self.stream_row_checked.get(row['id'], 0.0)
                self.stream_target_busy = False

    def tick(self, selected_row):
        now = time.monotonic()
        with self.lock:
            do_full = not self.full_busy and (self.full_requested or
                now - self.full_attempted >= self.args.full_refresh)
            do_target = bool(selected_row) and not self.target_busy and (
                selected_row['id'] != self.target_id or
                now - self.target_attempted >= self.args.target_refresh)
        if do_full:
            self.request_full()
        if do_target:
            self.request_target(selected_row)


def safe_add(win, y, x, value, color=0, bold=False, cell_fitted=False):
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width - 1:
        return
    try:
        attr = curses.color_pair(color) | (curses.A_BOLD if bold else 0)
        win.addnstr(y, x, str(value), len(str(value)) if cell_fitted else max(0, width - x - 1), attr)
    except curses.error:
        pass

def prompt(win, label, uppercase=True, max_chars=32):
    height, width = win.getmaxyx()
    if height < 3 or width < len(label) + 5:
        return None
    curses.echo()
    curses.curs_set(1)
    win.nodelay(False)
    try:
        win.move(height - 1, 0)
        win.clrtoeol()
        safe_add(win, height - 1, 0, label)
        win.refresh()
        value = win.getstr(height - 1, len(label), min(max_chars, width - len(label) - 2))
        decoded = value.decode('utf-8', 'replace').strip()
        return decoded.upper() if uppercase else decoded
    except (curses.error, KeyboardInterrupt):
        return None
    finally:
        curses.noecho()
        curses.curs_set(0)
        win.nodelay(True)

def draw(stdscr, monitor):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    colors = curses.has_colors()
    if colors:
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        for n, color in [(1, curses.COLOR_CYAN), (2, curses.COLOR_GREEN),
                         (3, curses.COLOR_RED), (4, curses.COLOR_YELLOW)]:
            curses.init_pair(n, color, bg)
    selected_id = None
    selected_index = 0
    scroll = 0
    only_fail = False
    cloud_filter = ''
    type_filter = ''
    instance_filter = ''
    while True:
        h, w = stdscr.getmaxyx()
        with monitor.lock:
            rows = list(monitor.rows.values())
            checked = monitor.full_checked
            attempted = monitor.full_attempted
            error = monitor.full_error
            busy = monitor.full_busy
            tid = monitor.target_id
            target_row = dict(monitor.target_row) if monitor.target_row else None
            target_error = monitor.target_error
            target_busy = monitor.target_busy
            target_checked = monitor.target_checked
            stream_rows = dict(monitor.stream_rows)
            stream_row_checked = dict(monitor.stream_row_checked)
            stream_checked = monitor.stream_checked
            stream_cloud_checked = dict(monitor.stream_cloud_checked)
            stream_error = monitor.stream_error
            stream_busy = monitor.stream_busy
            stream_target_id = monitor.stream_target_id
            stream_target_state = monitor.stream_target_state
            stream_target_checked = monitor.stream_target_checked
            stream_target_error = monitor.stream_target_error
            stream_target_busy = monitor.stream_target_busy
            stream_progress = (monitor.stream_completed, monitor.stream_total)
            stream_missing = len(monitor.stream_missing)
            stream_errors = dict(monitor.stream_row_errors)
            cloud_errors = dict(monitor.stream_cloud_errors)
            active_cloud = monitor.stream_active_cloud
            stream_worker_alive = monitor.stream_thread.is_alive()
            inventory_groups = list(monitor.args.group)
        rows.sort(key=lambda r: (r['host'], r['id']))
        def get_stream(row):
            # Show last known status for every application, regardless of selection.
            # A stale observation remains visible; it is not a new live assertion.
            return stream_rows.get(row['id'], 'UNKNOWN')
        visible = [r for r in rows if
                   (not cloud_filter or r['cloud'] == cloud_filter.zfill(2)) and
                   (not type_filter or r['app'].upper() == type_filter) and
                   (not instance_filter or r['instance'] == instance_filter.zfill(3)) and
                   (not only_fail or r['status'] != 'RUNNING' or get_stream(r) in ('FAILED', 'DOWN', 'GAPPING', 'SYNC+GAP', 'SYNCING'))]
        if selected_id and any(r['id'] == selected_id for r in visible):
            selected_index = next(i for i, r in enumerate(visible) if r['id'] == selected_id)
        selected_index = min(max(selected_index, 0), max(0, len(visible) - 1))
        selected = visible[selected_index] if visible else None
        selected_id = selected['id'] if selected else None
        monitor.tick(selected)
        stdscr.erase()
        safe_add(stdscr, 0, 0, 'MIAX OPERATIONS CONTROL | PHASE 2.5.3 | {}'.format(
            'DEMO' if monitor.args.demo else 'LIVE'), 1, True)
        safe_add(stdscr, 1, 0, 'Time: {}  |  Read-only  |  Inventory: {}s  Target: {}s'.format(
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            monitor.args.full_refresh, monitor.args.target_refresh))
        safe_add(stdscr, 2, 0, 'TOTAL {}  RUNNING {}  DOWN {}  OTHER {}'.format(
            len(rows), sum(r['status'] == 'RUNNING' for r in rows),
            sum(r['status'] == 'DOWN' for r in rows),
            sum(r['status'] not in ('RUNNING', 'DOWN') for r in rows)), 1, True)
        age = int(time.monotonic() - checked) if checked else None
        freshness = ('PENDING' if age is None else '{}s ago'.format(age))
        if age is not None and age > monitor.args.full_refresh + monitor.args.full_timeout:
            freshness += ' [STALE]'
        safe_add(stdscr, 3, 0, 'Inventory: {} | {} | {}'.format(
            freshness, 'COLLECTING' if busy else 'IDLE', 'ERROR' if error else 'OK'),
            3 if error else (4 if busy else 2))
        safe_add(stdscr, 4, 0, 'Cloud [{}]  Type [{}]  Instance [{}]  Failures [{}]  Matches {}'.format(
            cloud_filter or 'ALL', type_filter or 'ALL', instance_filter or 'ALL',
            'ON' if only_fail else 'OFF', len(visible)) +
            ' | Groups [' + (', '.join(inventory_groups) if inventory_groups else 'NONE') + ']')
        safe_add(stdscr, 5, 0, 'APPLICATION         HOST                 VERSION       PID         APP       STREAM', 1, True)
        available = max(0, h - 14)
        if selected_index < scroll:
            scroll = selected_index
        if available and selected_index >= scroll + available:
            scroll = selected_index - available + 1
        for i, row in enumerate(visible[scroll:scroll + available], start=scroll):
            status = row['status']
            color = 2 if status == 'RUNNING' else 3 if status in ('DOWN', 'FAILED', 'STOPPED') else 4
            stream = get_stream(row)
            stream_color = 2 if stream == 'CURRENT' else 3 if stream in ('FAILED', 'DOWN', 'GAPPING') else 4
            safe_add(stdscr, 6 + i - scroll, 0,
                     '{} {:<19.19} {:<20.20} {:<13.13} {:<11.11} {:<9.9}'.format(
                         '>' if i == selected_index else ' ', row['id'], row['host'],
                         row['version'], row['pid'], status), color, i == selected_index)
            safe_add(stdscr, 6 + i - scroll, 78, stream, stream_color, i == selected_index)
        if h >= 12:
            if selected:
                safe_add(stdscr, h - 6, 0, 'SELECTED: {} | Host {} | Cloud {} | Type {} | Instance {}'.format(
                    selected['id'], selected['host'], selected['cloud'], selected['app'], selected['instance']) +
                    (' | Group ' + ', '.join(selected['_inventory_groups']) if selected.get('_inventory_groups') else ''), 1)
                if tid == selected['id']:
                    if target_row:
                        safe_add(stdscr, h - 5, 0, 'TARGET: {} | PID {} | {}s ago'.format(
                            target_row['status'], target_row['pid'],
                            int(time.monotonic() - target_checked)), 2 if target_row['status'] == 'RUNNING' else 3)
                    elif target_error:
                        safe_add(stdscr, h - 5, 0, 'TARGET ERROR: ' + target_error, 3)
                    else:
                        safe_add(stdscr, h - 5, 0, 'TARGET: ' + ('COLLECTING' if target_busy else 'PENDING'), 4)
            stream_age = int(time.monotonic() - stream_checked) if stream_checked else None
            safe_add(stdscr, h - 7, 0,
                     'Streams {}/{} verified | bulk {}/{} | missing {} | {} | {} | {}'.format(
                         sum(r['id'] in stream_row_checked for r in rows), len(rows),
                         stream_progress[0], stream_progress[1], stream_missing,
                         '{}s ago'.format(stream_age) if stream_age is not None else 'PENDING',
                         ('TARGET' if stream_target_busy else ('CLOUD ' + active_cloud if active_cloud else 'IDLE'))
                         if stream_worker_alive else 'WORKER STOPPED',
                         stream_error or ('{} target errors'.format(len(stream_errors)) if stream_errors else 'OK')),
                     3 if stream_error else 2)
            if selected:
                state = get_stream(selected)
                safe_add(stdscr, h - 3, 0, 'STREAM: {} | verified {} | {}'.format(
                    state, ('{}s ago'.format(int(time.monotonic() - stream_row_checked[selected['id']]))
                            if selected['id'] in stream_row_checked else 'NEVER'),
                    stream_errors.get(selected['id']) or
                    (cloud_errors.get(selected['cloud']) if not stream_group(selected) else None) or
                    ('COLLECTING' if stream_target_busy and stream_target_id == selected['id'] else
                     ('NEVER VERIFIED' if selected['id'] not in stream_row_checked else 'OK'))),
                    2 if state == 'CURRENT' else (3 if state in ('FAILED', 'DOWN', 'GAPPING') else 4))
            if error:
                safe_add(stdscr, h - 4, 0, 'INVENTORY ERROR: ' + error, 3)
            else:
                safe_add(stdscr, h - 4, 0, 'Inventory last successful: ' + freshness, 2)
            safe_add(stdscr, h - 2, 0, 'UP/DOWN Navigate | F Failures | C Cloud | T Type | I Instance | G Add group | X Clear', 1)
            safe_add(stdscr, h - 1, 0, 'ENTER Logs | R Inventory | P Probe app | S Stream | B Bulk | Q Quit', 1)
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            break
        if key in (curses.KEY_DOWN, ord('j')):
            selected_index += 1
            selected_id = None
        elif key in (curses.KEY_UP, ord('k')):
            selected_index -= 1
            selected_id = None
        elif key in (ord('f'), ord('F')):
            only_fail = not only_fail
            selected_index, selected_id, scroll = 0, None, 0
        elif key in (ord('x'), ord('X')):
            cloud_filter = type_filter = instance_filter = ''
            only_fail = False
            selected_index, selected_id, scroll = 0, None, 0
        elif key in (ord('c'), ord('C'), ord('t'), ord('T'), ord('i'), ord('I')):
            label = {ord('c'): 'Cloud (blank=ALL): ', ord('t'): 'Type (blank=ALL): ',
                     ord('i'): 'Instance (blank=ALL): '}[ord(chr(key).lower())]
            value = prompt(stdscr, label)
            if value is not None:
                if chr(key).lower() == 'c' and (not value or value.isdigit()):
                    cloud_filter = value
                elif chr(key).lower() == 't' and (not value or re.match(r'^[A-Z0-9]+$', value)):
                    type_filter = value
                elif chr(key).lower() == 'i' and (not value or value.isdigit()):
                    instance_filter = value
                selected_index, selected_id, scroll = 0, None, 0
        elif key in (ord('g'), ord('G')):
            group = prompt(stdscr, 'Add group (blank=cancel): ', uppercase=False, max_chars=256)
            if group and valid_group_name(group):
                monitor.add_group(group)
        elif key in (10, 13, curses.KEY_ENTER) and selected:
            draw_logs(stdscr, monitor, monitor.logs, dict(selected))
        elif key in (ord('r'), ord('R')):
            monitor.request_full()
        elif key in (ord('p'), ord('P')) and selected:
            monitor.request_target(selected)
        elif key in (ord('s'), ord('S')) and selected:
            monitor.request_stream_target(selected)
        elif key in (ord('b'), ord('B')):
            monitor.request_stream_bulk()
        time.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='Use simulated data only')
    parser.add_argument('-G', '--group', action='append', nargs='?', const='', default=[],
                        help='Add named inventory group; repeatable; -G alone prompts before startup')
    parser.add_argument('--command', default=DEFAULT_COMMAND, help='Absolute miax_status executable path')
    parser.add_argument('--full-refresh', type=int, default=300, help='Seconds between full inventories')
    parser.add_argument('--target-refresh', type=int, default=30, help='Seconds between selected instance checks')
    parser.add_argument('--full-timeout', type=int, default=90)
    parser.add_argument('--target-timeout', type=int, default=20)
    parser.add_argument('--stream-bulk-refresh', type=int, default=300)
    parser.add_argument('--stream-target-refresh', type=int, default=300, help='Minimum seconds between automatic fallback retries per app')
    parser.add_argument('--stream-target-spacing', type=int, default=5,
                        help='Minimum idle seconds between targeted stream commands')
    parser.add_argument('--stream-bulk-timeout', type=int, default=20)
    parser.add_argument('--stream-target-timeout', type=int, default=20)
    parser.add_argument('--no-log-wrap', dest='log_wrap', action='store_false',
                        help='Start log panes with horizontal scrolling instead of wrapping')
    parser.add_argument('--log-history', type=int, default=20000,
                        help='Latest matching lines retained per log section (default 20000)')
    parser.add_argument('--log-line-length', type=int, default=4096,
                        help='Maximum retained bytes per log line, truncation labelled')
    parser.add_argument('--log-match', choices=('id', 'type'), default='id',
                        help='Filter by selected full application ID or application type')
    parser.add_argument('--log-ssh-user', default='', help='SSH account (default current account)')
    parser.add_argument('--log-connect-timeout', type=int, default=10)
    parser.add_argument('--log-timeout', type=int, default=90, help='Overall SSH/log scan timeout')
    parser.add_argument('--log-min-refresh', type=int, default=15,
                        help='Minimum idle seconds between log scans')
    parser.add_argument('--log-refresh', type=int, default=0,
                        help='Automatic refresh seconds while log view is open; 0 means manual')
    args = parser.parse_args()
    if min(args.full_refresh, args.target_refresh, args.full_timeout, args.target_timeout,
           args.stream_bulk_refresh, args.stream_target_refresh,
           args.stream_bulk_timeout, args.stream_target_timeout, args.stream_target_spacing) < 1:
        parser.error('Refresh intervals and timeouts must be positive')
    if min(args.log_history, args.log_line_length, args.log_connect_timeout,
           args.log_timeout, args.log_min_refresh) < 1 or args.log_refresh < 0:
        parser.error('Log limits/timeouts must be positive; log refresh must be zero or positive')
    if args.log_history > 200000 or args.log_line_length > 65536:
        parser.error('Maximum log history is 200000 lines/section; maximum line length is 65536')
    if args.log_ssh_user and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', args.log_ssh_user):
        parser.error('Invalid SSH user name')
    groups = []
    for name in args.group:
        if name == '':
            try:
                name = input('Inventory group name (blank=skip): ')
            except (EOFError, KeyboardInterrupt):
                parser.error('Group prompt cancelled; use -G GROUPNAME to supply a name')
        name = name.strip()
        if name and not valid_group_name(name):
            parser.error('Invalid group name')
        if name and name not in groups:
            groups.append(name)
    args.group = groups
    monitor = Monitor(args)
    try:
        curses.wrapper(draw, monitor)
    finally:
        monitor.close()

if __name__ == '__main__':
    main()
