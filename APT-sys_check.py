#!/usr/bin/env python3
"""Operations Control - Phase 2.2. Python 3.6+, standard library only.

Read-only application and stream monitoring. No SSH or application controls.
"""
import argparse
import curses
import os
import re
import subprocess
import threading
import time
from datetime import datetime

DEFAULT_COMMAND = '/apps/miaxprod/scripts/miax_status'
APP_RE = re.compile(r'(?P<host>\S+)\s+(?P<id>\d+_[A-Za-z0-9]+_\d+)\s+(?P<version>\S+)(?P<rest>.*)', re.I)
STATUS_RE = re.compile(r'\[(running|down|starting|stopping|stopped|failed)\]', re.I)
PID_RE = re.compile(r'\bpid=(\d+)\b', re.I)
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
DEMO = '''dch4t1fgw01 00_FOI_183 3.34.0 pid=2954301 10:02 [running]
dchgw02 00_FOI_185 3.34.0 pid=2910915 10:02 [running]
dnyeqs01p 00_OFXD_018 3.0.0 [down]
dnynj01 01_INJ_001 4.12.0 pid=2874412 10:04 [running]
dnyj02 01_INJ_002 4.12.0 [starting]
'''

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
    if re.search(r'\b(FAIL|FAILED|ERROR|TIMEOUT)\b', value):
        return 'FAILED'
    if re.search(r'\bCURRENT\b', value):
        return 'CURRENT'
    return 'UNKNOWN'


def parse_cloudless(output):
    result = {}
    for raw in output.splitlines():
        m = CLOUDLESS_RE.search(ANSI_RE.sub('', raw))
        if m:
            key = normalize_id(m.group('cloud'), m.group('app'), m.group('instance'))
            result[key] = stream_state(m.group('state'))
    return result


# Clouded bulk rows: 01_BOD_001 : 'Current' SUCCESS (50 usec)
CLOUDED_RE = re.compile(
    r"\b(?P<cloud>\d+)_(?P<app>[A-Za-z0-9]+)_(?P<instance>\d+)\s*:\s*"
    r"['\"](?P<state>[^'\"]+)['\"]\s+SUCCESS\b", re.I)
TARGET_RE = re.compile(
    r"(?:^|\s|:)['\"](?P<state>CURRENT|SYNCING(?:\s*\+\s*GAPPING|\s+AND\s+GAPPING)?|GAPPING)['\"]\s+SUCCESS\b", re.I)

def parse_clouded(output):
    result = {}
    for raw in output.splitlines():
        m = CLOUDED_RE.search(ANSI_RE.sub('', raw))
        if m:
            result[normalize_id(m.group('cloud'), m.group('app'), m.group('instance'))] = stream_state(m.group('state'))
    return result

def parse_target_stream(output):
    # Only recognize actual stream results, not shell startup/help text.
    matches = []
    clean = ANSI_RE.sub('', output)
    for pattern in (TARGET_RE, CLOUDED_RE):
        for m in pattern.finditer(clean):
            matches.append((m.start(), stream_state(m.group('state'))))
    return max(matches, key=lambda x: x[0])[1] if matches else 'UNKNOWN'


def stream_command(args):
    # Existing sc is a Bash function loaded by interactive shell startup.
    # Arguments are numeric/alphanumeric only, validated by the inventory parser.
    if not all(re.match(r'^[A-Za-z0-9]+$', str(x)) for x in args):
        raise ValueError('Invalid stream command argument')
    return ['bash', '-ic', 'sc ' + ' '.join(str(x) for x in args)]


def command_result(argv, timeout, accept_inventory_nonzero=False):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode:
        # miax_status may return 1 when applications are DOWN while still
        # providing a valid inventory. Never apply this exception to sc.
        if accept_inventory_nonzero and parse_apps(proc.stdout):
            return proc.stdout, None
        return None, 'exit {}: {}'.format(proc.returncode, proc.stderr.strip()[:140])
    return proc.stdout, None

class Monitor(object):
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
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
        self.request_full()
        # Bulk stream collection begins after inventory discovers the clouds.

    def request_full(self):
        with self.lock:
            if self.full_busy:
                return
            self.full_busy = True
            self.full_attempted = time.monotonic()
        threading.Thread(target=self._full_worker, daemon=True).start()

    def _full_worker(self):
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
                    self.rows = rows
                    self.full_checked = time.monotonic()
                self.full_error = error
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
                argv = [self.args.command, '-c', str(int(row['cloud'])),
                        '-t', row['app'], '-i', str(int(row['instance']))]
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
            if self.stream_busy:
                return
            self.stream_busy = True
            self.stream_attempted = time.monotonic()
        threading.Thread(target=self._stream_bulk_worker, daemon=True).start()

    def _stream_bulk_worker(self):
        parsed = {}
        errors = {}
        successful_clouds = set()
        try:
            with self.lock:
                clouds = sorted(set(r['cloud'] for r in self.rows.values()))
            if self.args.demo:
                clouds = sorted(set(clouds + ['00']))
            for cloud in clouds:
                try:
                    if self.args.demo:
                        if cloud == '00':
                            output = ('0_FOI_183 stream status on all clouds [CURRENT]\n'
                                      '0_FOI_185 stream status on all clouds [SYNCING]\n'
                                      '0_OFXD_18 stream status on all clouds [GAPPING]')
                        else:
                            output = "{}{}_INJ_001 : 'Current' SUCCESS (51 usec)".format(
                                '0' if int(cloud) < 10 else '', int(cloud))
                        error = None
                    else:
                        output, error = command_result(
                            stream_command([str(int(cloud)), 'all', 'all']),
                            self.args.stream_bulk_timeout)
                    if error:
                        errors[cloud] = error
                        continue
                    found = parse_cloudless(output) if cloud == '00' else parse_clouded(output)
                    if not found:
                        errors[cloud] = 'No recognized stream rows'
                    else:
                        parsed.update(found)
                        successful_clouds.add(cloud)
                except Exception as exc:
                    errors[cloud] = '{}: {}'.format(type(exc).__name__, exc)
        except Exception as exc:
            errors['GENERAL'] = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                if parsed:
                    # Retain last successful states from clouds that failed this cycle.
                    self.stream_rows.update(parsed)
                    self.stream_checked = time.monotonic()
                    for cloud in successful_clouds:
                        self.stream_cloud_checked[cloud] = self.stream_checked
                self.stream_cloud_errors = errors
                self.stream_error = ('{} cloud(s) failed: {}'.format(
                    len(errors), ', '.join(sorted(errors))) if errors else None)
                self.stream_busy = False

    def request_stream_target(self, row):
        with self.lock:
            if self.stream_target_busy:
                return
            self.stream_target_busy = True
            self.stream_target_id = row['id']
            self.stream_target_attempted = time.monotonic()
            self.stream_target_error = None
            self.stream_target_state = None
        threading.Thread(target=self._stream_target_worker, args=(dict(row),), daemon=True).start()

    def _stream_target_worker(self, row):
        state, error = None, None
        try:
            if self.args.demo:
                state = {'01_INJ_001': 'CURRENT', '01_INJ_002': 'SYNC+GAP'}.get(row['id'], 'UNKNOWN')
                if row['cloud'] == '00':
                    state = parse_cloudless('0_FOI_183 stream status on all clouds [CURRENT]').get(row['id'], 'UNKNOWN')
            else:
                args = [str(int(row['cloud'])), row['app'], str(int(row['instance']))]
                output, error = command_result(stream_command(args), self.args.stream_target_timeout)
                if output is not None:
                    if row['cloud'] == '00':
                        state = parse_cloudless(output).get(row['id'])
                        # Some targeted cloudless commands return a different identifier format.
                        if state is None:
                            state = parse_target_stream(output)
                    else:
                        state = parse_target_stream(output)
                if state == 'UNKNOWN':
                    error = 'Unrecognized stream output'
        except Exception as exc:
            error = '{}: {}'.format(type(exc).__name__, exc)
        finally:
            with self.lock:
                if self.stream_target_id == row['id']:
                    self.stream_target_state = state
                    self.stream_target_error = error
                    self.stream_target_checked = time.monotonic() if state is not None else 0.0
                self.stream_target_busy = False

    def tick(self, selected_row):
        now = time.monotonic()
        with self.lock:
            do_full = not self.full_busy and now - self.full_attempted >= self.args.full_refresh
            do_target = bool(selected_row) and not self.target_busy and (
                selected_row['id'] != self.target_id or
                now - self.target_attempted >= self.args.target_refresh)
        if do_full:
            self.request_full()
        if do_target:
            self.request_target(selected_row)
        with self.lock:
            do_stream_bulk = (bool(self.rows) and not self.stream_busy and
                              now - self.stream_attempted >= self.args.stream_bulk_refresh)
            do_stream_target = (bool(selected_row) and not self.stream_target_busy and
                                (selected_row['id'] != self.stream_target_id or
                                 now - self.stream_target_attempted >= self.args.stream_target_refresh))
        if do_stream_bulk:
            self.request_stream_bulk()
        if do_stream_target:
            self.request_stream_target(selected_row)

def safe_add(win, y, x, value, color=0, bold=False):
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width - 1:
        return
    try:
        attr = curses.color_pair(color) | (curses.A_BOLD if bold else 0)
        win.addnstr(y, x, str(value), max(0, width - x - 1), attr)
    except curses.error:
        pass

def prompt(win, label):
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
        value = win.getstr(height - 1, len(label), min(32, width - len(label) - 2))
        return value.decode('utf-8', 'replace').strip().upper()
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
            stream_checked = monitor.stream_checked
            stream_cloud_checked = dict(monitor.stream_cloud_checked)
            stream_error = monitor.stream_error
            stream_busy = monitor.stream_busy
            stream_target_id = monitor.stream_target_id
            stream_target_state = monitor.stream_target_state
            stream_target_checked = monitor.stream_target_checked
            stream_target_error = monitor.stream_target_error
            stream_target_busy = monitor.stream_target_busy
        rows.sort(key=lambda r: (r['host'], r['id']))
        def get_stream(row):
            if row['id'] == stream_target_id and stream_target_state not in (None, 'UNKNOWN') and stream_target_checked:
                if time.monotonic() - stream_target_checked <= monitor.args.stream_target_refresh + monitor.args.stream_target_timeout:
                    return stream_target_state
            cloud_checked = stream_cloud_checked.get(row['cloud'], 0)
            if cloud_checked and time.monotonic() - cloud_checked <= monitor.args.stream_bulk_refresh + monitor.args.stream_bulk_timeout * max(1, len(set(r['cloud'] for r in rows))):
                return stream_rows.get(row['id'], 'UNKNOWN')
            return 'UNKNOWN'
        visible = [r for r in rows if
                   (not cloud_filter or r['cloud'] == cloud_filter.zfill(2)) and
                   (not type_filter or r['app'].upper() == type_filter) and
                   (not instance_filter or r['instance'] == instance_filter.zfill(3)) and
                   (not only_fail or r['status'] != 'RUNNING' or get_stream(r) in ('FAILED', 'GAPPING', 'SYNC+GAP', 'SYNCING'))]
        if selected_id and any(r['id'] == selected_id for r in visible):
            selected_index = next(i for i, r in enumerate(visible) if r['id'] == selected_id)
        selected_index = min(max(selected_index, 0), max(0, len(visible) - 1))
        selected = visible[selected_index] if visible else None
        selected_id = selected['id'] if selected else None
        monitor.tick(selected)
        stdscr.erase()
        safe_add(stdscr, 0, 0, 'MIAX OPERATIONS CONTROL | PHASE 2.2 | {}'.format(
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
            'ON' if only_fail else 'OFF', len(visible)))
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
            stream_color = 2 if stream == 'CURRENT' else 3 if stream in ('FAILED', 'GAPPING') else 4
            safe_add(stdscr, 6 + i - scroll, 0,
                     '{} {:<19.19} {:<20.20} {:<13.13} {:<11.11} {:<9.9}'.format(
                         '>' if i == selected_index else ' ', row['id'], row['host'],
                         row['version'], row['pid'], status), color, i == selected_index)
            safe_add(stdscr, 6 + i - scroll, 78, stream, stream_color, i == selected_index)
        if h >= 12:
            if selected:
                safe_add(stdscr, h - 6, 0, 'SELECTED: {} | Host {} | Cloud {} | Type {} | Instance {}'.format(
                    selected['id'], selected['host'], selected['cloud'], selected['app'], selected['instance']), 1)
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
                     'Cloud streams: {} | {} | {}'.format(
                         '{}s ago'.format(stream_age) if stream_age is not None else 'PENDING',
                         'COLLECTING' if stream_busy else 'IDLE', stream_error or 'OK'),
                     3 if stream_error else 2)
            if selected:
                state = get_stream(selected)
                safe_add(stdscr, h - 3, 0, 'STREAM TARGET: {} | {}'.format(
                    state, stream_target_error or ('COLLECTING' if stream_target_busy else 'OK')),
                    2 if state == 'CURRENT' else (3 if state in ('FAILED', 'GAPPING') else 4))
            if error:
                safe_add(stdscr, h - 4, 0, 'INVENTORY ERROR: ' + error, 3)
            else:
                safe_add(stdscr, h - 4, 0, 'Inventory last successful: ' + freshness, 2)
            safe_add(stdscr, h - 2, 0, 'UP/DOWN Navigate | F Failures | C Cloud | T Type | I Instance | X Clear', 1)
            safe_add(stdscr, h - 1, 0, 'R Inventory | P Probe app | S Probe stream | B Bulk streams | Q Quit', 1)
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
    parser.add_argument('--command', default=DEFAULT_COMMAND, help='Absolute miax_status executable path')
    parser.add_argument('--full-refresh', type=int, default=300, help='Seconds between full inventories')
    parser.add_argument('--target-refresh', type=int, default=30, help='Seconds between selected instance checks')
    parser.add_argument('--full-timeout', type=int, default=90)
    parser.add_argument('--target-timeout', type=int, default=20)
    parser.add_argument('--stream-bulk-refresh', type=int, default=300)
    parser.add_argument('--stream-target-refresh', type=int, default=15)
    parser.add_argument('--stream-bulk-timeout', type=int, default=90)
    parser.add_argument('--stream-target-timeout', type=int, default=20)
    args = parser.parse_args()
    if min(args.full_refresh, args.target_refresh, args.full_timeout, args.target_timeout,
           args.stream_bulk_refresh, args.stream_target_refresh,
           args.stream_bulk_timeout, args.stream_target_timeout) < 1:
        parser.error('Refresh intervals and timeouts must be positive')
    curses.wrapper(draw, Monitor(args))

if __name__ == '__main__':
    main()

