#!/usr/bin/env python3
"""MIAX Operations Control - Phase 1.1. Python 3.6+, standard library only.

Read-only status monitoring. No SSH, stream checks, or application controls yet.
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
dcw02 00_FOI_185 3.34.0 pid=2910915 10:02 [running]
dn01 00_OFXD_018 3.0.0 [down]
dn01 01_INJ_001 4.12.0 pid=2874412 10:04 [running]
dn02 01_INJ_002 4.12.0 [starting]
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

def command_result(argv, timeout):
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode:
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
        self.request_full()

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
                output, error = command_result([self.args.command], self.args.full_timeout)
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
                output, error = command_result(argv, self.args.target_timeout)
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
        rows.sort(key=lambda r: (r['host'], r['id']))
        visible = [r for r in rows if
                   (not cloud_filter or r['cloud'] == cloud_filter.zfill(2)) and
                   (not type_filter or r['app'].upper() == type_filter) and
                   (not instance_filter or r['instance'] == instance_filter.zfill(3)) and
                   (not only_fail or r['status'] != 'RUNNING')]
        if selected_id and any(r['id'] == selected_id for r in visible):
            selected_index = next(i for i, r in enumerate(visible) if r['id'] == selected_id)
        selected_index = min(max(selected_index, 0), max(0, len(visible) - 1))
        selected = visible[selected_index] if visible else None
        selected_id = selected['id'] if selected else None
        monitor.tick(selected)
        stdscr.erase()
        safe_add(stdscr, 0, 0, 'MIAX OPERATIONS CONTROL | PHASE 1.1 | {}'.format(
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
        safe_add(stdscr, 5, 0, 'APPLICATION         HOST                 VERSION       PID         STATUS', 1, True)
        available = max(0, h - 12)
        if selected_index < scroll:
            scroll = selected_index
        if available and selected_index >= scroll + available:
            scroll = selected_index - available + 1
        for i, row in enumerate(visible[scroll:scroll + available], start=scroll):
            status = row['status']
            color = 2 if status == 'RUNNING' else 3 if status in ('DOWN', 'FAILED', 'STOPPED') else 4
            safe_add(stdscr, 6 + i - scroll, 0,
                     '{} {:<19.19} {:<20.20} {:<13.13} {:<11.11} {}'.format(
                         '>' if i == selected_index else ' ', row['id'], row['host'],
                         row['version'], row['pid'], status), color, i == selected_index)
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
            if error:
                safe_add(stdscr, h - 4, 0, 'INVENTORY ERROR: ' + error, 3)
            else:
                safe_add(stdscr, h - 4, 0, 'Inventory last successful: ' + freshness, 2)
            safe_add(stdscr, h - 2, 0, 'UP/DOWN Navigate | F Failures | C Cloud | T Type | I Instance | X Clear', 1)
            safe_add(stdscr, h - 1, 0, 'R Refresh inventory | P Probe selected | Q Quit', 1)
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
        time.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true', help='Use simulated data only')
    parser.add_argument('--command', default=DEFAULT_COMMAND, help='Absolute miax_status executable path')
    parser.add_argument('--full-refresh', type=int, default=300, help='Seconds between full inventories')
    parser.add_argument('--target-refresh', type=int, default=30, help='Seconds between selected instance checks')
    parser.add_argument('--full-timeout', type=int, default=90)
    parser.add_argument('--target-timeout', type=int, default=20)
    args = parser.parse_args()
    if min(args.full_refresh, args.target_refresh, args.full_timeout, args.target_timeout) < 1:
        parser.error('Refresh intervals and timeouts must be positive')
    curses.wrapper(draw, Monitor(args))

if __name__ == '__main__':
    main()
