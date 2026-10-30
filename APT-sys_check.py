
#!/usr/bin/env python3
"""Live curses log viewer: python3 log_viewer.py [path]."""
import argparse
import base64
import codecs
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import socket
import curses
from dataclasses import dataclass, field
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path


def parse_application(value):
    match = re.fullmatch(r'(\d+)_([A-Za-z][A-Za-z0-9]*)_(\d+)', value.strip())
    if not match:
        raise ValueError('Use an application name like 01_INJ_001.')
    cluster, app_type, instance = match.groups()
    return str(int(cluster)), app_type.upper(), str(int(instance))


def application_commands(value):
    cluster, app_type, instance = parse_application(value)
    return [
        ('Application hostname', ['miax_run_table', '-mc', cluster, '-ma', app_type, '-mi', instance]),
        ('Application status', ['miax_status', '-c', cluster, '-t', app_type, '-i', instance]),
        ('Stream status', ['sc', cluster, app_type, instance]),
    ]


def valid_hostname(value):
    return (len(value) <= 253 and all(
        re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
        for label in value.rstrip('.').split('.')))


def extract_hostname(output, pattern=None, application=None):
    # Do not guess a host from an unknown table layout.
    if pattern:
        found = list(re.finditer(pattern, output, re.MULTILINE))
        if len(found) != 1:
            raise ValueError('Hostname pattern must match exactly once.')
        host = found[0].group('host').strip()
    elif application:
        cluster, app_type, instance = parse_application(application)
        hosts = set()
        for line in output.splitlines():
            fields = line.split()
            # Example: - dch4t1bod01-a 1 INJ 1 3.34.1
            if len(fields) >= 6 and fields[0] == '-':
                try:
                    same_app = (str(int(fields[2])), fields[3].upper(), str(int(fields[4]))) == (cluster, app_type, instance)
                except ValueError:
                    continue
                if same_app and valid_hostname(fields[1]):
                    hosts.add(fields[1])
        if len(hosts) > 1:
            raise ValueError('Multiple hosts found for this application; cannot choose automatically.')
        host = next(iter(hosts)) if hosts else output.strip()
    else:
        host = output.strip()
    if not valid_hostname(host):
        raise ValueError('Hostname output is not a single hostname. Supply --hostname-pattern with a named (?P<host>...) group for table output.')
    return host


def run_check(label, command):
    print(f'\n{label}: {shlex.join(command)}', flush=True)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'{label} timed out after 30 seconds.') from exc
    if result.stdout:
        print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='' if result.stderr.endswith('\n') else '\n', flush=True)
    if result.returncode:
        raise RuntimeError(f'{label} failed (exit {result.returncode}); startup stopped.')
    return result.stdout


def check_remote_command(command):
    """Run a remote-side status command without blocking curses."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        output = (result.stdout or result.stderr).strip()
        if result.returncode:
            return False, f'exit {result.returncode}: {clean(output.splitlines()[0])[:110] if output else "no output"}'
        return True, output
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def summarize_status(output):
    """Display command output faithfully; only color unambiguous status tokens."""
    lines = [clean(line.strip()) for line in output.splitlines() if line.strip()]
    if not lines:
        return '(no output)', 'neutral'
    sample = ' | '.join(lines[:2])
    # Color only when the command explicitly provides a recognizable state.
    words = re.findall(r'\b(?:RUNNING|UP|ONLINE|ACTIVE|DOWN|STOPPED|FAILED|OFFLINE|ERROR)\b',
                       sample.upper())
    bad = {'DOWN', 'STOPPED', 'FAILED', 'OFFLINE', 'ERROR'}
    good = {'RUNNING', 'UP', 'ONLINE', 'ACTIVE'}
    state = 'bad' if any(w in bad for w in words) else 'good' if any(w in good for w in words) else 'neutral'
    return sample, state


class StatusMonitor:
    def __init__(self, application, interval=10):
        self.commands = application_commands(application)[1:]
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='miax-status')
        self.jobs = {}
        self.results = {label: ('Checking...', 'neutral', False) for label, _ in self.commands}
        self.last_success = None
        self.interval = interval
        self.next_check = 0

    def poll(self):
        now = time.monotonic()
        for label, future in list(self.jobs.items()):
            if not future.done():
                continue
            del self.jobs[label]
            try:
                ok, output = future.result()
            except Exception as exc:
                ok, output = False, str(exc)
            if ok:
                text, color = summarize_status(output)
                self.results[label] = (text, color, False)
                self.last_success = datetime.now().strftime('%H:%M:%S')
            else:
                previous, color, _ = self.results[label]
                if previous == 'Checking...':
                    previous, color = 'Unavailable', 'neutral'
                previous = previous.split(' [STALE:', 1)[0]
                self.results[label] = (previous + ' [STALE: ' + clean(output)[:55] + ']', color, True)
        if now >= self.next_check:
            for label, command in self.commands:
                if label not in self.jobs:
                    self.jobs[label] = self.executor.submit(check_remote_command, command)
            self.next_check = now + self.interval

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)


def launch_application(args):
    application = args.application
    while True:
        if application is None:
            application = input('Application name (example: 01_INJ_001): ').strip()
        try:
            commands = application_commands(application)
            break
        except ValueError as exc:
            if args.application:
                raise
            print(exc)
            application = None
    host_output = run_check(*commands[0])
    host = extract_hostname(host_output, args.hostname_pattern, application)
    print(f'\nConnecting to host: {host}', flush=True)
    # Send this viewer as a command payload: no remote installation or file writes.
    source = base64.b64encode(Path(__file__).read_bytes()).decode('ascii')
    code = f"import base64; exec(compile(base64.b64decode('{source}'), 'log_viewer.py', 'exec'))"
    remote = shlex.join(['python3', '-c', code, '--local', args.path,
                         '--buffer', str(args.buffer), '--remote-application', application])
    # SSH owns the terminal for authentication and the remote curses session.
    # Normal SSH host-key verification and user SSH configuration remain active.
    while True:
        rc = subprocess.call(['ssh', '-t', '-o', 'ConnectTimeout=15', host, remote])
        if rc != 255:
            return rc
        print(f'\nSSH connection to {host} failed or disconnected. Retrying in 5 seconds (Ctrl+C to stop)...', flush=True)
        time.sleep(5)


@dataclass
class Filters:
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    any_match: bool = False
    regex: bool = False
    ignore_case: bool = False

    def compile(self):
        flags = re.IGNORECASE if self.ignore_case else 0
        def patterns(values):
            return [re.compile(v if self.regex else re.escape(v), flags) for v in values if v]
        return patterns(self.include), patterns(self.exclude)


def matches(line, includes, excludes, any_match):
    return (not includes or (any if any_match else all)(p.search(line) for p in includes)) and not any(p.search(line) for p in excludes)


def clean(line):
    return ''.join(c if c.isprintable() else ' ' for c in line.expandtabs(4))


def put(screen, y, text, attr=0, x=0):
    height, width = screen.getmaxyx()
    if 0 <= y < height and 0 <= x < width - 1:
        try:
            screen.addnstr(y, x, text, width - x - 1, attr)
        except curses.error:
            pass


def prompt(screen, label):
    value = ''
    while True:
        screen.erase()
        put(screen, 0, label, curses.A_BOLD)
        put(screen, 2, '> ' + value[-max(1, screen.getmaxyx()[1] - 4):])
        put(screen, 4, 'Enter: accept | Esc: cancel')
        screen.refresh()
        try:
            key = screen.get_wch()
        except curses.error:
            continue
        if key in ('\n', '\r'):
            return value
        if key == '\x1b':
            return None
        if key in (curses.KEY_BACKSPACE, '\b', '\x7f'):
            value = value[:-1]
        elif isinstance(key, str) and key.isprintable():
            value += key


def edit_filters(screen, original):
    draft = Filters(list(original.include), list(original.exclude), original.any_match,
                    original.regex, original.ignore_case)
    error = ''
    while True:
        screen.erase()
        put(screen, 0, 'Filters - Enter applies changes; Esc cancels', curses.A_BOLD)
        put(screen, 1, f"m: {'ANY' if draft.any_match else 'ALL'} | r: {'regex' if draft.regex else 'plain text'} | c: {'ignore case' if draft.ignore_case else 'case sensitive'}")
        put(screen, 3, 'a: add include | x: add exclusion | d: remove by number | z: clear')
        rows = [('+', v) for v in draft.include] + [('-', v) for v in draft.exclude]
        height = screen.getmaxyx()[0]
        for i, (kind, value) in enumerate(rows[:max(0, height - 8)], 1):
            put(screen, i + 3, f'{i}. {kind} {value}')
        put(screen, height - 3, error)
        put(screen, height - 2, f'{len(rows)} filters | + include / - exclude | Enter: apply | Esc: cancel')
        screen.refresh()
        key = screen.getch()
        if key == 27:
            return original
        if key in (10, 13):
            try:
                draft.compile()
                return draft
            except re.error as exc:
                error = f'Invalid regex: {exc}'
        elif key in (ord('a'), ord('x')):
            value = prompt(screen, 'Include text:' if key == ord('a') else 'Exclude text:')
            if value:
                (draft.include if key == ord('a') else draft.exclude).append(value)
                error = ''
        elif key == ord('d'):
            value = prompt(screen, f'Remove filter number (1-{len(rows)}):')
            if value and value.isdigit() and 1 <= int(value) <= len(rows):
                index = int(value) - 1
                if index < len(draft.include):
                    draft.include.pop(index)
                else:
                    draft.exclude.pop(index - len(draft.include))
        elif key == ord('z'):
            draft.include.clear()
            draft.exclude.clear()
        elif key == ord('m'):
            draft.any_match = not draft.any_match
        elif key == ord('r'):
            draft.regex = not draft.regex
        elif key == ord('c'):
            draft.ignore_case = not draft.ignore_case


def highlight(screen, y, line, patterns, offset, attr):
    width = max(0, screen.getmaxyx()[1] - 1)
    put(screen, y, line[offset:offset + width])
    for pattern in patterns:
        for match in pattern.finditer(line):
            start, end = max(match.start(), offset), min(match.end(), offset + width)
            if start < end:
                put(screen, y, line[start:end], attr, start - offset)


def run(screen, path, limit, application=None):
    screen.keypad(True)
    screen.timeout(100)
    monitor = StatusMonitor(application) if application else None
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    match_attr = curses.A_REVERSE | curses.A_BOLD
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_YELLOW)
        match_attr = curses.color_pair(1) | curses.A_BOLD
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    try:
        curses.mousemask(curses.ALL_MOUSE_EVENTS)
        curses.mouseinterval(0)
    except curses.error:
        pass
    first = prompt(screen, 'Initial plain-text filter (empty shows all):')
    filters = Filters(include=[first] if first else [])
    includes, excludes = filters.compile()
    lines = deque(maxlen=limit)
    filtered = []
    dirty, follow = True, True
    top = horizontal = 0
    anchor = stream = identity = None
    pending = ''
    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
    total = 0
    status = 'Waiting for log'
    last_check = 0
    try:
        while True:
            if monitor:
                monitor.poll()
            if time.monotonic() - last_check >= 0.5:
                last_check = time.monotonic()
                try:
                    current = os.stat(path)
                    if stream is None or (current.st_dev, current.st_ino) != identity:
                        new_stream = open(path, 'rb')
                        if stream is not None:
                            stream.close()
                        stream = new_stream
                        opened = os.fstat(stream.fileno())
                        identity = (opened.st_dev, opened.st_ino)
                        pending = ''
                        decoder.reset()
                    elif current.st_size < stream.tell():
                        stream.seek(0)
                        pending = ''
                        decoder.reset()
                    status = 'Reading'
                except OSError as exc:
                    status = str(exc)
            if stream is not None:
                try:
                    chunk = stream.read(256 * 1024)
                    if chunk:
                        pending += decoder.decode(chunk)
                        parts = pending.split('\n')
                        pending = parts.pop()
                        for line in parts:
                            total += 1
                            lines.append((total, clean(line.rstrip('\r'))))
                        dirty = True
                except OSError as exc:
                    status = str(exc)
                    stream.close()
                    stream = None
            height, width = screen.getmaxyx()
            log_start = 10 if monitor else 2
            page = max(1, height - log_start - 3)
            if dirty:
                filtered = [(n, line) for n, line in lines if matches(line, includes, excludes, filters.any_match)]
                if not follow and anchor is not None:
                    top = next((i for i, (n, _) in enumerate(filtered) if n >= anchor), max(0, len(filtered) - page))
                dirty = False
            maximum = max(0, len(filtered) - page)
            top = maximum if follow else min(top, maximum)
            anchor = filtered[top][0] if filtered else None
            screen.erase()
            mode = 'ANY' if filters.any_match else 'ALL'
            if monitor:
                put(screen, 0, 'MIAX APPLICATION MONITOR', curses.A_BOLD)
                put(screen, 1, f'Application: {application}  |  Host: {socket.gethostname()}', curses.A_BOLD)
                put(screen, 2, 'Connection: CONNECTED (SSH session active)', curses.A_BOLD)
                for row, label in ((3, 'Application status'), (4, 'Stream status')):
                    value, color, stale = monitor.results[label]
                    attribute = curses.A_BOLD
                    if curses.has_colors():
                        attribute |= curses.color_pair({'good': 2, 'bad': 3, 'neutral': 4}[color])
                    put(screen, row, f'{label}: {value}', attribute)
                put(screen, 5, f'Last successful check: {monitor.last_success or "none"} | Refresh: {monitor.interval}s')
                put(screen, 6, '-' * max(0, width - 1))
                put(screen, 7, f'LOG VIEWER: {path}', curses.A_BOLD)
                put(screen, 8, f"{mode} {filters.include or ['(all)']} | exclude {filters.exclude} | {'regex' if filters.regex else 'text'} | {'ignore case' if filters.ignore_case else 'case sensitive'}")
                put(screen, 9, '-' * max(0, width - 1))
            else:
                put(screen, 0, f'Live logs: {path}', curses.A_BOLD)
                put(screen, 1, f"{mode} {filters.include or ['(all)']} | exclude {filters.exclude} | {'regex' if filters.regex else 'text'} | {'ignore case' if filters.ignore_case else 'case sensitive'}")
            for row, (_, line) in enumerate(filtered[top:top + page], log_start):
                highlight(screen, row, line, includes, horizontal, match_attr)
            if width > 2 and filtered:
                thumb = log_start + round((page - 1) * top / max(1, maximum))
                for row in range(log_start, log_start + page):
                    try:
                        screen.addch(row, width - 1, '#' if row == thumb else '|')
                    except curses.error:
                        pass
            end = min(top + page, len(filtered))
            position = f'{top + 1 if filtered else 0}-{end}/{len(filtered)} matches'
            put(screen, height - 3, f"{'LIVE' if follow else 'PAUSED'} | {position} | {len(lines)}/{limit} retained | {total} read | col {horizontal + 1}", curses.A_REVERSE)
            put(screen, height - 2, status)
            put(screen, height - 1, 'Arrows/PgUp/PgDn/wheel: scroll | End/f: live | Space: pause | e: filters | q: quit')
            screen.refresh()
            key = screen.getch()
            delta = 0
            if key in (ord('q'), ord('Q')):
                break
            elif key == ord('e'):
                filters = edit_filters(screen, filters)
                includes, excludes = filters.compile()
                dirty = True
            elif key in (curses.KEY_END, ord('f')):
                follow = True
            elif key == ord(' '):
                follow = not follow
            elif key == curses.KEY_HOME:
                follow, top = False, 0
            elif key == curses.KEY_UP:
                delta = -1
            elif key == curses.KEY_DOWN:
                delta = 1
            elif key == curses.KEY_PPAGE:
                delta = -page
            elif key == curses.KEY_NPAGE:
                delta = page
            elif key == curses.KEY_LEFT:
                horizontal = max(0, horizontal - 8)
            elif key == curses.KEY_RIGHT:
                horizontal += 8
            elif key == curses.KEY_MOUSE:
                try:
                    _, x, y, _, buttons = curses.getmouse()
                    if buttons & getattr(curses, 'BUTTON4_PRESSED', 0):
                        delta = -3
                    elif buttons & getattr(curses, 'BUTTON5_PRESSED', 0):
                        delta = 3
                    elif buttons & (curses.BUTTON1_PRESSED | curses.BUTTON1_CLICKED):
                        if x >= width - 2 and log_start <= y < log_start + page:
                            follow = False
                            top = round((y - log_start) * maximum / max(1, page - 1))
                except curses.error:
                    pass
            if delta:
                follow = False
                top = max(0, min(maximum, top + delta))
            anchor = filtered[top][0] if filtered else None
    finally:
        if monitor:
            monitor.close()
        if stream is not None:
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', nargs='?', default='/logs/miax.log')
    parser.add_argument('--buffer', type=int, default=10000, help='Retained log lines')
    parser.add_argument('--application', help='Application name; otherwise prompted at startup')
    parser.add_argument('--local', action='store_true', help='View a local log without application discovery or SSH')
    parser.add_argument('--hostname-pattern', help='Regex with a named host group for miax_run_table output')
    parser.add_argument('--remote-application', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.buffer < 1:
        parser.error('--buffer must be positive')
    if args.hostname_pattern:
        try:
            pattern = re.compile(args.hostname_pattern)
            if 'host' not in pattern.groupindex:
                parser.error('--hostname-pattern needs a named (?P<host>...) group')
        except re.error as exc:
            parser.error(f'Invalid hostname pattern: {exc}')
    try:
        if args.local:
            curses.wrapper(run, args.path, args.buffer, args.remote_application)
        else:
            return launch_application(args)
    except (KeyboardInterrupt, EOFError):
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
