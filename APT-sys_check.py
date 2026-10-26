
#!/usr/bin/env python3
"""Read-only MIAX terminal application monitor. Python 3.9+; no dependencies."""
import argparse
import curses
import os
import re
import subprocess
import threading
import time
from datetime import datetime

APP_RE = re.compile(r'(?P<host>\S+)\s+(?P<id>\d+_[A-Za-z0-9]+_\d+)\s+(?P<version>\S+)(?P<rest>.*)', re.I)
STATUS_RE = re.compile(r'\[(running|down|starting|stopping|stopped|failed)\]', re.I)
PID_RE = re.compile(r'\bpid=(\d+)\b', re.I)

DEMO = '''dch4t1fgw01 00_FOI_183 3.34.0 pid=2954301 10:02 [running]
dch4t1fgw02 00_FOI_185 3.34.0 pid=2910915 10:02 [running]
dny4e1eqs01p 00_OFXD_018 3.0.0 [down]
dny4t1inj01 01_INJ_001 4.12.0 pid=2874412 10:04 [running]
'''

def parse_apps(output):
    rows = []
    for line in output.splitlines():
        line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).strip()
        m = APP_RE.search(line)
        if not m:
            continue
        st = STATUS_RE.search(m.group('rest'))
        pid = PID_RE.search(m.group('rest'))
        cloud, app, instance = m.group('id').split('_', 2)
        rows.append(dict(host=m.group('host'), id=m.group('id'), cloud=cloud,
                         app=app, instance=instance, version=m.group('version'),
                         pid=pid.group(1) if pid else '-',
                         status=st.group(1).upper() if st else 'UNKNOWN'))
    return rows

def collect(demo, timeout):
    if demo:
        return parse_apps(DEMO), None
    try:
        p = subprocess.run(['/apps/miaxprod/scripts/miax_status'],
                           capture_output=True, text=True, timeout=timeout, check=False)
        if p.returncode != 0:
            return [], 'miax_status failed (exit %s): %s' % (p.returncode, p.stderr.strip()[:120])
        rows = parse_apps(p.stdout)
        if not rows:
            return [], 'No recognized application rows; verify output format'
        return rows, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)[:160]

class Monitor:
    def __init__(self, demo, refresh, timeout):
        self.demo, self.refresh, self.timeout = demo, refresh, timeout
        self.rows, self.error, self.checked = [], 'Waiting for first check', 0
        self.lock = threading.Lock()
        self.busy = False
        self.refresh_async()

    def refresh_async(self):
        with self.lock:
            if self.busy:
                return
            self.busy = True
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        try:
            rows, err = collect(self.demo, self.timeout)
            with self.lock:
                self.rows, self.error, self.checked = rows, err, time.monotonic()
        finally:
            with self.lock:
                self.busy = False

def draw(stdscr, monitor):
    curses.curs_set(0)
    stdscr.nodelay(True)
    curses.start_color()
    curses.use_default_colors()
    for i, fg in [(1,curses.COLOR_CYAN),(2,curses.COLOR_GREEN),
                  (3,curses.COLOR_RED),(4,curses.COLOR_YELLOW)]:
        curses.init_pair(i, fg, -1)
    selected, filter_fail, app_filter, scroll = 0, False, '', 0
    def put(y, x, s, color=0):
        h,w=stdscr.getmaxyx()
        if 0 <= y < h and x < w:
            try: stdscr.addnstr(y,x,str(s),max(0,w-x-1),curses.color_pair(color))
            except curses.error: pass
    while True:
        h,w=stdscr.getmaxyx()
        stdscr.erase()
        with monitor.lock:
            rows=list(monitor.rows); error=monitor.error; checked=monitor.checked; busy=monitor.busy
        if not busy and time.monotonic()-checked >= monitor.refresh:
            monitor.refresh_async()
        visible=[r for r in rows if (not filter_fail or r['status']!='RUNNING')
                 and (not app_filter or app_filter.upper() in r['id'].upper())]
        selected=max(0,min(selected,len(visible)-1))
        if selected<scroll: scroll=selected
        if selected>=scroll+max(1,h-9): scroll=selected-max(1,h-9)+1
        put(0,0,'MIAX OPERATIONS CONTROL  |  APPLICATION STATUS',1)
        put(1,0,'Read-only  |  %s  |  %s' % ('DEMO DATA' if monitor.demo else 'LIVE',datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        put(2,0,'TOTAL %d  RUNNING %d  DOWN %d  OTHER %d' % (
            len(rows),sum(r['status']=='RUNNING' for r in rows),
            sum(r['status']=='DOWN' for r in rows),sum(r['status'] not in ('RUNNING','DOWN') for r in rows)),1)
        put(3,0,'Filter: %s | Failures only: %s | %s' % (app_filter or 'ALL',filter_fail,'Refreshing...' if busy else 'Ready'))
        put(4,0,'APPLICATION       HOST                 VERSION      PID         STATUS',1)
        for idx,r in enumerate(visible[scroll:scroll+max(1,h-9)],start=scroll):
            y=5+idx-scroll
            marker='>' if idx==selected else ' '
            line='%-1s %-17s %-20.20s %-12.12s %-11.11s %s' % (
                marker,r['id'],r['host'],r['version'],r['pid'],r['status'])
            color=2 if r['status']=='RUNNING' else 3 if r['status']=='DOWN' else 4
            put(y,0,line,color)
        if visible and h>=8:
            r=visible[selected]
            put(h-4,0,'SELECTED: %s | Cloud %s | Type %s | Instance %s' % (r['id'],r['cloud'],r['app'],r['instance']),1)
        if error: put(h-3,0,'CHECK ERROR: '+error,3)
        else: put(h-3,0,'Last collection: %s' % ('pending' if not checked else 'completed'),2)
        put(h-2,0,'UP/DOWN Navigate  F Failures  / Filter  C Clear  R Refresh  Q Quit',1)
        stdscr.refresh()
        key=stdscr.getch()
        if key in (ord('q'),ord('Q')): break
        if key in (curses.KEY_DOWN,ord('j')): selected+=1
        elif key in (curses.KEY_UP,ord('k')): selected-=1
        elif key in (ord('f'),ord('F')): filter_fail=not filter_fail;selected=scroll=0
        elif key in (ord('c'),ord('C')): app_filter='';selected=scroll=0
        elif key in (ord('r'),ord('R')): monitor.refresh_async()
        elif key==ord('/'):
            curses.echo();stdscr.nodelay(False)
            put(h-1,0,'Filter app (e.g. FOI or 00_FOI_183): ')
            stdscr.clrtoeol();stdscr.refresh()
            try: app_filter=stdscr.getstr(h-1,min(w-2,37),40).decode('utf-8','replace').strip()
            except curses.error: pass
            curses.noecho();stdscr.nodelay(True);selected=scroll=0
        time.sleep(.1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--demo',action='store_true',help='Use example data, no production commands')
    p.add_argument('--refresh',type=int,default=30)
    p.add_argument('--timeout',type=int,default=10)
    args=p.parse_args()
    if args.refresh<1 or args.timeout<1: p.error('refresh and timeout must be positive')
    curses.wrapper(draw,Monitor(args.demo,args.refresh,args.timeout))
if __name__=='__main__': main()

