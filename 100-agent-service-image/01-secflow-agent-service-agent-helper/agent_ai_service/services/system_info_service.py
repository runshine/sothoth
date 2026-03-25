import subprocess
from typing import Dict

import psutil


class SystemInfoService:
    @staticmethod
    def collect() -> Dict[str, object]:
        return {
            'hostname': subprocess.getoutput('hostname'),
            'kernel': subprocess.getoutput('uname -a'),
            'cpu_info': subprocess.getoutput('lscpu | grep "Model name"').split(':')[-1].strip(),
            'memory': subprocess.getoutput('free -h | head -2'),
            'disks': subprocess.getoutput('df -h'),
            'network': subprocess.getoutput('ip addr show'),
            'processes': len(psutil.pids()),
            'uptime': subprocess.getoutput('uptime'),
            'container_id': subprocess.getoutput('cat /proc/self/cgroup | head -1').split('/')[-1],
        }

    @staticmethod
    def debug_tools() -> Dict[str, object]:
        return {
            'compiler': {
                'gcc': subprocess.getoutput('gcc --version | head -1'),
                'g++': subprocess.getoutput('g++ --version | head -1'),
                'clang': subprocess.getoutput('clang --version | head -1'),
            },
            'debuggers': {
                'gdb': subprocess.getoutput('gdb --version | head -1'),
                'lldb': subprocess.getoutput('lldb --version | head -1'),
            },
            'tracers': {
                'strace': subprocess.getoutput('strace --version | head -1'),
                'ltrace': subprocess.getoutput('ltrace --version | head -1'),
            },
            'other': {
                'make': subprocess.getoutput('make --version | head -1'),
                'cmake': subprocess.getoutput('cmake --version | head -1'),
            },
        }
