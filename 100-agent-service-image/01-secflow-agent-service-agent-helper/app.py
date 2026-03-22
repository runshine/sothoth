#!/usr/bin/env python3
"""
远程命令执行API服务
支持超时控制、特权执行、安全限制
"""

import os
import json
import subprocess
import shlex
import threading
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
import psutil

app = Flask(__name__)
CORS(app)

# 从环境变量获取配置
TIMEOUT = int(os.getenv('TIMEOUT', 180))
ALLOWED_COMMANDS = os.getenv('ALLOWED_COMMANDS', '').split(',')
BLOCKED_COMMANDS = ['rm -rf /']  # 危险命令黑名单

class CommandExecutor:
    """安全的命令执行器"""

    def __init__(self, timeout=TIMEOUT):
        self.timeout = timeout
        self.process = None

    def execute(self, command, env_vars=None):
        """执行命令并返回结果"""
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'returncode': -1,
            'execution_time': 0,
            'pid': None,
            'error': None
        }

        # 安全检查
        if not self._is_command_safe(command):
            result['error'] = 'Command blocked for security reasons'
            return result

        start_time = time.time()

        try:
            # 准备环境变量
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)

            # 执行命令（使用timeout包装，防止超时）
            self.process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid,  # 创建新进程组
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            result['pid'] = self.process.pid

            # 设置超时
            try:
                stdout, stderr = self.process.communicate(timeout=self.timeout)
                result['stdout'] = stdout
                result['stderr'] = stderr
                result['returncode'] = self.process.returncode
                result['success'] = self.process.returncode == 0

            except subprocess.TimeoutExpired:
                # 超时处理
                self._terminate_process_tree(self.process.pid)
                result['error'] = f'Command timed out after {self.timeout} seconds'
                result['stderr'] = 'Command execution timeout'

        except Exception as e:
            result['error'] = str(e)
        finally:
            result['execution_time'] = round(time.time() - start_time, 3)

        return result

    def _is_command_safe(self, command):
        """检查命令安全性"""
        # 检查黑名单
        for blocked in BLOCKED_COMMANDS:
            if blocked in command:
                return False

        # 如果有白名单，只允许白名单内的命令
        if ALLOWED_COMMANDS and ALLOWED_COMMANDS[0]:
            allowed = False
            for allowed_cmd in ALLOWED_COMMANDS:
                if allowed_cmd in command:
                    allowed = True
                    break
            if not allowed:
                return False

        return True

    def _terminate_process_tree(self, pid):
        """终止进程树"""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            for child in children:
                try:
                    child.terminate()
                except:
                    pass

            parent.terminate()

            # 等待进程结束
            gone, alive = psutil.wait_procs(children + [parent], timeout=5)

            # 强制杀死仍在运行的进程
            for p in alive:
                p.kill()
        except:
            pass

# 全局执行器实例
executor = CommandExecutor()

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查端点"""
    return jsonify({
        'status': 'healthy',
        'service': 'remote-command-executor',
        'version': '1.0.0',
        'timeout': TIMEOUT,
        'privileged': True
    })

@app.route('/api/execute', methods=['POST'])
def execute_command():
    """执行命令API"""
    try:
        data = request.get_json()

        if not data or 'command' not in data:
            return jsonify({
                'success': False,
                'error': 'No command provided'
            }), 400

        command = data['command']
        env_vars = data.get('env', {})

        # 添加调试信息
        print(f"Executing command: {command}")

        # 执行命令
        result = executor.execute(command, env_vars)

        # 返回结果
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/system/info', methods=['GET'])
def system_info():
    """获取系统信息"""
    try:
        info = {
            'hostname': subprocess.getoutput('hostname'),
            'kernel': subprocess.getoutput('uname -a'),
            'cpu_info': subprocess.getoutput('lscpu | grep "Model name"').split(':')[-1].strip(),
            'memory': subprocess.getoutput('free -h | head -2'),
            'disks': subprocess.getoutput('df -h'),
            'network': subprocess.getoutput('ip addr show'),
            'processes': len(psutil.pids()),
            'uptime': subprocess.getoutput('uptime'),
            'container_id': subprocess.getoutput('cat /proc/self/cgroup | head -1').split('/')[-1]
        }

        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/tools', methods=['GET'])
def debug_tools():
    """获取可用调试工具"""
    tools = {
        'compiler': {
            'gcc': subprocess.getoutput('gcc --version | head -1'),
            'g++': subprocess.getoutput('g++ --version | head -1'),
            'clang': subprocess.getoutput('clang --version | head -1')
        },
        'debuggers': {
            'gdb': subprocess.getoutput('gdb --version | head -1'),
            'lldb': subprocess.getoutput('lldb --version | head -1')
        },
        'tracers': {
            'strace': subprocess.getoutput('strace --version | head -1'),
            'ltrace': subprocess.getoutput('ltrace --version | head -1')
        },
        'other': {
            'make': subprocess.getoutput('make --version | head -1'),
            'cmake': subprocess.getoutput('cmake --version | head -1')
        }
    }
    return jsonify(tools)

if __name__ == '__main__':
    port = int(os.getenv('REST_PORT', 20001))
    app.run(host='0.0.0.0', port=port, debug=False)
