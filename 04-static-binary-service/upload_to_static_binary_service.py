#!/usr/bin/env python3
"""
多架构软件包管理系统 - 文件上传脚本
功能：批量上传指定文件夹中的所有文件到软件包管理系统
修复大文件上传进度显示负数的问题，并在每个文件结束后立即显示结果
"""

import os
import sys
import time
import argparse
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import concurrent.futures
from tqdm import tqdm
import json
import hashlib

class PackageUploader:
    def __init__(self, base_url: str, max_workers: int = 3):
        """
        初始化上传器

        Args:
            base_url: 服务的基础URL，例如: http://localhost:8080
            max_workers: 最大并发上传线程数
        """
        self.base_url = base_url.rstrip('/')
        self.max_workers = max_workers
        self.session = requests.Session()

        # 统计信息
        self.stats = {
            'total_files': 0,
            'skipped_valid': 0,
            'skipped_after_check': 0,
            'replaced_invalid': 0,
            'replaced_after_check': 0,
            'uploaded_new': 0,
            'failed': 0,
            'total_size': 0,
            'uploaded_size': 0,
            'deleted_size': 0,
            'check_requests': 0,
            'wait_time': 0,
            'start_time': None,
            'end_time': None,
            'retry_count': 0
        }

        # 失败文件列表
        self.failed_files = []

        # 成功文件列表
        self.successful_files = []

        # 跳过的文件列表
        self.skipped_files = []

        # 替换的文件列表
        self.replaced_files = []

    def _calculate_md5(self, file_path: Path) -> str:
        """计算文件的MD5哈希值"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            return ""

    def _format_size(self, bytes_size: int) -> str:
        """格式化文件大小"""
        if bytes_size >= 1024 * 1024 * 1024:  # GB
            return f"{bytes_size / (1024 * 1024 * 1024):.2f} GB"
        elif bytes_size >= 1024 * 1024:  # MB
            return f"{bytes_size / (1024 * 1024):.2f} MB"
        elif bytes_size >= 1024:  # KB
            return f"{bytes_size / 1024:.2f} KB"
        else:  # B
            return f"{bytes_size} B"

    def _format_speed(self, bytes_per_sec: float) -> str:
        """格式化上传速度"""
        if bytes_per_sec >= 1024 * 1024:  # MB/s
            return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
        elif bytes_per_sec >= 1024:  # KB/s
            return f"{bytes_per_sec / 1024:.2f} KB/s"
        else:  # B/s
            return f"{bytes_per_sec:.2f} B/s"

    def _format_time(self, seconds: float) -> str:
        """格式化时间"""
        if seconds < 60:
            return f"{seconds:.1f}秒"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            seconds = seconds % 60
            return f"{minutes}分{seconds:.0f}秒"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            seconds = seconds % 60
            return f"{hours}小时{minutes}分{seconds:.0f}秒"

    def _format_duration(self, seconds: float) -> str:
        """格式化持续时间"""
        if seconds < 1:
            return f"{seconds*1000:.0f}毫秒"
        else:
            return self._format_time(seconds)

    def check_server_health(self) -> bool:
        """检查服务器健康状态"""
        try:
            health_url = f"{self.base_url}/api/health"
            print(f"尝试连接到: {health_url}")

            # 设置更长的超时时间
            response = self.session.get(health_url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                print(f"服务器状态: {data.get('status', 'unknown')}")
                if data.get('database'):
                    print(f"数据库: {data.get('database', 'unknown')}")
                if data.get('storage'):
                    print(f"存储: {data.get('storage', 'unknown')}")
                return True
            else:
                print(f"服务器健康检查失败: HTTP {response.status_code}")
                print(f"响应内容: {response.text[:200]}")
                return False

        except requests.exceptions.ConnectTimeout:
            print(f"连接超时: 无法在15秒内连接到服务器 {self.base_url}")
            return False
        except requests.exceptions.ConnectionError as e:
            print(f"连接错误: {e}")
            print("请检查:")
            print(f"  1. 服务器地址是否正确: {self.base_url}")
            print(f"  2. 服务器是否正在运行")
            print(f"  3. 防火墙设置是否允许访问端口8080")
            print(f"  4. 网络连接是否正常")
            return False
        except requests.exceptions.Timeout:
            print(f"请求超时: 服务器响应时间过长")
            return False
        except requests.exceptions.RequestException as e:
            print(f"请求异常: {e}")
            return False
        except Exception as e:
            print(f"未知错误: {e}")
            return False

    def _get_package_status(self, package_id: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        获取软件包的校验状态

        Args:
            package_id: 软件包ID

        Returns:
            (是否存在, 校验状态, 包信息)
        """
        try:
            url = f"{self.base_url}/api/packages/{package_id}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    package_info = data.get('package', {})
                    check_status = package_info.get('check_status', 'unknown')
                    return True, check_status, package_info

            elif response.status_code == 404:
                return False, None, None

        except requests.exceptions.RequestException as e:
            print(f"  查询包状态失败: {e}")

        return False, None, None

    def _trigger_package_check(self, package_id: str) -> Tuple[bool, Optional[str]]:
        """
        触发软件包校验

        Args:
            package_id: 软件包ID

        Returns:
            (是否成功, 校验状态)
        """
        try:
            self.stats['check_requests'] += 1
            url = f"{self.base_url}/api/packages/{package_id}/check"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return True, data.get('check_status', 'unknown')

        except requests.exceptions.RequestException as e:
            print(f"  触发校验失败: {e}")

        return False, None

    def _wait_for_check_completion(self, package_id: str, filename: str,
                                   max_wait_time: int = 120, poll_interval: int = 2) -> Tuple[str, Optional[Dict]]:
        """
        等待软件包校验完成

        Args:
            package_id: 软件包ID
            filename: 文件名（用于显示）
            max_wait_time: 最大等待时间（秒）
            poll_interval: 轮询间隔（秒）

        Returns:
            (最终状态, 包信息)
        """
        print(f"  等待校验完成...")

        start_time = time.time()
        last_status = None

        # 创建进度条
        with tqdm(total=max_wait_time, unit='s', desc="  校验",
                  bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}s [{elapsed}<{remaining}]') as pbar:

            while time.time() - start_time < max_wait_time:
                exists, status, package_info = self._get_package_status(package_id)

                if not exists:
                    return 'not_found', None

                # 显示当前状态
                if status != last_status:
                    if status == 'checking':
                        pbar.set_postfix({'status': '校验中'})
                    elif status == 'valid':
                        pbar.set_postfix({'status': '通过'})
                        pbar.update(max_wait_time)  # 直接完成
                        return status, package_info
                    elif status == 'invalid':
                        pbar.set_postfix({'status': '失败'})
                        pbar.update(max_wait_time)  # 直接完成
                        return status, package_info
                    elif status == 'pending':
                        pbar.set_postfix({'status': '待校验'})
                    else:
                        pbar.set_postfix({'status': status})
                    last_status = status

                # 如果状态变为 checking，说明校验已经开始
                if status == 'checking':
                    pass  # 继续等待
                elif status in ['valid', 'invalid']:
                    # 校验完成
                    wait_time = time.time() - start_time
                    self.stats['wait_time'] += wait_time
                    return status, package_info
                elif status == 'pending':
                    # 如果还是pending，触发校验
                    success, new_status = self._trigger_package_check(package_id)
                    if success and new_status:
                        status = new_status
                        if status in ['valid', 'invalid']:
                            # 立即返回结果
                            wait_time = time.time() - start_time
                            self.stats['wait_time'] += wait_time
                            return status, package_info

                # 更新进度条
                elapsed = time.time() - start_time
                pbar.update(min(poll_interval, max_wait_time - elapsed))

                # 等待轮询间隔
                time.sleep(poll_interval)

        # 超时
        wait_time = time.time() - start_time
        self.stats['wait_time'] += wait_time
        print(f"  校验超时（{max_wait_time}秒）")
        return 'timeout', None

    def _delete_package(self, package_id: str) -> bool:
        """
        删除软件包

        Args:
            package_id: 软件包ID

        Returns:
            是否删除成功
        """
        try:
            url = f"{self.base_url}/api/packages/{package_id}"
            response = self.session.delete(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return data.get('success', False)

        except requests.exceptions.RequestException as e:
            print(f"  删除包失败: {e}")

        return False

    def _check_and_upload_file(self, file_path: Path, max_retries: int = 3) -> Tuple[str, Optional[str], Optional[Dict]]:
        """
        检查并上传单个文件

        Args:
            file_path: 文件路径
            max_retries: 最大重试次数

        Returns:
            (状态, 错误信息, 响应数据)
            状态: 'skipped_valid', 'skipped_after_check', 'replaced_invalid',
                 'replaced_after_check', 'uploaded', 'failed'
        """
        filename = file_path.name
        file_size = file_path.stat().st_size

        # 1. 计算文件MD5
        file_md5 = self._calculate_md5(file_path)
        if not file_md5:
            return 'failed', "无法计算文件MD5", None

        # 2. 检查包是否存在
        exists, check_status, package_info = self._get_package_status(file_md5)

        if exists:
            if check_status == 'valid':
                # 校验通过，跳过
                print(f"  ✓ 跳过: {filename} - 已存在且校验通过")
                return 'skipped_valid', None, {
                    'filename': filename,
                    'package_id': file_md5,
                    'size': file_size,
                    'status': 'already_valid'
                }
            elif check_status == 'invalid':
                # 校验不通过，先删除
                print(f"  ! 软件包存在但校验不通过，删除后重新上传")
                if self._delete_package(file_md5):
                    self.stats['deleted_size'] += file_size
                else:
                    return 'failed', "删除旧包失败", None
            elif check_status in ['pending', 'checking']:
                # 未校验或正在校验，等待校验完成
                print(f"  ⏳ 软件包存在但未校验，等待校验完成...")

                final_status, final_package_info = self._wait_for_check_completion(
                    file_md5, filename, max_wait_time=60, poll_interval=2
                )

                if final_status == 'valid':
                    # 校验通过，跳过
                    print(f"  ✓ 跳过: {filename} - 校验后通过")
                    return 'skipped_after_check', None, {
                        'filename': filename,
                        'package_id': file_md5,
                        'size': file_size,
                        'status': 'checked_valid'
                    }
                elif final_status == 'invalid':
                    # 校验不通过，删除后重新上传
                    print(f"  ! 软件包校验不通过，删除后重新上传")
                    if self._delete_package(file_md5):
                        self.stats['deleted_size'] += file_size
                    else:
                        return 'failed', "删除旧包失败", None
                else:
                    # 超时或未找到
                    return 'failed', f"校验等待超时或失败: {final_status}", None
            else:
                # 其他未知状态
                print(f"  ! 软件包存在但状态未知('{check_status}')，删除后重新上传")
                if self._delete_package(file_md5):
                    self.stats['deleted_size'] += file_size
                else:
                    return 'failed', "删除旧包失败", None

        # 3. 上传文件
        upload_result = self._upload_file_with_progress(file_path, file_md5, max_retries)

        if upload_result[0]:  # 上传成功
            if exists:
                if check_status == 'invalid':
                    return 'replaced_invalid', None, upload_result[2]
                elif check_status in ['pending', 'checking']:
                    return 'replaced_after_check', None, upload_result[2]
                else:
                    return 'replaced', None, upload_result[2]
            else:
                return 'uploaded', None, upload_result[2]
        else:
            return 'failed', upload_result[1], None

    def _upload_file_with_progress(self, file_path: Path, package_id: str, max_retries: int = 3) -> Tuple[bool, str, Optional[Dict]]:
        """
        上传单个文件，显示上传进度（修复大文件进度显示负数问题）

        Args:
            file_path: 文件路径
            package_id: 包ID（MD5）
            max_retries: 最大重试次数

        Returns:
            (是否成功, 错误信息, 响应数据)
        """
        filename = file_path.name
        file_size = file_path.stat().st_size

        # 上传文件
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    print(f"  重试 {attempt}/{max_retries}...")
                    self.stats['retry_count'] += 1
                    time.sleep(min(2 ** attempt, 10))  # 指数退避

                # 准备上传
                upload_url = f"{self.base_url}/api/packages/upload"

                # 使用 requests_toolbelt 的监控器（如果可用）
                try:
                    from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor

                    # 创建多部分编码器
                    encoder = MultipartEncoder({
                        'file': (filename, open(file_path, 'rb'), 'application/octet-stream')
                    })

                    # 记录开始时间和已上传字节数
                    start_time = time.time()
                    uploaded_bytes = 0
                    last_update_time = start_time

                    # 创建进度条
                    progress_bar = tqdm(
                        total=file_size,
                        unit='B',
                        unit_scale=True,
                        desc=f"上传 {filename[:20]}...",
                        leave=False,
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
                        miniters=1
                    )

                    # 进度回调函数
                    def progress_callback(monitor):
                        """上传进度回调 - 修复版"""
                        nonlocal progress_bar, uploaded_bytes, last_update_time

                        current_bytes = monitor.bytes_read

                        # 确保不会超过文件总大小
                        if current_bytes > file_size:
                            current_bytes = file_size

                        # 计算增量
                        delta = current_bytes - uploaded_bytes
                        if delta <= 0:
                            return  # 没有新数据，不更新

                        # 更新进度条
                        progress_bar.update(delta)
                        uploaded_bytes = current_bytes

                        # 计算速度（每0.5秒更新一次）
                        current_time = time.time()
                        if current_time - last_update_time >= 0.5:
                            elapsed_time = current_time - last_update_time
                            if elapsed_time > 0:
                                current_speed = delta / elapsed_time
                                progress_bar.set_postfix_str(f"{self._format_speed(current_speed)}")
                            last_update_time = current_time

                    # 创建监控器
                    monitor = MultipartEncoderMonitor(encoder, progress_callback)

                    # 设置请求头
                    headers = {'Content-Type': monitor.content_type}

                    # 发送请求
                    response = self.session.post(
                        upload_url,
                        data=monitor,
                        headers=headers,
                        timeout=300  # 5分钟超时
                    )

                    # 确保进度条显示100%
                    progress_bar.n = file_size
                    progress_bar.last_print_n = file_size
                    progress_bar.refresh()
                    progress_bar.close()

                except ImportError:
                    # 如果 requests_toolbelt 不可用，使用普通方式上传（无进度显示）
                    print(f"  注意: 未安装 requests_toolbelt，使用普通上传方式")
                    with open(file_path, 'rb') as f:
                        files = {'file': (filename, f)}
                        response = self.session.post(
                            upload_url,
                            files=files,
                            timeout=300
                        )

                # 处理响应
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        # 解析包信息
                        package_info = data.get('package_info', {})
                        returned_package_id = data.get('package_id', package_id)

                        return True, "", {
                            'filename': filename,
                            'package_id': returned_package_id,
                            'package_info': package_info,
                            'size': file_size
                        }
                    else:
                        error_msg = data.get('error', '未知错误')
                        print(f"  ✗ 失败: {filename} - {error_msg}")
                        return False, error_msg, None
                elif response.status_code == 409:
                    # 包已存在（虽然在前面检查过，但可能同时上传导致冲突）
                    data = response.json()
                    returned_package_id = data.get('package_id', package_id)

                    print(f"  ⚠ 跳过: {filename} - 已存在 (包ID: {returned_package_id})")

                    return True, "已存在", {
                        'filename': filename,
                        'package_id': returned_package_id,
                        'size': file_size,
                        'status': 'already_exists'
                    }
                else:
                    error_msg = f"HTTP {response.status_code}: {response.text[:100]}"
                    print(f"  ✗ 失败: {filename} - {error_msg}")
                    return False, error_msg, None

            except requests.exceptions.Timeout:
                error_msg = "上传超时"
                if attempt == max_retries - 1:
                    print(f"  ✗ 失败: {filename} - {error_msg}")
                    return False, error_msg, None
            except requests.exceptions.RequestException as e:
                error_msg = str(e)
                if attempt == max_retries - 1:
                    print(f"  ✗ 失败: {filename} - {error_msg}")
                    return False, error_msg, None
            except Exception as e:
                error_msg = f"未知错误: {e}"
                if attempt == max_retries - 1:
                    print(f"  ✗ 失败: {filename} - {error_msg}")
                    return False, error_msg, None
            finally:
                # 确保进度条被关闭
                if 'progress_bar' in locals():
                    try:
                        progress_bar.close()
                    except:
                        pass

        return False, "达到最大重试次数", None

    def upload_folder(self, folder_path: str, max_retries: int = 3) -> bool:
        """
        上传文件夹中的所有文件

        Args:
            folder_path: 文件夹路径
            max_retries: 最大重试次数

        Returns:
            是否所有文件都处理成功
        """
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            print(f"错误: 文件夹不存在或不是目录: {folder_path}")
            return False

        # 检查服务器健康状态
        print(f"连接服务器: {self.base_url}")
        if not self.check_server_health():
            print("服务器不可用，请检查服务器状态和连接")
            return False

        print(f"上传文件夹: {folder_path}")
        print("处理策略: 校验通过的跳过，校验不通过的删除后重新上传，未校验的先校验后决定")
        print("-" * 60)

        # 获取所有文件
        files = []
        for file_path in folder.iterdir():
            if file_path.is_file():
                files.append(file_path)

        if not files:
            print("文件夹中没有找到文件")
            return True

        self.stats['total_files'] = len(files)
        self.stats['start_time'] = time.time()

        # 计算总大小
        total_size = sum(f.stat().st_size for f in files)
        self.stats['total_size'] = total_size

        print(f"找到 {len(files)} 个文件，总大小: {self._format_size(total_size)}")
        print("-" * 60)

        # 显示处理开始
        print("\n开始处理文件...")

        # 并发处理文件
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交处理任务
            future_to_file = {
                executor.submit(self._process_single_file, file_path, max_retries): file_path
                for file_path in files
            }

            # 处理结果
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                filename = file_path.name
                file_size = file_path.stat().st_size

                try:
                    status, error_msg, result_data = future.result()

                    if status == 'skipped_valid':
                        self.stats['skipped_valid'] += 1
                        self.skipped_files.append({
                            'filename': filename,
                            'package_id': result_data.get('package_id', 'N/A') if result_data else 'N/A',
                            'size': file_size,
                            'status': 'valid',
                            'action': 'skipped'
                        })

                    elif status == 'skipped_after_check':
                        self.stats['skipped_after_check'] += 1
                        self.skipped_files.append({
                            'filename': filename,
                            'package_id': result_data.get('package_id', 'N/A') if result_data else 'N/A',
                            'size': file_size,
                            'status': 'valid',
                            'action': 'checked_and_skipped'
                        })

                    elif status == 'replaced_invalid':
                        self.stats['replaced_invalid'] += 1
                        self.stats['uploaded_size'] += file_size
                        self.replaced_files.append({
                            'filename': filename,
                            'package_id': result_data.get('package_id', 'N/A') if result_data else 'N/A',
                            'size': file_size,
                            'package_info': result_data.get('package_info', {}) if result_data else {},
                            'old_status': 'invalid',
                            'action': 'replaced'
                        })

                    elif status == 'replaced_after_check':
                        self.stats['replaced_after_check'] += 1
                        self.stats['uploaded_size'] += file_size
                        self.replaced_files.append({
                            'filename': filename,
                            'package_id': result_data.get('package_id', 'N/A') if result_data else 'N/A',
                            'size': file_size,
                            'package_info': result_data.get('package_info', {}) if result_data else {},
                            'old_status': 'invalid_after_check',
                            'action': 'checked_and_replaced'
                        })

                    elif status == 'uploaded':
                        self.stats['uploaded_new'] += 1
                        self.stats['uploaded_size'] += file_size
                        print(f"  ✓ 成功: {filename} - 上传完成 ({self._format_size(file_size)})")
                        self.successful_files.append({
                            'filename': filename,
                            'package_id': result_data.get('package_id', 'N/A') if result_data else 'N/A',
                            'size': file_size,
                            'package_info': result_data.get('package_info', {}) if result_data else {},
                            'action': 'uploaded_new'
                        })

                    elif status == 'failed':
                        self.stats['failed'] += 1
                        self.failed_files.append({
                            'filename': filename,
                            'error': error_msg,
                            'size': file_size
                        })
                        # 失败信息已经在上传函数中打印了

                except Exception as e:
                    self.stats['failed'] += 1
                    self.failed_files.append({
                        'filename': filename,
                        'error': f"执行异常: {str(e)}",
                        'size': file_size
                    })
                    print(f"  ✗ 失败: {filename} - 执行异常: {str(e)}")

        # 记录结束时间
        self.stats['end_time'] = time.time()

        return self.stats['failed'] == 0

    def _process_single_file(self, file_path: Path, max_retries: int) -> Tuple[str, Optional[str], Optional[Dict]]:
        """
        处理单个文件

        Args:
            file_path: 文件路径
            max_retries: 最大重试次数

        Returns:
            (状态, 错误信息, 响应数据)
        """
        filename = file_path.name
        file_size = file_path.stat().st_size

        try:
            # 检查并上传文件
            return self._check_and_upload_file(file_path, max_retries)

        except Exception as e:
            return 'failed', f"处理异常: {str(e)}", None

    def print_statistics(self):
        """打印统计信息"""
        # 检查是否已经开始处理
        if self.stats['start_time'] is None:
            print("\n未开始处理，无法显示统计信息")
            return

        print("\n" + "=" * 60)
        print("处理统计信息")
        print("=" * 60)

        if self.stats['end_time'] is None:
            self.stats['end_time'] = time.time()

        total_time = self.stats['end_time'] - self.stats['start_time']

        print(f"总文件数: {self.stats['total_files']}")
        print(f"跳过（直接校验通过）: {self.stats['skipped_valid']}")
        print(f"跳过（校验后通过）: {self.stats['skipped_after_check']}")
        print(f"替换（直接校验不通过）: {self.stats['replaced_invalid']}")
        print(f"替换（校验后不通过）: {self.stats['replaced_after_check']}")
        print(f"上传（新文件）: {self.stats['uploaded_new']}")
        print(f"失败: {self.stats['failed']}")
        print(f"重试次数: {self.stats['retry_count']}")
        print(f"校验请求次数: {self.stats['check_requests']}")
        print(f"等待校验总时间: {self._format_duration(self.stats['wait_time'])}")
        print(f"总文件大小: {self._format_size(self.stats['total_size'])}")
        print(f"已上传大小: {self._format_size(self.stats['uploaded_size'])}")
        print(f"已删除大小: {self._format_size(self.stats['deleted_size'])}")
        print(f"总耗时: {self._format_time(total_time)}")

        if total_time > 0 and self.stats['uploaded_size'] > 0:
            avg_speed = self.stats['uploaded_size'] / total_time
            print(f"平均上传速度: {self._format_speed(avg_speed)}")

        if self.stats['wait_time'] > 0 and (self.stats['skipped_after_check'] + self.stats['replaced_after_check']) > 0:
            avg_wait_time = self.stats['wait_time'] / (self.stats['skipped_after_check'] + self.stats['replaced_after_check'])
            print(f"平均校验等待时间: {self._format_duration(avg_wait_time)}")

        if self.failed_files:
            print(f"\n失败的文件 ({len(self.failed_files)}个):")
            for i, file_info in enumerate(self.failed_files[:10], 1):
                print(f"  {i}. {file_info['filename']} ({self._format_size(file_info['size'])})")
                print(f"     错误: {file_info['error'][:100]}...")
            if len(self.failed_files) > 10:
                print(f"  ... 还有 {len(self.failed_files) - 10} 个文件")

            # 保存失败文件列表到文件
            failed_list_path = "failed_uploads.json"
            with open(failed_list_path, 'w', encoding='utf-8') as f:
                json.dump(self.failed_files, f, ensure_ascii=False, indent=2)
            print(f"\n失败文件列表已保存到: {failed_list_path}")

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='批量上传文件到多架构软件包管理系统（支持智能校验，修复进度显示）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --folder ./downloads --url http://localhost:8080
  %(prog)s --folder /path/to/packages --url http://192.168.12.90:8080 --workers 5 --retries 2
  %(prog)s --folder ./my_packages --url http://example.com --wait-time 90 --poll-interval 3
        """
    )

    parser.add_argument(
        '--folder',
        required=True,
        help='包含要上传文件的文件夹路径'
    )

    parser.add_argument(
        '--url',
        required=True,
        help='服务器URL，例如: http://localhost:8080 或 http://192.168.12.90:8080'
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=3,
        help='最大并发上传线程数 (默认: 3)'
    )

    parser.add_argument(
        '--retries',
        type=int,
        default=3,
        help='每个文件的最大重试次数 (默认: 3)'
    )

    parser.add_argument(
        '--wait-time',
        type=int,
        default=60,
        help='等待校验完成的最大时间（秒）(默认: 60)'
    )

    parser.add_argument(
        '--poll-interval',
        type=int,
        default=2,
        help='轮询校验状态的间隔时间（秒）(默认: 2)'
    )

    parser.add_argument(
        '--install-deps',
        action='store_true',
        help='安装必要的依赖包 (requests, requests-toolbelt, tqdm)'
    )

    parser.add_argument(
        '--check-only',
        action='store_true',
        help='仅检查服务器连接，不进行上传'
    )

    parser.add_argument(
        '--show-all-files',
        action='store_true',
        help='显示所有文件的详细处理结果'
    )

    args = parser.parse_args()

    # 安装依赖选项
    if args.install_deps:
        print("正在安装依赖包...")
        import subprocess
        packages = ['requests', 'requests-toolbelt', 'tqdm']
        for package in packages:
            print(f"安装 {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
        print("依赖安装完成！")
        sys.exit(0)

    # 检查必要依赖
    try:
        import requests
    except ImportError:
        print("错误: 未安装 requests 库")
        print("请运行: pip install requests")
        print("或使用: python uploader.py --install-deps")
        sys.exit(1)

    # 创建上传器
    uploader = PackageUploader(base_url=args.url, max_workers=args.workers)

    # 仅检查服务器连接
    if args.check_only:
        print(f"检查服务器连接: {args.url}")
        if uploader.check_server_health():
            print("服务器连接正常")
            sys.exit(0)
        else:
            print("服务器连接失败")
            sys.exit(1)

    # 执行上传
    success = False
    try:
        success = uploader.upload_folder(
            folder_path=args.folder,
            max_retries=args.retries
        )
    except KeyboardInterrupt:
        print("\n上传被用户中断")
        uploader.print_statistics()
        sys.exit(1)
    except Exception as e:
        print(f"上传过程中发生错误: {e}")
        uploader.print_statistics()
        sys.exit(1)

    # 打印统计信息
    uploader.print_statistics()

    # 根据结果返回适当的退出码
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()