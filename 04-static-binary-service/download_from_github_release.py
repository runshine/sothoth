#!/usr/bin/env python3
"""
GitHub Releases下载脚本
支持重试机制、下载统计信息，显示实时下载速度
只过滤GitHub自动生成的Source code压缩包
支持从release页面获取SHA256哈希值并进行文件校验
"""

import os
import sys
import time
import argparse
import requests
import hashlib
import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
import threading

class GitHubReleaseDownloader:
    def __init__(self, max_retries: int = 10):
        """
        初始化下载器

        Args:
            max_retries: 最大重试次数
        """
        self.max_retries = max_retries
        self.session = requests.Session()
        # 设置合理的请求头，模拟浏览器访问
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # 统计信息
        self.stats = {
            'total_files': 0,
            'filtered_files': 0,
            'available_files': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,  # 新增：跳过的文件数
            'hash_verified': 0,  # 新增：哈希校验成功的文件数
            'hash_failed': 0,  # 新增：哈希校验失败的文件数
            'total_size': 0,
            'retry_count': 0,
            'start_time': None,
            'end_time': None
        }

        # 失败文件列表
        self.failed_files = []

        # 过滤的文件列表
        self.filtered_files = []

        # 哈希映射字典，存储文件名到哈希值的映射
        self.hash_map = {}

    def _format_speed(self, bytes_per_sec: float) -> str:
        """
        格式化下载速度

        Args:
            bytes_per_sec: 每秒字节数

        Returns:
            格式化后的速度字符串
        """
        if bytes_per_sec >= 1024 * 1024:  # MB/s
            return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
        elif bytes_per_sec >= 1024:  # KB/s
            return f"{bytes_per_sec / 1024:.2f} KB/s"
        else:  # B/s
            return f"{bytes_per_sec:.2f} B/s"

    def _format_size(self, bytes_size: int) -> str:
        """
        格式化文件大小

        Args:
            bytes_size: 字节数

        Returns:
            格式化后的大小字符串
        """
        if bytes_size >= 1024 * 1024 * 1024:  # GB
            return f"{bytes_size / (1024 * 1024 * 1024):.2f} GB"
        elif bytes_size >= 1024 * 1024:  # MB
            return f"{bytes_size / (1024 * 1024):.2f} MB"
        elif bytes_size >= 1024:  # KB
            return f"{bytes_size / 1024:.2f} KB"
        else:  # B
            return f"{bytes_size} B"

    def _format_time(self, seconds: float) -> str:
        """
        格式化时间

        Args:
            seconds: 秒数

        Returns:
            格式化后的时间字符串
        """
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

    def _calculate_file_hash(self, filepath: Path, hash_type: str = "sha256") -> Optional[str]:
        """
        计算文件的哈希值

        Args:
            filepath: 文件路径
            hash_type: 哈希算法类型，支持 'md5', 'sha1', 'sha256'

        Returns:
            文件的哈希值，如果文件不存在或出错则返回None
        """
        if not filepath.exists():
            return None

        try:
            hash_func = getattr(hashlib, hash_type)()
            with open(filepath, 'rb') as f:
                # 以64KB块读取文件，避免大文件内存占用过高
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"    计算文件哈希值时出错: {e}")
            return None

    def _extract_hashes_from_release_page(self, release_url: str) -> Dict[str, str]:
        """
        从GitHub release页面提取SHA256哈希值

        注意：GitHub release页面的哈希值通常显示在文件下载链接旁边，
        格式可能是：文件名 + SHA256哈希值（64位十六进制字符串）

        Args:
            release_url: GitHub release页面URL

        Returns:
            文件名到SHA256哈希值的映射字典
        """
        hash_map = {}

        try:
            # 获取release页面HTML内容
            response = self.session.get(release_url, timeout=10)
            response.raise_for_status()
            html_content = response.text

            # 在HTML中查找SHA256哈希值
            # GitHub release页面的哈希值通常在<code>标签中或文件下载链接附近
            # 常见模式：64位十六进制字符串（SHA256）
            sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
            all_hashes = re.findall(sha256_pattern, html_content)

            if not all_hashes:
                print("    警告: 在release页面中未找到SHA256哈希值")
                return hash_map

            print(f"    找到 {len(all_hashes)} 个SHA256哈希值")

            # 尝试查找文件名和哈希值的关联
            # GitHub的release页面通常有类似这样的结构：
            # <span>文件名称</span> ... <code>哈希值</code>
            # 或者 <a>文件链接</a> ... <samp>哈希值</samp>

            # 查找所有可能的文件名（在下载链接中）
            file_pattern = r'href="(/releases/download/[^"]+/([^"]+))"'
            file_matches = re.findall(file_pattern, html_content)

            for file_url, filename in file_matches:
                # 在文件名附近查找哈希值
                # 构建一个在文件名后1000个字符内查找哈希值的模式
                escaped_filename = re.escape(filename)
                hash_near_file_pattern = f'{escaped_filename}[^<]*?<code>[^<]*?({sha256_pattern})[^<]*?</code>'
                match = re.search(hash_near_file_pattern, html_content, re.IGNORECASE)

                if match:
                    file_hash = match.group(1)
                    hash_map[filename] = file_hash
                    print(f"    为 {filename} 找到哈希值: {file_hash[:16]}...")

            # 如果没有找到关联，至少保存找到的哈希值
            if not hash_map and all_hashes:
                print(f"    注意: 无法将哈希值与具体文件关联，将尝试自动匹配")
                # 将哈希值存储在类变量中，供后续尝试匹配
                self._found_hashes = all_hashes

        except Exception as e:
            print(f"    从release页面提取哈希值时出错: {e}")
            import traceback
            print(f"    错误详情: {traceback.format_exc()}")

        return hash_map

    def _extract_hashes_from_api(self, api_url: str) -> Dict[str, str]:
        """
        从GitHub API获取哈希值信息

        Args:
            api_url: GitHub API地址

        Returns:
            文件名到SHA256哈希值的映射字典
        """
        hash_map = {}

        try:
            response = self.session.get(api_url)
            response.raise_for_status()
            release_data = response.json()

            # 检查release描述中是否包含哈希值
            body = release_data.get('body', '')
            if body:
                # 在描述中查找哈希值
                sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
                hashes_in_body = re.findall(sha256_pattern, body)

                if hashes_in_body:
                    print(f"    在release描述中找到 {len(hashes_in_body)} 个SHA256哈希值")

                    # 尝试匹配文件名和哈希值
                    # 常见格式：文件名: 哈希值 或 文件名 - 哈希值
                    lines = body.split('\n')
                    for line in lines:
                        # 查找包含哈希值的行
                        hash_match = re.search(f'([^\\s:]+)[\\s:]*({sha256_pattern})', line)
                        if hash_match:
                            filename = hash_match.group(1).strip()
                            file_hash = hash_match.group(2)

                            # 清理文件名，移除可能的标点
                            filename = re.sub(r'^[\\-\\*\\s]+', '', filename)
                            filename = re.sub(r'[\\s:]+$', '', filename)

                            if filename and file_hash:
                                hash_map[filename] = file_hash
                                print(f"    从描述中找到 {filename} 的哈希值: {file_hash[:16]}...")

        except Exception as e:
            print(f"    从API提取哈希值时出错: {e}")

        return hash_map

    def _get_hash_from_asset(self, asset_info: Dict) -> Optional[str]:
        """
        从asset信息中获取哈希值

        Args:
            asset_info: GitHub API返回的asset信息

        Returns:
            SHA256哈希值，如果未找到则返回None
        """
        # 首先检查asset的content_type或name是否包含哈希信息
        filename = asset_info.get('name', '')
        download_url = asset_info.get('browser_download_url', '')

        # 检查文件名是否以.sha256、.sha1、.md5等结尾
        hash_extensions = ['.sha256', '.sha1', '.md5', '.checksum', '.sum']
        for ext in hash_extensions:
            if filename.lower().endswith(ext):
                # 这是一个哈希文件，需要下载并解析
                try:
                    response = self.session.get(download_url, timeout=10)
                    response.raise_for_status()
                    content = response.text.strip()

                    # 解析哈希文件内容
                    # 常见格式: "hash filename" 或 "hash *filename"
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 2:
                                # 第一个部分可能是哈希值
                                hash_value = parts[0]
                                # 检查是否为有效的SHA256哈希值
                                if len(hash_value) == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_value):
                                    # 尝试找到对应的文件名
                                    for part in parts[1:]:
                                        # 移除可能的通配符和路径
                                        base_part = part.lstrip('*').split('/')[-1]
                                        if base_part and not base_part.endswith(tuple(hash_extensions)):
                                            self.hash_map[base_part] = hash_value
                                            print(f"    从哈希文件 {filename} 找到 {base_part} 的哈希值: {hash_value[:16]}...")
                                    return hash_value
                except Exception as e:
                    print(f"    下载/解析哈希文件失败: {e}")

        # 如果没有找到，尝试从hash_map中获取
        if filename in self.hash_map:
            return self.hash_map[filename]

        return None

    def _verify_file_hash(self, filepath: Path, expected_hash: Optional[str], filename: str) -> bool:
        """
        验证文件的哈希值

        Args:
            filepath: 文件路径
            expected_hash: 期望的哈希值
            filename: 文件名

        Returns:
            True if hash matches or no hash to verify, False otherwise
        """
        if not expected_hash:
            print(f"    警告: 未找到 {filename} 的服务器哈希值，跳过校验")
            return True  # 没有期望的哈希值，跳过校验

        if not filepath.exists():
            print(f"    错误: 文件 {filename} 不存在，无法验证哈希值")
            return False

        actual_hash = self._calculate_file_hash(filepath, "sha256")
        if not actual_hash:
            print(f"    错误: 无法计算 {filename} 的哈希值")
            return False

        if actual_hash.lower() == expected_hash.lower():
            print(f"    ✓ 哈希校验成功: {actual_hash[:16]}...")
            self.stats['hash_verified'] += 1
            return True
        else:
            print(f"    ✗ 哈希校验失败!")
            print(f"      期望: {expected_hash}")
            print(f"      实际: {actual_hash}")
            self.stats['hash_failed'] += 1
            return False

    def _extract_repo_info(self, release_url: str) -> Tuple[str, str]:
        """
        从GitHub发布地址提取仓库信息和tag

        Args:
            release_url: GitHub发布地址

        Returns:
            (api_url, tag) API地址和标签
        """
        # 解析URL
        parsed = urlparse(release_url)
        path_parts = parsed.path.strip('/').split('/')

        if len(path_parts) < 5 or path_parts[2] != 'releases' or path_parts[3] != 'tag':
            raise ValueError(f"无效的GitHub发布地址: {release_url}")

        owner = path_parts[0]
        repo = path_parts[1]
        tag = path_parts[4]

        # 构建GitHub API URL
        api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        return api_url, tag

    def _get_assets_info(self, api_url: str) -> List[Dict]:
        """
        从GitHub API获取发布资源信息

        Args:
            api_url: GitHub API地址

        Returns:
            资源信息列表
        """
        try:
            response = self.session.get(api_url)
            response.raise_for_status()
            release_data = response.json()

            assets = release_data.get('assets', [])
            if not assets:
                print(f"警告: 发布版本中没有找到任何文件")
                return []

            # 只过滤GitHub自动生成的Source code压缩包
            filtered_assets = []
            for asset in assets:
                filename = asset['name']
                # 检查是否为GitHub自动生成的Source code压缩包
                # 通常命名为: Source code (zip) 或 Source code (tar.gz)
                if ('Source code' in filename and
                        ('zip' in filename.lower() or 'tar.gz' in filename.lower() or 'tar' in filename.lower())):
                    print(f"跳过GitHub自动生成的Source code文件: {filename}")
                    self.filtered_files.append(filename)
                    self.stats['filtered_files'] += 1
                else:
                    # 尝试获取该文件的哈希值
                    file_hash = self._get_hash_from_asset(asset)
                    if file_hash:
                        self.hash_map[filename] = file_hash
                        print(f"    找到 {filename} 的SHA256哈希值: {file_hash[:16]}...")

                    filtered_assets.append(asset)

            return filtered_assets

        except requests.exceptions.RequestException as e:
            print(f"获取发布信息失败: {e}")
            return []
        except ValueError as e:
            print(f"解析API响应失败: {e}")
            return []

    def _download_file_with_retry(self, download_url: str, filepath: Path, filename: str, force_download: bool = False) -> bool:
        """
        下载单个文件，支持重试机制，显示实时下载速度
        支持哈希值检查，避免重复下载

        Args:
            download_url: 文件下载URL
            filepath: 保存路径
            filename: 文件名
            force_download: 强制重新下载，忽略哈希检查

        Returns:
            True if successful, False otherwise
        """
        # 获取该文件的服务器哈希值
        expected_hash = self.hash_map.get(filename)

        # 检查文件是否存在且哈希值匹配
        if not force_download and filepath.exists():
            if expected_hash:
                # 计算本地文件的哈希值
                local_hash = self._calculate_file_hash(filepath, "sha256")
                if local_hash and local_hash.lower() == expected_hash.lower():
                    print(f"    文件已存在且哈希值匹配，跳过下载")
                    print(f"    哈希值: {local_hash[:16]}...")
                    self.stats['skipped'] += 1
                    self.stats['hash_verified'] += 1
                    return True
                elif local_hash:
                    print(f"    文件存在但哈希值不匹配，需要重新下载")
                    print(f"    本地: {local_hash[:16]}...")
                    print(f"    服务器: {expected_hash[:16]}...")
            else:
                # 没有服务器哈希值，检查文件大小
                try:
                    # 获取远程文件大小
                    response = self.session.head(download_url, timeout=10, allow_redirects=True)
                    if response.status_code == 200:
                        remote_size = int(response.headers.get('content-length', 0))
                        local_size = filepath.stat().st_size

                        if remote_size > 0 and local_size == remote_size:
                            print(f"    文件已存在且大小匹配，跳过下载")
                            self.stats['skipped'] += 1
                            return True
                        elif remote_size > 0:
                            print(f"    文件存在但大小不匹配，需要重新下载")
                            print(f"    本地: {self._format_size(local_size)}，远程: {self._format_size(remote_size)}")
                except Exception as e:
                    print(f"    检查远程文件信息失败: {e}")

        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    print(f"\n  重试 {attempt}/{self.max_retries}...")
                    self.stats['retry_count'] += 1
                    # 指数退避策略
                    time.sleep(min(2 ** attempt, 30))

                print(f"  下载 {filename}...")
                if expected_hash:
                    print(f"    期望哈希值: {expected_hash[:16]}...")

                # 发送请求
                response = self.session.get(download_url, stream=True, timeout=30)
                response.raise_for_status()

                # 获取文件大小
                total_size = int(response.headers.get('content-length', 0))

                # 创建目录
                filepath.parent.mkdir(parents=True, exist_ok=True)

                # 下载文件
                downloaded_size = 0
                start_time = time.time()
                last_update_time = start_time
                last_downloaded_size = 0

                # 临时文件路径，下载完成后再重命名
                temp_filepath = filepath.with_suffix(filepath.suffix + '.download')

                with open(temp_filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)

                            # 每0.5秒更新一次速度显示
                            current_time = time.time()
                            if current_time - last_update_time >= 0.5:
                                elapsed_time = current_time - last_update_time
                                downloaded_chunk = downloaded_size - last_downloaded_size

                                if elapsed_time > 0:
                                    current_speed = downloaded_chunk / elapsed_time
                                else:
                                    current_speed = 0

                                # 计算进度百分比
                                if total_size > 0:
                                    percent = (downloaded_size / total_size) * 100
                                    progress_info = f"    {self._format_size(downloaded_size)} / {self._format_size(total_size)} ({percent:.1f}%) - {self._format_speed(current_speed)}"
                                else:
                                    progress_info = f"    {self._format_size(downloaded_size)} - {self._format_speed(current_speed)}"

                                # 使用回车符回到行首，更新显示
                                sys.stdout.write('\r' + progress_info)
                                sys.stdout.flush()

                                last_update_time = current_time
                                last_downloaded_size = downloaded_size

                # 下载完成，重命名临时文件
                if temp_filepath.exists():
                    # 如果目标文件已存在，先删除
                    if filepath.exists():
                        filepath.unlink()
                    temp_filepath.rename(filepath)

                # 下载完成，打印最终信息
                end_time = time.time()
                total_download_time = end_time - start_time

                # 计算平均下载速度
                if total_download_time > 0:
                    avg_speed = downloaded_size / total_download_time
                else:
                    avg_speed = 0

                # 清除进度行，打印完成信息
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    下载完成: {self._format_size(downloaded_size)}，用时 {self._format_time(total_download_time)}，平均速度 {self._format_speed(avg_speed)}")

                # 验证文件大小
                if total_size > 0 and downloaded_size != total_size:
                    raise IOError(f"文件大小不匹配: 期望 {total_size}, 实际 {downloaded_size}")

                # 验证文件哈希值
                if expected_hash:
                    if self._verify_file_hash(filepath, expected_hash, filename):
                        print(f"    ✓ 文件 {filename} 下载并校验成功")
                    else:
                        print(f"    ✗ 文件 {filename} 哈希校验失败!")
                        # 删除损坏的文件
                        if filepath.exists():
                            filepath.unlink()
                        raise ValueError(f"文件哈希校验失败: {filename}")
                else:
                    print(f"    ⚠ 文件 {filename} 下载完成，但未进行哈希校验")

                self.stats['total_size'] += downloaded_size
                return True

            except requests.exceptions.RequestException as e:
                # 清除进度显示
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    失败: {e}")
                # 删除临时文件
                if 'temp_filepath' in locals() and temp_filepath.exists():
                    temp_filepath.unlink()
                # 如果是最后一次尝试，记录失败文件
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })
            except (IOError, ValueError) as e:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    错误: {e}")
                if 'temp_filepath' in locals() and temp_filepath.exists():
                    temp_filepath.unlink()
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })
            except KeyboardInterrupt:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print("    下载被用户中断")
                if 'temp_filepath' in locals() and temp_filepath.exists():
                    temp_filepath.unlink()
                raise
            except Exception as e:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    未知错误: {e}")
                if 'temp_filepath' in locals() and temp_filepath.exists():
                    temp_filepath.unlink()
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })

        return False

    def download_release(self, release_url: str, target_dir: str, force_download: bool = False) -> bool:
        """
        下载指定发布版本的所有文件（只过滤GitHub自动生成的Source code）

        Args:
            release_url: GitHub发布地址
            target_dir: 目标目录
            force_download: 强制重新下载所有文件

        Returns:
            True if all files downloaded successfully, False otherwise
        """
        print(f"开始下载: {release_url}")
        print(f"目标目录: {target_dir}")
        print(f"跳过GitHub自动生成的Source code文件: 是")
        print(f"强制重新下载: {'是' if force_download else '否'}")
        print("-" * 50)

        # 记录开始时间
        self.stats['start_time'] = time.time()

        try:
            # 提取仓库信息
            api_url, tag = self._extract_repo_info(release_url)

            # 从release页面提取哈希值
            print("从release页面提取哈希值...")
            page_hashes = self._extract_hashes_from_release_page(release_url)
            self.hash_map.update(page_hashes)

            # 从API描述中提取哈希值
            print("从API描述提取哈希值...")
            api_hashes = self._extract_hashes_from_api(api_url)
            self.hash_map.update(api_hashes)

            # 获取并过滤资源信息
            assets = self._get_assets_info(api_url)
            self.stats['total_files'] = self.stats['filtered_files'] + len(assets)
            self.stats['available_files'] = len(assets)

            if not assets:
                print("没有找到可下载的文件")
                return True

            # 创建目标目录
            target_path = Path(target_dir)
            target_path.mkdir(parents=True, exist_ok=True)

            # 下载每个文件
            for i, asset in enumerate(assets, 1):
                filename = asset['name']
                download_url = asset['browser_download_url']
                filepath = target_path / filename

                print(f"[{i}/{len(assets)}] {filename}")

                success = self._download_file_with_retry(download_url, filepath, filename, force_download)

                if success:
                    self.stats['successful'] += 1
                else:
                    self.stats['failed'] += 1

            return self.stats['failed'] == 0 and self.stats['hash_failed'] == 0

        except KeyboardInterrupt:
            print("\n下载被用户中断")
            return False
        except Exception as e:
            print(f"下载过程中发生错误: {e}")
            return False

        finally:
            # 记录结束时间
            self.stats['end_time'] = time.time()

    def print_statistics(self):
        """打印下载统计信息"""
        print("\n" + "=" * 60)
        print("下载统计信息")
        print("=" * 60)

        total_time = self.stats['end_time'] - self.stats['start_time']

        print(f"总文件数: {self.stats['total_files']}")
        print(f"过滤的Source code文件: {self.stats['filtered_files']}")
        print(f"可下载文件数: {self.stats['available_files']}")
        print(f"成功下载: {self.stats['successful']}")
        print(f"失败下载: {self.stats['failed']}")
        print(f"跳过下载（哈希值匹配）: {self.stats['skipped']}")
        print(f"哈希校验成功: {self.stats['hash_verified']}")
        print(f"哈希校验失败: {self.stats['hash_failed']}")
        print(f"重试次数: {self.stats['retry_count']}")
        print(f"总下载大小: {self._format_size(self.stats['total_size'])}")
        print(f"总耗时: {self._format_time(total_time)}")

        if total_time > 0 and (self.stats['successful'] + self.stats['skipped']) > 0:
            avg_speed = self.stats['total_size'] / total_time
            print(f"平均下载速度: {self._format_speed(avg_speed)}")

        if self.filtered_files:
            print(f"\n跳过的GitHub自动生成的Source code文件 ({len(self.filtered_files)}个):")
            for filename in self.filtered_files:
                print(f"  - {filename}")

        if self.failed_files:
            print(f"\n失败的文件 ({len(self.failed_files)}个):")
            for failed in self.failed_files:
                print(f"  - {failed['filename']}: {failed['error']}")

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='从GitHub Releases下载所有文件（跳过GitHub自动生成的Source code）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s https://github.com/owner/repo/releases/tag/v1.0 ./downloads
  %(prog)s --max-retries 5 https://github.com/owner/repo/releases/tag/v2.0 ./my_files
  %(prog)s --force https://github.com/owner/repo/releases/tag/v1.0 ./downloads
        """
    )

    parser.add_argument(
        'release_url',
        help='GitHub发布地址 (例如: https://github.com/owner/repo/releases/tag/v1.0)'
    )

    parser.add_argument(
        'target_dir',
        help='下载目标目录'
    )

    parser.add_argument(
        '--max-retries',
        type=int,
        default=10,
        help='最大重试次数 (默认: 10)'
    )

    parser.add_argument(
        '--include-source-code',
        action='store_true',
        help='包含GitHub自动生成的Source code文件（默认跳过）'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='强制重新下载所有文件，忽略哈希值检查'
    )

    parser.add_argument(
        '--skip-hash-check',
        action='store_true',
        help='跳过哈希值校验（仅用于测试或当哈希值不可用时）'
    )

    args = parser.parse_args()

    # 创建下载器
    downloader = GitHubReleaseDownloader(max_retries=args.max_retries)

    # 如果用户指定包含Source code文件，则修改过滤规则
    if args.include_source_code:
        # 重写_get_assets_info方法，不进行过滤
        def get_all_assets(api_url):
            try:
                response = downloader.session.get(api_url)
                response.raise_for_status()
                release_data = response.json()
                assets = release_data.get('assets', [])
                downloader.stats['available_files'] = len(assets)
                downloader.stats['total_files'] = len(assets)
                return assets
            except requests.exceptions.RequestException as e:
                print(f"获取发布信息失败: {e}")
                return []

        downloader._get_assets_info = get_all_assets
        print("注意: 已启用GitHub自动生成的Source code文件下载")

    # 如果用户指定跳过哈希检查，禁用哈希校验
    if args.skip_hash_check:
        original_verify = downloader._verify_file_hash
        downloader._verify_file_hash = lambda *args, **kwargs: True
        print("注意: 已禁用哈希校验")

    # 执行下载
    success = downloader.download_release(args.release_url, args.target_dir, args.force)

    # 打印统计信息
    downloader.print_statistics()

    # 根据结果返回适当的退出码
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()