#!/usr/bin/env python3
"""
GitHub Releases下载脚本
支持重试机制、下载统计信息，显示实时下载速度
只过滤GitHub自动生成的Source code压缩包
"""

import os
import sys
import time
import argparse
import requests
from pathlib import Path
from typing import List, Dict, Tuple
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
            'total_size': 0,
            'retry_count': 0,
            'start_time': None,
            'end_time': None
        }

        # 失败文件列表
        self.failed_files = []

        # 过滤的文件列表
        self.filtered_files = []

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
                    filtered_assets.append(asset)

            return filtered_assets

        except requests.exceptions.RequestException as e:
            print(f"获取发布信息失败: {e}")
            return []
        except ValueError as e:
            print(f"解析API响应失败: {e}")
            return []

    def _download_file_with_retry(self, download_url: str, filepath: Path, filename: str) -> bool:
        """
        下载单个文件，支持重试机制，显示实时下载速度

        Args:
            download_url: 文件下载URL
            filepath: 保存路径
            filename: 文件名

        Returns:
            True if successful, False otherwise
        """
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    print(f"\n  重试 {attempt}/{self.max_retries}...")
                    self.stats['retry_count'] += 1
                    # 指数退避策略
                    time.sleep(min(2 ** attempt, 30))

                print(f"  下载 {filename}...")

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

                with open(filepath, 'wb') as f:
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

                self.stats['total_size'] += downloaded_size
                return True

            except requests.exceptions.RequestException as e:
                # 清除进度显示
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    失败: {e}")
                # 如果是最后一次尝试，记录失败文件
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })
            except IOError as e:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    IO错误: {e}")
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })
            except KeyboardInterrupt:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print("    下载被用户中断")
                raise
            except Exception as e:
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"    未知错误: {e}")
                if attempt == self.max_retries - 1:
                    self.failed_files.append({
                        'filename': filename,
                        'url': download_url,
                        'error': str(e)
                    })

        return False

    def download_release(self, release_url: str, target_dir: str) -> bool:
        """
        下载指定发布版本的所有文件（只过滤GitHub自动生成的Source code）

        Args:
            release_url: GitHub发布地址
            target_dir: 目标目录

        Returns:
            True if all files downloaded successfully, False otherwise
        """
        print(f"开始下载: {release_url}")
        print(f"目标目录: {target_dir}")
        print(f"跳过GitHub自动生成的Source code文件: 是")
        print("-" * 50)

        # 记录开始时间
        self.stats['start_time'] = time.time()

        try:
            # 提取仓库信息
            api_url, tag = self._extract_repo_info(release_url)

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

                success = self._download_file_with_retry(download_url, filepath, filename)

                if success:
                    self.stats['successful'] += 1
                else:
                    self.stats['failed'] += 1

            return self.stats['failed'] == 0

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
        print(f"重试次数: {self.stats['retry_count']}")
        print(f"总下载大小: {self._format_size(self.stats['total_size'])}")
        print(f"总耗时: {self._format_time(total_time)}")

        if total_time > 0 and self.stats['successful'] > 0:
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

    # 执行下载
    success = downloader.download_release(args.release_url, args.target_dir)

    # 打印统计信息
    downloader.print_statistics()

    # 根据结果返回适当的退出码
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()