#!/usr/bin/env python3
"""
WEB API服务器 - Docker Compose服务管理中心
增强版本：修复分布式锁问题，增强连接检查
支持多种压缩格式：.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tbz, .tbz2, .tar.xz, .txz
"""


import sys
import os
import argparse
import json
from model.constants import *
from api.web_api_server import adjust_timeout_config,WebAPIServer


def _resolve_runtime_pod_id(config: dict, cli_pod_id: str = None) -> str:
    if cli_pod_id:
        return cli_pod_id
    for env_key in ('POD_NAME', 'HOSTNAME'):
        env_value = os.environ.get(env_key)
        if env_value:
            return env_value
    return config.get('pod_id', 'webapi-server')

# ===================== 主函数 =====================

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WEB API服务器 - Docker Compose服务管理中心')
    parser.add_argument('-c', '--config', help='配置文件路径')
    parser.add_argument('--host', help='监听主机')
    parser.add_argument('--port', type=int, help='监听端口')
    parser.add_argument('--debug', action='store_true', help='调试模式')
    parser.add_argument('--pod-id', help='POD标识符')
    parser.add_argument('--skip-connection-check', action='store_true',
                        help='跳过连接检查（用于测试）')
    parser.add_argument('--timeout', type=int, help='全局超时时间（秒）')
    parser.add_argument('--deploy-timeout', type=int, help='部署超时时间（秒）')

    args = parser.parse_args()

    config = DEFAULT_CONFIG.copy()

    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            sys.exit(1)

    if args.host:
        config['host'] = args.host
    if args.port:
        config['port'] = args.port
    if args.debug:
        config['debug'] = args.debug
    config['pod_id'] = _resolve_runtime_pod_id(config, args.pod_id)
    if args.skip_connection_check:
        config['skip_connection_check'] = True

    # 调整超时配置
    config = adjust_timeout_config(config)

    # 命令行参数覆盖配置
    if args.timeout:
        config['agent_api_timeouts']['default'] = (10, args.timeout)
        config['agent_api_timeouts']['proxy'] = (10, args.timeout)

    if args.deploy_timeout:
        deploy_read_timeout = int(args.deploy_timeout)
        deploy_timeout_tuple = (10, deploy_read_timeout)
        for key in ('deploy_create', 'deploy_start', 'deploy_stop', 'deploy_delete', 'undeploy', 'file_upload'):
            config['agent_api_timeouts'][key] = deploy_timeout_tuple
        config['agent_api_timeouts']['deploy_start_grace_sec'] = deploy_read_timeout

    # 打印启动信息
    print("=" * 60)
    print("WEB API 服务器 - Docker Compose服务管理中心")
    print(f"版本: 2.0.0 (增强连接检查和分布式锁修复版)")
    print(f"POD ID: {config['pod_id']}")
    print(f"数据库: {config['database'].get('type', 'sqlite').upper()}")
    print(f"Redis: {'启用' if config.get('redis_enabled', True) else '禁用'}")
    print(f"支持的压缩格式: {', '.join(config.get('supported_formats', SUPPORTED_FORMATS))}")
    print(f"监听地址: {config['host']}:{config['port']}")
    print("\n超时配置:")
    for key, value in config['agent_api_timeouts'].items():
        print(f"  {key}: {value}")
    print("=" * 60)

    try:
        server = WebAPIServer(config)
        server.run()
    except ConnectionError as e:
        print(f"\n启动失败: {e}")
        print("请检查配置文件和网络连接后重试")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n正在关闭服务器...")
        if 'server' in locals():
            server.shutdown()
        sys.exit(0)
    except Exception as e:
        print(f"\n服务器启动失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
