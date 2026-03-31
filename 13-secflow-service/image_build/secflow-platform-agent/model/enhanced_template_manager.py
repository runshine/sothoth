import logging
import tarfile
import tempfile
import hashlib
from contextlib import ExitStack


from .db import DatabaseManager
from .constants import COMPRESSION_EXT_MAPPING, SUPPORTED_FORMATS
from .redis_manager import RedisManager
import io
import zipfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
import json
import yaml


# ===================== Docker Compose 解析器 =====================

class DockerComposeParser:
    """Docker Compose YAML 解析器"""

    def parse_compose_file(self, yaml_content: str) -> Tuple[bool, Dict, str]:
        """
        解析 docker-compose YAML 内容

        Args:
            yaml_content: YAML 文件内容

        Returns:
            (success, parsed_data, error_message)
        """
        try:
            compose_data = yaml.safe_load(yaml_content)

            if not isinstance(compose_data, dict):
                return False, {}, "YAML must be a dictionary"

            parsed = {
                'version': compose_data.get('version', '3.0'),
                'services': self._parse_services(compose_data.get('services', {})),
                'networks': self._parse_networks(compose_data.get('networks', {})),
                'volumes': self._parse_volumes(compose_data.get('volumes', {})),
                'configs': self._parse_configs(compose_data.get('configs', {})),
                'secrets': self._parse_secrets(compose_data.get('secrets', {}))
            }

            return True, parsed, ""

        except Exception as e:
            return False, {}, str(e)

    def _parse_services(self, services: Dict) -> Dict:
        """解析 services 部分，提取关键字段"""
        parsed_services = {}

        for service_name, config in services.items():
            if not isinstance(config, dict):
                continue

            parsed_service = {
                'image': config.get('image', ''),
                'ports': self._normalize_ports(config.get('ports', [])),
                'environment': self._normalize_environment(config.get('environment', {})),
                'volumes': self._normalize_volumes(config.get('volumes', [])),
                'networks': config.get('networks', []),
                'depends_on': self._normalize_depends_on(config.get('depends_on', [])),
                'restart': config.get('restart', ''),
                'container_name': config.get('container_name', ''),
                'build': config.get('build', {}),
                'labels': config.get('labels', {}),
                'healthcheck': config.get('healthcheck', {}),
                'deploy': config.get('deploy', {})
            }

            # 移除空值
            parsed_service = {k: v for k, v in parsed_service.items() if v}
            parsed_services[service_name] = parsed_service

        return parsed_services

    def _normalize_ports(self, ports) -> List[Dict]:
        """规范化端口配置"""
        normalized = []
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, str):
                    # "80:8080" 或 "80:8080/tcp"
                    parts = port.split(':')
                    if len(parts) >= 2:
                        normalized.append({
                            'published': parts[0],
                            'target': parts[-1].split('/')[0],
                            'protocol': 'tcp' if '/' not in parts[-1] else parts[-1].split('/')[1]
                        })
                elif isinstance(port, dict):
                    normalized.append({
                        'published': str(port.get('published', '')),
                        'target': str(port.get('target', '')),
                        'protocol': port.get('protocol', 'tcp')
                    })
        return normalized

    def _normalize_environment(self, env) -> Dict:
        """规范化环境变量"""
        if isinstance(env, dict):
            return env
        elif isinstance(env, list):
            result = {}
            for item in env:
                if isinstance(item, str) and '=' in item:
                    key, value = item.split('=', 1)
                    result[key] = value
            return result
        return {}

    def _normalize_volumes(self, volumes) -> List[Dict]:
        """规范化卷挂载"""
        normalized = []
        if isinstance(volumes, list):
            for vol in volumes:
                if isinstance(vol, str):
                    # "/host/path:/container/path" or "volume_name:/container/path"
                    parts = vol.split(':')
                    if len(parts) >= 2:
                        vol_info = {
                            'source': parts[0],
                            'target': parts[1],
                            'type': 'bind' if parts[0].startswith('/') or parts[0].startswith('./') else 'volume'
                        }
                        if len(parts) >= 3:
                            vol_info['mode'] = parts[2]
                        normalized.append(vol_info)
                elif isinstance(vol, dict):
                    normalized.append({
                        'source': vol.get('source', ''),
                        'target': vol.get('target', ''),
                        'type': vol.get('type', 'volume'),
                        'read_only': vol.get('read_only', False)
                    })
        return normalized

    def _normalize_depends_on(self, depends) -> List[str]:
        """规范化依赖关系"""
        if isinstance(depends, list):
            return depends
        elif isinstance(depends, dict):
            return list(depends.keys())
        return []

    def _parse_networks(self, networks) -> Dict:
        """解析 networks 定义"""
        if not networks:
            return {}

        parsed = {}
        for name, config in networks.items():
            if config is None:
                parsed[name] = {'external': False}
            elif isinstance(config, dict):
                parsed[name] = config
            elif isinstance(config, bool):
                parsed[name] = {'external': config}
            else:
                parsed[name] = {'external': False}
        return parsed

    def _parse_volumes(self, volumes) -> Dict:
        """解析 volumes 定义"""
        if not volumes:
            return {}

        parsed = {}
        for name, config in volumes.items():
            if config is None:
                parsed[name] = {}
            elif isinstance(config, dict):
                parsed[name] = config
            else:
                parsed[name] = {}
        return parsed

    def _parse_configs(self, configs) -> Dict:
        """解析 configs 定义 (v3.3+)"""
        if not configs:
            return {}

        parsed = {}
        for name, config in configs.items():
            if isinstance(config, dict):
                parsed[name] = config
        return parsed

    def _parse_secrets(self, secrets) -> Dict:
        """解析 secrets 定义 (v3.1+)"""
        if not secrets:
            return {}

        parsed = {}
        for name, secret in secrets.items():
            if isinstance(secret, dict):
                parsed[name] = secret
        return parsed
# ===================== 模板管理器（完整增强版，支持多种压缩格式） =====================

class EnhancedTemplateManager:
    """完整增强版模板管理器，支持多种压缩格式"""

    def __init__(self, templates_root: str, db_manager: DatabaseManager,
                 supported_formats: List[str] = None,
                 redis_manager: Optional[RedisManager] = None):
        self.templates_root = Path(templates_root)
        self.db = db_manager
        self.redis_manager = redis_manager
        self.templates_root.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # 设置支持的格式
        self.supported_formats = supported_formats or SUPPORTED_FORMATS
        self.compression_map = COMPRESSION_EXT_MAPPING

        self.logger.info(f"模板管理器初始化，支持格式: {', '.join(self.supported_formats)}")

    def _template_lock_names(self, names: List[str]) -> List[str]:
        return sorted({str(name or '').strip() for name in names if str(name or '').strip()})

    def _with_template_locks(self, names: List[str], callback, timeout: int = 120):
        lock_names = self._template_lock_names(names)
        if not lock_names or not self.redis_manager:
            return callback()

        with ExitStack() as stack:
            for name in lock_names:
                lock = stack.enter_context(self.redis_manager.get_lock(f"template_write:{name}", timeout=timeout))
                if not lock.is_acquired():
                    return False, f"模板 '{name}' 正在被其他实例修改，请稍后重试"
            return callback()

    def _normalize_web_port_presets(self, presets: Any) -> List[Dict[str, Any]]:
        """规范化模板预制Web端口配置。"""
        if not presets:
            return []
        normalized: List[Dict[str, Any]] = []
        if not isinstance(presets, list):
            return normalized
        for item in presets:
            if not isinstance(item, dict):
                continue
            try:
                port = int(item.get('port'))
            except Exception:
                continue
            if port <= 0 or port > 65535:
                continue

            backend_protocol = str(
                item.get('backend_protocol') or item.get('protocol') or 'http'
            ).strip().lower()
            if backend_protocol not in ('http', 'https'):
                backend_protocol = 'http'

            ingress_tls_enabled = bool(
                item.get('ingress_tls_enabled',
                         item.get('tls_enabled', True))
            )

            entry = {
                'port': port,
                'protocol': backend_protocol,
                'backend_protocol': backend_protocol,
                'name': str(item.get('name') or '').strip()[:64],
                'description': str(item.get('description') or '').strip()[:256],
                'path': str(item.get('path') or '/').strip() or '/',
                'websocket_enabled': bool(item.get('websocket_enabled', True)),
                'tls_enabled': ingress_tls_enabled,
                'ingress_tls_enabled': ingress_tls_enabled
            }
            normalized.append(entry)

        dedup: Dict[str, Dict[str, Any]] = {}
        for p in normalized:
            dedup[f"{p['port']}:{p['backend_protocol']}:{int(bool(p['ingress_tls_enabled']))}:{p['path']}"] = p
        return list(dedup.values())[:32]

    def _normalize_llm_provider_mix_request(self, binding: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(binding, dict):
            return None
        raw_provider_keys = binding.get('provider_keys')
        if not isinstance(raw_provider_keys, list):
            raw_provider_keys = []
        provider_keys: List[str] = []
        seen = set()
        for item in raw_provider_keys:
            text = str(item or '').strip()
            if not text or text in seen:
                continue
            seen.add(text)
            provider_keys.append(text)

        raw_targets = binding.get('target_services', '*')
        if raw_targets == '*' or raw_targets is None:
            target_services: Union[str, List[str]] = '*'
        elif isinstance(raw_targets, list):
            target_seen = set()
            target_services = []
            for item in raw_targets:
                text = str(item or '').strip()
                if not text or text in target_seen:
                    continue
                target_seen.add(text)
                target_services.append(text)
        else:
            target_services = '*'

        if not provider_keys:
            return None
        return {
            'provider_keys': provider_keys,
            'target_services': target_services,
            'updated_at': datetime.now().isoformat(),
        }

    @staticmethod
    def _normalize_template_tags(tags: Any) -> List[str]:
        if isinstance(tags, str):
            try:
                parsed = json.loads(tags)
                if isinstance(parsed, list):
                    tags = parsed
                else:
                    tags = [item.strip() for item in tags.split(',')]
            except Exception:
                tags = [item.strip() for item in tags.split(',')]
        elif not isinstance(tags, (list, tuple, set)):
            tags = []

        normalized: List[str] = []
        for item in tags:
            value = str(item or '').strip()
            if value and value not in normalized:
                normalized.append(value)
        return normalized[:64]

    @staticmethod
    def _internal_meta_dir_name() -> str:
        return '.template-meta'

    def _internal_meta_dir(self, template_dir: Path) -> Path:
        return template_dir / self._internal_meta_dir_name()

    def _original_compose_backup_relative_path(self) -> str:
        return f"{self._internal_meta_dir_name()}/original-compose.yaml"

    def _is_internal_template_path(self, relative_path: Path) -> bool:
        return bool(relative_path.parts) and relative_path.parts[0] == self._internal_meta_dir_name()

    def _load_template_metadata_dict(self, template: Dict[str, Any]) -> Dict[str, Any]:
        metadata = template.get('metadata') or {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        return metadata

    def _update_template_metadata(self, template_id: int, metadata: Dict[str, Any]):
        table_name = self.db.get_table_name('service_templates')
        metadata_json = json.dumps(metadata, ensure_ascii=False)
        if self.db.db_type == 'mysql':
            self.db.execute_query(
                f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE id = %s",
                (metadata_json, template_id)
            )
        else:
            self.db.execute_query(
                f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE id = ?",
                (metadata_json, template_id)
            )

    def _write_original_compose_backup(
        self,
        template_dir: Path,
        compose_content: str,
        source_type: str,
        main_compose_path: str,
    ) -> Dict[str, Any]:
        meta_dir = self._internal_meta_dir(template_dir)
        meta_dir.mkdir(parents=True, exist_ok=True)
        backup_relative_path = self._original_compose_backup_relative_path()
        backup_path = template_dir / backup_relative_path
        backup_path.write_text(compose_content, encoding='utf-8')
        return {
            'file_path': backup_relative_path,
            'source_type': source_type,
            'main_compose_path': main_compose_path,
            'created_at': datetime.now().isoformat(),
        }

    def _get_main_compose_relative_path(self, template: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        main_yaml = str(metadata.get('main_yaml_file') or '').strip()
        if main_yaml:
            return main_yaml
        file_path = Path(str(template.get('file_path') or ''))
        return file_path.name

    def _ensure_original_compose_backup(
        self,
        template_id: int,
        template: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], str]:
        backup_info = metadata.get('original_compose_backup') if isinstance(metadata.get('original_compose_backup'), dict) else None
        template_dir = self.templates_root / str(template.get('name') or '')
        if not template_dir.exists():
            raise ValueError(f"模板目录不存在: {template_dir}")

        if backup_info:
            backup_path = template_dir / str(backup_info.get('file_path') or '')
            if backup_path.exists():
                return backup_info, backup_path.read_text(encoding='utf-8')

        main_compose_path = self._get_main_compose_relative_path(template, metadata)
        current_compose_path = template_dir / main_compose_path
        if not current_compose_path.exists():
            raise ValueError(f"模板主 compose 不存在: {main_compose_path}")
        compose_content = current_compose_path.read_text(encoding='utf-8')
        backup_info = self._write_original_compose_backup(
            template_dir=template_dir,
            compose_content=compose_content,
            source_type=str(template.get('type') or 'yaml'),
            main_compose_path=main_compose_path,
        )
        metadata['original_compose_backup'] = backup_info
        self._update_template_metadata(int(template_id), metadata)
        return backup_info, compose_content

    @staticmethod
    def _normalize_compose_environment(environment: Any) -> Dict[str, str]:
        if isinstance(environment, dict):
            return {str(k): '' if v is None else str(v) for k, v in environment.items()}
        if isinstance(environment, list):
            result: Dict[str, str] = {}
            for item in environment:
                if not isinstance(item, str) or '=' not in item:
                    continue
                key, value = item.split('=', 1)
                result[str(key)] = value
            return result
        return {}

    @staticmethod
    def _normalize_service_configs(configs: Any) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        if isinstance(configs, list):
            for item in configs:
                if isinstance(item, str):
                    source = item.strip()
                    if source:
                        normalized.append({'source': source})
                    continue
                if not isinstance(item, dict):
                    continue
                source = str(item.get('source') or item.get('config') or '').strip()
                if not source:
                    continue
                record: Dict[str, Any] = {'source': source}
                target = str(item.get('target') or '').strip()
                if target:
                    record['target'] = target
                if 'mode' in item:
                    record['mode'] = item.get('mode')
                if 'uid' in item:
                    record['uid'] = item.get('uid')
                if 'gid' in item:
                    record['gid'] = item.get('gid')
                normalized.append(record)
        return normalized

    @staticmethod
    def _sanitize_config_name(value: str) -> str:
        normalized = ''.join(ch if str(ch).isalnum() else '_' for ch in str(value or '').strip().lower())
        normalized = normalized.strip('_')
        if not normalized:
            normalized = 'llm_file'
        return normalized[:48]

    def _apply_llm_provider_binding_to_yaml(
        self,
        yaml_content: str,
        binding: Optional[Dict[str, Any]],
        template_dir: Optional[Path] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        if not binding or not isinstance(binding, dict):
            return yaml_content, {'applied': False, 'provider_keys': [], 'target_services': [], 'mapped_env_keys': [], 'mapped_file_paths': []}

        merged_env = binding.get('merged_env') if isinstance(binding.get('merged_env'), dict) else {}
        merged_files = binding.get('merged_files') if isinstance(binding.get('merged_files'), list) else []
        provider_keys = [str(item) for item in (binding.get('provider_keys') or []) if str(item).strip()]
        target_services = binding.get('target_services', '*')
        if (not merged_env and not merged_files) or not provider_keys:
            return yaml_content, {'applied': False, 'provider_keys': provider_keys, 'target_services': [], 'mapped_env_keys': sorted(merged_env.keys()), 'mapped_file_paths': []}

        compose_data = yaml.safe_load(yaml_content) or {}
        if not isinstance(compose_data, dict):
            raise ValueError('compose YAML 解析结果不是对象')
        services = compose_data.get('services')
        if not isinstance(services, dict) or not services:
            raise ValueError('compose YAML 缺少 services 定义')

        available_services = [str(name) for name in services.keys()]
        if target_services == '*' or target_services is None:
            selected_services = available_services
        else:
            selected_services = [str(item) for item in (target_services or []) if str(item).strip()]
            missing = [name for name in selected_services if name not in services]
            if missing:
                raise ValueError(f"LLM Provider 目标服务不存在: {', '.join(missing)}")

        mapped_file_paths: List[str] = []
        llm_service_configs: Dict[str, Dict[str, Any]] = {}
        if merged_files:
            if template_dir is None:
                raise ValueError('模板目录不存在，无法写入 LLM Provider 文件')
            llm_files_dir = template_dir / '.llm-provider-files'
            if llm_files_dir.exists():
                shutil.rmtree(llm_files_dir, ignore_errors=True)
            llm_files_dir.mkdir(parents=True, exist_ok=True)
            compose_configs = compose_data.get('configs')
            if not isinstance(compose_configs, dict):
                compose_configs = {}
                compose_data['configs'] = compose_configs

            for idx, raw_item in enumerate(merged_files):
                if not isinstance(raw_item, dict):
                    continue
                file_path = str(raw_item.get('path') or '').strip()
                content = raw_item.get('content')
                if not file_path or not isinstance(content, str):
                    continue
                file_name_token = hashlib.sha1(file_path.encode('utf-8')).hexdigest()[:12]
                file_ext = Path(file_path).suffix or '.txt'
                relative_file_path = Path('.llm-provider-files') / f"{idx + 1:02d}_{file_name_token}{file_ext}"
                absolute_file_path = template_dir / relative_file_path
                absolute_file_path.parent.mkdir(parents=True, exist_ok=True)
                absolute_file_path.write_text(content, encoding='utf-8')

                config_name = f"llm_file_{self._sanitize_config_name(file_name_token)}"
                compose_configs[config_name] = {'file': relative_file_path.as_posix()}
                llm_service_configs[file_path] = {
                    'source': config_name,
                    'target': file_path,
                }
                mapped_file_paths.append(file_path)

        for service_name in selected_services:
            service_cfg = services.get(service_name)
            if not isinstance(service_cfg, dict):
                continue
            env_map = self._normalize_compose_environment(service_cfg.get('environment'))
            env_map.update({str(k): '' if v is None else str(v) for k, v in merged_env.items()})
            service_cfg['environment'] = env_map
            if llm_service_configs:
                existing_configs = self._normalize_service_configs(service_cfg.get('configs'))
                target_path_set = set(llm_service_configs.keys())
                cleaned_configs = [
                    item for item in existing_configs
                    if str(item.get('target') or '').strip() not in target_path_set
                ]
                cleaned_configs.extend(llm_service_configs.values())
                service_cfg['configs'] = cleaned_configs

        updated_yaml = yaml.safe_dump(compose_data, sort_keys=False, allow_unicode=True)
        return updated_yaml, {
            'applied': True,
            'provider_keys': provider_keys,
            'target_services': selected_services,
            'mapped_env_keys': sorted(merged_env.keys()),
            'mapped_file_paths': sorted(set(mapped_file_paths)),
        }

    def _rebuild_template_archive(self, template: Dict[str, Any], template_dir: Path):
        archive_path = Path(str(template.get('file_path') or ''))
        if not archive_path.exists():
            raise ValueError(f"原始压缩文件不存在: {archive_path}")

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in template_dir.rglob('*'):
                if not file_path.is_file():
                    continue
                rel_path = file_path.relative_to(template_dir)
                if self._is_internal_template_path(rel_path):
                    continue
                if archive_path.resolve() == file_path.resolve():
                    continue
                zipf.write(file_path, rel_path)
        archive_path.write_bytes(buffer.getvalue())

    def _append_llm_mix_history(self, metadata: Dict[str, Any], entry: Dict[str, Any]):
        history = metadata.get('llm_mix_history')
        if not isinstance(history, list):
            history = []
        history.append(entry)
        metadata['llm_mix_history'] = history[-20:]

    def regenerate_template_with_llm_providers(
        self,
        template_id: int,
        binding: Dict[str, Any],
        generated_by: str = 'system',
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        template = self.get_template_by_id(template_id)
        if not template:
            return False, '模板不存在', None

        metadata = self._load_template_metadata_dict(template)
        normalized = self._normalize_llm_provider_mix_request(binding)
        if not normalized:
            return False, 'provider_keys 不能为空', None

        try:
            backup_info, original_compose = self._ensure_original_compose_backup(template_id, template, metadata)
            resolved_binding = {
                'provider_keys': list(binding.get('provider_keys') or []),
                'target_services': normalized.get('target_services', '*'),
                'merged_env': dict(binding.get('merged_env') or {}),
                'merged_files': list(binding.get('merged_files') or []),
                'provider_snapshots': list(binding.get('provider_snapshots') or []),
                'mapped_env_keys': list(binding.get('mapped_env_keys') or []),
                'mapped_file_paths': list(binding.get('mapped_file_paths') or []),
            }
            template_dir = self.templates_root / str(template.get('name') or '')
            updated_yaml, injection = self._apply_llm_provider_binding_to_yaml(
                original_compose,
                resolved_binding,
                template_dir=template_dir,
            )

            main_compose_path = str((backup_info or {}).get('main_compose_path') or self._get_main_compose_relative_path(template, metadata))
            compose_path = template_dir / main_compose_path
            compose_path.parent.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(updated_yaml, encoding='utf-8')

            if str(template.get('type') or '') == 'archive':
                self._rebuild_template_archive(template, template_dir)

            mix_state = {
                'provider_keys': list(resolved_binding.get('provider_keys') or []),
                'provider_snapshots': list(resolved_binding.get('provider_snapshots') or []),
                'mapped_env_keys': list(injection.get('mapped_env_keys') or []),
                'mapped_file_paths': list(injection.get('mapped_file_paths') or []),
                'target_services': resolved_binding.get('target_services', '*'),
                'generated_at': datetime.now().isoformat(),
                'generated_by': generated_by,
            }
            metadata['llm_mix_state'] = mix_state
            self._append_llm_mix_history(metadata, dict(mix_state))
            self._update_template_metadata(template_id, metadata)
            if template.get('name'):
                self.parse_template_compose(str(template.get('name')))
            return True, '模板已重新生成', self.get_template_by_id(template_id)
        except Exception as e:
            self.logger.error(f"重新生成模板失败: {str(e)}", exc_info=True)
            return False, f"重新生成模板失败: {str(e)}", None

    def restore_template_original_compose(
        self,
        template_id: int,
        restored_by: str = 'system',
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        template = self.get_template_by_id(template_id)
        if not template:
            return False, '模板不存在', None

        metadata = self._load_template_metadata_dict(template)
        try:
            backup_info, original_compose = self._ensure_original_compose_backup(template_id, template, metadata)
            template_dir = self.templates_root / str(template.get('name') or '')
            llm_files_dir = template_dir / '.llm-provider-files'
            if llm_files_dir.exists():
                shutil.rmtree(llm_files_dir, ignore_errors=True)
            main_compose_path = str((backup_info or {}).get('main_compose_path') or self._get_main_compose_relative_path(template, metadata))
            compose_path = template_dir / main_compose_path
            compose_path.parent.mkdir(parents=True, exist_ok=True)
            compose_path.write_text(original_compose, encoding='utf-8')
            if str(template.get('type') or '') == 'archive':
                self._rebuild_template_archive(template, template_dir)
            metadata.pop('llm_mix_state', None)
            metadata['llm_mix_restored_at'] = datetime.now().isoformat()
            metadata['llm_mix_restored_by'] = restored_by
            self._update_template_metadata(template_id, metadata)
            if template.get('name'):
                self.parse_template_compose(str(template.get('name')))
            return True, '模板已恢复为原始内容', self.get_template_by_id(template_id)
        except Exception as e:
            self.logger.error(f"恢复原始模板失败: {str(e)}", exc_info=True)
            return False, f"恢复原始模板失败: {str(e)}", None

    def get_template_compose_source(self, template_id: int) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        template = self.get_template_by_id(template_id)
        if not template:
            return False, '模板不存在', None
        metadata = self._load_template_metadata_dict(template)
        backup_info = metadata.get('original_compose_backup') if isinstance(metadata.get('original_compose_backup'), dict) else None
        llm_mix_state = metadata.get('llm_mix_state') if isinstance(metadata.get('llm_mix_state'), dict) else None
        llm_mix_history = metadata.get('llm_mix_history') if isinstance(metadata.get('llm_mix_history'), list) else []
        return True, 'ok', {
            'template_id': template_id,
            'template_name': template.get('name'),
            'original_compose_backup': backup_info,
            'llm_mix_state': llm_mix_state,
            'llm_mix_history': llm_mix_history[-20:],
            'current_source': (
                'original'
                if not llm_mix_state
                else f"original + {' + '.join([str(item) for item in (llm_mix_state.get('provider_keys') or []) if str(item).strip()])}"
            ),
        }

    @staticmethod
    def _normalize_template_owner(template: Dict[str, Any]) -> Dict[str, Any]:
        """确保模板返回数据始终包含作者信息。"""
        item = dict(template or {})
        owner_name = str(item.get('owner_name') or '').strip()
        owner_id = str(item.get('owner_id') or '').strip()
        created_by = str(item.get('created_by') or '').strip()

        if not owner_name:
            owner_name = created_by or 'system'
        if not owner_id:
            # 兼容历史数据：若无 owner_id，保留为空或使用 created_by 作为可读标识
            owner_id = created_by or 'system'

        item['owner_name'] = owner_name
        item['owner_id'] = owner_id
        return item

    # 新增方法：获取模板目录下指定文件的内容
    def get_template_file_by_path(self, template_name: str, file_path: str,
                                  encoding: str = 'utf-8') -> Tuple[bool, Union[str, bytes], str, Dict]:
        """
        获取模板目录下指定文件的内容

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            encoding: 文本文件编码

        Returns:
            (success, content_or_error, content_type, file_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", "text/plain", {}

            # 获取模板目录
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", "text/plain", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", "text/plain", {}

            # 检查文件是否存在
            if not safe_path.exists() or not safe_path.is_file():
                return False, f"文件不存在: {file_path}", "text/plain", {}

            # 获取文件信息
            stat_info = safe_path.stat()
            file_info = {
                'name': safe_path.name,
                'path': str(safe_path.relative_to(template_dir)),
                'size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'is_directory': False
            }

            # 确定内容类型
            content_type, is_text = self._get_file_type(safe_path)
            file_info['content_type'] = content_type
            file_info['is_text'] = is_text

            # 读取文件内容
            try:
                if is_text:
                    with open(safe_path, 'r', encoding=encoding) as f:
                        content = f.read()
                else:
                    with open(safe_path, 'rb') as f:
                        content = f.read()
            except Exception as e:
                return False, f"读取文件失败: {str(e)}", "text/plain", file_info

            return True, content, content_type, file_info

        except Exception as e:
            self.logger.error(f"获取模板文件失败: {str(e)}", exc_info=True)
            return False, f"获取文件失败: {str(e)}", "text/plain", {}

    # 新增方法：更新模板目录下指定文件的内容
    def update_template_file(self, template_name: str, file_path: str, content: Union[str, bytes],
                             encoding: str = 'utf-8', updated_by: str = 'system') -> Tuple[bool, str, Dict]:
        """
        更新模板目录下指定文件的内容，并更新原始压缩文件（如果存在）

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            content: 文件内容（字符串或字节）
            encoding: 文本文件编码
            updated_by: 更新者

        Returns:
            (success, message, update_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_type = template['type']
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", {}

            if template_type == 'yaml' and safe_path.suffix.lower() in ['.yaml', '.yml']:
                main_file = Path(template.get('file_path') or '')
                if main_file.exists() and safe_path.resolve() != main_file.resolve():
                    return False, f"yaml模板仅允许编辑主文件: {main_file.name}", {
                        'expected_path': str(main_file.name),
                        'requested_path': str(safe_path.relative_to(template_dir))
                    }

            # 确保父目录存在
            safe_path.parent.mkdir(parents=True, exist_ok=True)

            # 保留原文件内容用于失败回滚（不落地备份文件）
            original_content = None
            if safe_path.exists():
                with open(safe_path, 'rb') as f:
                    original_content = f.read()

            # 写入新内容
            try:
                if isinstance(content, str):
                    with open(safe_path, 'w', encoding=encoding) as f:
                        f.write(content)
                    file_size = len(content.encode(encoding))
                elif isinstance(content, bytes):
                    with open(safe_path, 'wb') as f:
                        f.write(content)
                    file_size = len(content)
                else:
                    return False, f"不支持的内容类型: {type(content)}", {}
            except Exception as e:
                return False, f"写入文件失败: {str(e)}", {}

            # 获取更新后的文件信息
            stat_info = safe_path.stat()
            update_info = {
                'template_name': template_name,
                'file_path': str(safe_path.relative_to(template_dir)),
                'file_size': file_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'updated_by': updated_by,
                'updated_at': datetime.now().isoformat(),
                'backup_info': {}
            }

            # 如果是YAML文件，验证其格式
            if safe_path.suffix.lower() in ['.yaml', '.yml']:
                try:
                    with open(safe_path, 'r', encoding='utf-8') as f:
                        yaml_content = f.read()

                    is_valid, error_msg = self.validate_yaml_content(yaml_content, template_type, safe_path.name)
                    if not is_valid:
                        # 恢复更新前内容（不依赖备份文件）
                        if original_content is not None:
                            with open(safe_path, 'wb') as f:
                                f.write(original_content)
                        elif safe_path.exists():
                            safe_path.unlink()

                        return False, f"YAML格式验证失败: {error_msg}", {}

                    update_info['yaml_valid'] = True
                except Exception as e:
                    self.logger.warning(f"YAML验证失败: {str(e)}")
            # 如果模板是压缩格式，需要更新原始压缩文件
            if template_type == 'archive':
                archive_updated, archive_message = self._update_archive_file(template_name, safe_path, updated_by)
                update_info['archive_updated'] = archive_updated
                update_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"更新压缩文件失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'updated_files' not in metadata:
                metadata['updated_files'] = []

            metadata['updated_files'].append({
                'file_path': str(safe_path.relative_to(template_dir)),
                'updated_at': datetime.now().isoformat(),
                'updated_by': updated_by,
                'file_size': file_size
            })

            # 限制更新的文件记录数量
            if len(metadata['updated_files']) > 50:
                metadata['updated_files'] = metadata['updated_files'][-50:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            self.logger.info(f"模板文件更新成功: {template_name}/{file_path}, 大小: {file_size} 字节")
            if template_type == 'yaml' and safe_path.suffix.lower() in ['.yaml', '.yml']:
                removed = self._cleanup_extra_yaml_files_for_yaml_template(template)
                if removed:
                    update_info['removed_extra_yaml_files'] = removed
                    self.logger.info(f"模板 '{template_name}' 已清理多余YAML: {removed}")
            return True, f"文件更新成功", update_info

        except Exception as e:
            self.logger.error(f"更新模板文件失败: {str(e)}", exc_info=True)
            return False, f"更新文件失败: {str(e)}", {}

    # 新增方法：更新压缩文件中的对应文件
    def _update_archive_file(self, template_name: str, updated_file: Path, updated_by: str) -> Tuple[bool, str]:
        """更新压缩文件中的对应文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_path = updated_file.relative_to(template_dir)

            # 保留压缩文件原始字节用于失败回滚（不落地备份文件）
            original_archive_content = archive_path.read_bytes()

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 更新ZIP文件
                success = self._update_zip_file(archive_path, updated_file, relative_path)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 更新TAR文件
                success = self._update_tar_file(archive_path, updated_file, relative_path)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_updates' not in metadata:
                    metadata['archive_updates'] = []

                metadata['archive_updates'].append({
                    'file': str(relative_path),
                    'updated_at': datetime.now().isoformat(),
                    'updated_by': updated_by
                })

                # 限制记录数量
                if len(metadata['archive_updates']) > 20:
                    metadata['archive_updates'] = metadata['archive_updates'][-20:]

                self.logger.info(f"压缩文件更新成功: {template_name}, 文件: {relative_path}")
                return True, "压缩文件更新成功"
            else:
                # 失败回滚为原始压缩文件
                archive_path.write_bytes(original_archive_content)
                return False, "更新压缩文件失败"

        except Exception as e:
            self.logger.error(f"更新压缩文件失败: {str(e)}", exc_info=True)
            return False, f"更新压缩文件失败: {str(e)}"

    # 新增方法：更新ZIP文件中的单个文件
    def _update_zip_file(self, zip_path: Path, updated_file: Path, relative_path: Path) -> bool:
        """更新ZIP文件中的单个文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要更新的文件外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是我们要更新的文件，跳过
                            if item.filename == str(relative_path):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                    # 添加更新的文件
                    new_zip.write(updated_file, str(relative_path))

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"更新ZIP文件失败: {str(e)}")
            return False

    # 新增方法：更新TAR文件中的单个文件
    def _update_tar_file(self, tar_path: Path, updated_file: Path, relative_path: Path) -> bool:
        """更新TAR文件中的单个文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要更新的文件外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是我们要更新的文件，跳过
                            if item.name == str(relative_path):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                    # 添加更新的文件
                    new_tar.add(updated_file, arcname=str(relative_path))

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"更新TAR文件失败: {str(e)}")
            return False

    # 新增方法：删除模板目录下的指定文件
    def delete_template_file(self, template_name: str, file_path: str, deleted_by: str = 'system') -> Tuple[bool, str, Dict]:
        """
        删除模板目录下指定文件，并更新原始压缩文件（如果存在）

        Args:
            template_name: 模板名称
            file_path: 相对路径（相对于模板目录）
            deleted_by: 删除者

        Returns:
            (success, message, delete_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_type = template['type']
            template_dir = self.templates_root / template_name
            file_path = template_dir / file_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, file_path)
            if not safe_path:
                return False, f"无效的文件路径: {file_path}", {}

            # 检查文件是否存在
            if not safe_path.exists():
                return False, f"文件不存在: {file_path}", {}

            # 如果是YAML文件，检查是否是主文件
            if safe_path.suffix.lower() in ['.yaml', '.yml']:
                # 检查是否是docker-compose文件
                if safe_path.name.lower() in ['docker-compose.yaml', 'docker-compose.yml']:
                    return False, "不能删除docker-compose文件，它是模板的核心文件", {}

                # 如果是YAML模板类型且删除的是主YAML文件
                if template_type == 'yaml' and safe_path == Path(template['file_path']):
                    return False, "不能删除YAML模板的主文件", {}

            # 如果是目录，不能删除
            if safe_path.is_dir():
                return False, f"不能删除目录，请使用专门的目录删除API", {}

            # 获取文件信息（用于返回和记录）
            stat_info = safe_path.stat()
            file_info = {
                'template_name': template_name,
                'file_path': str(safe_path.relative_to(template_dir)),
                'file_name': safe_path.name,
                'file_size': stat_info.st_size,
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'deleted_by': deleted_by,
                'deleted_at': datetime.now().isoformat()
            }

            # 删除文件
            try:
                safe_path.unlink()
                self.logger.info(f"模板文件删除成功: {template_name}/{file_path}")
            except Exception as e:
                return False, f"删除文件失败: {str(e)}", {}

            # 如果模板是压缩格式，需要更新原始压缩文件
            if template_type == 'archive':
                archive_updated, archive_message = self._delete_from_archive_file(template_name, safe_path, deleted_by)
                file_info['archive_updated'] = archive_updated
                file_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"从压缩文件中删除失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'deleted_files' not in metadata:
                metadata['deleted_files'] = []

            metadata['deleted_files'].append(file_info.copy())

            # 限制删除的文件记录数量
            if len(metadata['deleted_files']) > 50:
                metadata['deleted_files'] = metadata['deleted_files'][-50:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            return True, f"文件删除成功", file_info

        except Exception as e:
            self.logger.error(f"删除模板文件失败: {str(e)}", exc_info=True)
            return False, f"删除文件失败: {str(e)}", {}

    # 新增方法：从压缩文件中删除对应文件
    def _delete_from_archive_file(self, template_name: str, deleted_file: Path, deleted_by: str) -> Tuple[bool, str]:
        """从压缩文件中删除对应文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_path = deleted_file.relative_to(template_dir)

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 从ZIP文件中删除
                success = self._delete_from_zip_file(archive_path, relative_path)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 从TAR文件中删除
                success = self._delete_from_tar_file(archive_path, relative_path)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_deletions' not in metadata:
                    metadata['archive_deletions'] = []

                metadata['archive_deletions'].append({
                    'file': str(relative_path),
                    'deleted_at': datetime.now().isoformat(),
                    'deleted_by': deleted_by,
                })

                # 限制记录数量
                if len(metadata['archive_deletions']) > 20:
                    metadata['archive_deletions'] = metadata['archive_deletions'][-20:]

                self.logger.info(f"从压缩文件中删除成功: {template_name}, 文件: {relative_path}")
                return True, f"从压缩文件中删除成功"
            else:
                return False, "从压缩文件中删除失败"

        except Exception as e:
            self.logger.error(f"从压缩文件中删除失败: {str(e)}", exc_info=True)
            return False, f"从压缩文件中删除失败: {str(e)}"

    # 新增方法：从ZIP文件中删除单个文件
    def _delete_from_zip_file(self, zip_path: Path, relative_path: Path) -> bool:
        """从ZIP文件中删除单个文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件（不包含要删除的文件）
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要删除的文件外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是要删除的文件，跳过
                            if item.filename == str(relative_path):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"从ZIP文件中删除失败: {str(e)}")
            return False

    # 新增方法：从TAR文件中删除单个文件
    def _delete_from_tar_file(self, tar_path: Path, relative_path: Path) -> bool:
        """从TAR文件中删除单个文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件（不包含要删除的文件）
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要删除的文件外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是要删除的文件，跳过
                            if item.name == str(relative_path):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"从TAR文件中删除失败: {str(e)}")
            return False

    # 新增方法：删除模板目录下的目录
    def delete_template_directory(self, template_name: str, dir_path: str, deleted_by: str = 'system',
                                  force: bool = False) -> Tuple[bool, str, Dict]:
        """
        删除模板目录下的指定目录

        Args:
            template_name: 模板名称
            dir_path: 相对路径（相对于模板目录）
            deleted_by: 删除者
            force: 是否强制删除非空目录

        Returns:
            (success, message, delete_info)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在", {}

            template_dir = self.templates_root / template_name
            dir_path = template_dir / dir_path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", {}

            # 构建完整路径，防止路径遍历攻击
            safe_path = self._get_safe_path(template_dir, dir_path)
            if not safe_path:
                return False, f"无效的目录路径: {dir_path}", {}

            # 检查目录是否存在
            if not safe_path.exists() or not safe_path.is_dir():
                return False, f"目录不存在: {dir_path}", {}

            # 检查是否试图删除根目录
            if safe_path == template_dir:
                return False, "不能删除模板根目录", {}

            # 检查是否包含docker-compose文件
            for yaml_name in ['docker-compose.yaml', 'docker-compose.yml']:
                yaml_file = safe_path / yaml_name
                if yaml_file.exists():
                    return False, f"目录中包含docker-compose文件，不能删除", {}

            # 检查目录是否为空
            dir_items = list(safe_path.iterdir())
            if dir_items and not force:
                return False, f"目录不为空，使用force=true参数强制删除", {}

            # 计算目录大小
            dir_size = sum(f.stat().st_size for f in safe_path.rglob('*') if f.is_file())

            # 记录删除信息
            delete_info = {
                'template_name': template_name,
                'dir_path': str(safe_path.relative_to(template_dir)),
                'dir_name': safe_path.name,
                'dir_size': dir_size,
                'file_count': len([f for f in safe_path.rglob('*') if f.is_file()]),
                'deleted_by': deleted_by,
                'deleted_at': datetime.now().isoformat(),
                'force': force
            }

            # 删除目录
            try:
                if force:
                    shutil.rmtree(safe_path)
                else:
                    safe_path.rmdir()

                self.logger.info(f"模板目录删除成功: {template_name}/{dir_path}")
            except Exception as e:
                return False, f"删除目录失败: {str(e)}", {}

            # 如果模板是压缩格式，需要更新原始压缩文件
            if template['type'] == 'archive':
                # 需要遍历删除压缩文件中的所有相关文件
                archive_updated, archive_message = self._delete_directory_from_archive(template_name, safe_path, deleted_by)
                delete_info['archive_updated'] = archive_updated
                delete_info['archive_message'] = archive_message

                if not archive_updated:
                    self.logger.warning(f"从压缩文件中删除目录失败: {archive_message}")

            # 更新模板元数据
            metadata = template.get('metadata', {})
            if 'deleted_directories' not in metadata:
                metadata['deleted_directories'] = []

            metadata['deleted_directories'].append(delete_info.copy())

            # 限制删除的目录记录数量
            if len(metadata['deleted_directories']) > 20:
                metadata['deleted_directories'] = metadata['deleted_directories'][-20:]

            # 更新数据库
            metadata_json = json.dumps(metadata)
            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, template_name)
                )
            else:
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, template_name)
                )

            return True, f"目录删除成功", delete_info

        except Exception as e:
            self.logger.error(f"删除模板目录失败: {str(e)}", exc_info=True)
            return False, f"删除目录失败: {str(e)}", {}

    # 新增方法：从压缩文件中删除目录
    def _delete_directory_from_archive(self, template_name: str, deleted_dir: Path, deleted_by: str) -> Tuple[bool, str]:
        """从压缩文件中删除目录及其所有文件"""
        try:
            template = self.get_template(template_name)
            if not template or template['type'] != 'archive':
                return False, "不是压缩模板"

            archive_path = Path(template['file_path'])
            if not archive_path.exists():
                return False, f"原始压缩文件不存在: {archive_path}"

            template_dir = self.templates_root / template_name
            relative_dir = deleted_dir.relative_to(template_dir)

            # 获取文件扩展名以确定压缩格式
            filename = archive_path.name.lower()

            if filename.endswith('.zip'):
                # 从ZIP文件中删除目录
                success = self._delete_dir_from_zip_file(archive_path, relative_dir)
            elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                # 从TAR文件中删除目录
                success = self._delete_dir_from_tar_file(archive_path, relative_dir)
            else:
                return False, f"不支持的压缩格式: {filename}"

            if success:
                # 更新元数据
                metadata = template.get('metadata', {})
                if 'archive_dir_deletions' not in metadata:
                    metadata['archive_dir_deletions'] = []

                metadata['archive_dir_deletions'].append({
                    'directory': str(relative_dir),
                    'deleted_at': datetime.now().isoformat(),
                    'deleted_by': deleted_by,
                })

                # 限制记录数量
                if len(metadata['archive_dir_deletions']) > 20:
                    metadata['archive_dir_deletions'] = metadata['archive_dir_deletions'][-20:]

                self.logger.info(f"从压缩文件中删除目录成功: {template_name}, 目录: {relative_dir}")
                return True, f"从压缩文件中删除目录成功"
            else:

                return False, "从压缩文件中删除目录失败"

        except Exception as e:
            self.logger.error(f"从压缩文件中删除目录失败: {str(e)}", exc_info=True)
            return False, f"从压缩文件中删除目录失败: {str(e)}"

    # 新增方法：从ZIP文件中删除目录
    def _delete_dir_from_zip_file(self, zip_path: Path, relative_dir: Path) -> bool:
        """从ZIP文件中删除目录及其所有文件"""
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_zip = Path(temp_dir) / 'updated.zip'

                # 创建新的ZIP文件（不包含要删除的目录中的文件）
                with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    # 复制原ZIP中除了要删除的目录外的所有文件
                    with zipfile.ZipFile(zip_path, 'r') as old_zip:
                        for item in old_zip.infolist():
                            # 如果是要删除的目录中的文件，跳过
                            if str(item.filename).startswith(str(relative_dir) + '/'):
                                continue

                            # 读取并写入其他文件
                            with old_zip.open(item.filename) as f:
                                content = f.read()
                                new_zip.writestr(item, content)

                # 替换原ZIP文件
                shutil.copy2(temp_zip, zip_path)
                return True

        except Exception as e:
            self.logger.error(f"从ZIP文件中删除目录失败: {str(e)}")
            return False

    # 新增方法：从TAR文件中删除目录
    def _delete_dir_from_tar_file(self, tar_path: Path, relative_dir: Path) -> bool:
        """从TAR文件中删除目录及其所有文件"""
        try:
            # 获取压缩模式
            filename = tar_path.name.lower()
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'

            write_mode = mode.replace('r:', 'w:') if ':' in mode else 'w'

            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_tar = Path(temp_dir) / 'updated.tar'

                # 创建新的TAR文件（不包含要删除的目录中的文件）
                with tarfile.open(temp_tar, write_mode) as new_tar:
                    # 复制原TAR中除了要删除的目录外的所有文件
                    with tarfile.open(tar_path, mode) as old_tar:
                        for item in old_tar.getmembers():
                            # 如果是要删除的目录中的文件，跳过
                            if str(item.name).startswith(str(relative_dir) + '/'):
                                continue

                            # 提取并重新添加文件
                            try:
                                extracted = old_tar.extractfile(item)
                                if extracted:
                                    # 创建TarInfo对象
                                    tar_info = tarfile.TarInfo(name=item.name)
                                    tar_info.size = item.size
                                    tar_info.mtime = item.mtime
                                    tar_info.mode = item.mode
                                    tar_info.type = item.type

                                    # 添加文件到新TAR
                                    new_tar.addfile(tar_info, extracted)
                            except Exception as e:
                                self.logger.warning(f"处理TAR文件项 {item.name} 失败: {e}")
                                continue

                # 替换原TAR文件
                shutil.copy2(temp_tar, tar_path)
                return True

        except Exception as e:
            self.logger.error(f"从TAR文件中删除目录失败: {str(e)}")
            return False

    # 新增辅助方法：获取安全的文件路径
    def _get_safe_path(self, base_dir: Path, file_path: str) -> Optional[Path]:
        """获取安全的文件路径，防止路径遍历攻击"""
        try:
            # 规范化路径
            normalized = Path(file_path).resolve()
            base_normalized = base_dir.resolve()

            # 确保路径在基础目录内
            try:
                relative = normalized.relative_to(base_normalized)
            except ValueError:
                return None

            # 防止使用..等路径遍历
            if '..' in str(relative):
                return None

            # 构建完整路径
            full_path = base_dir / relative

            # 确保仍然是基础目录的子目录
            if not str(full_path.resolve()).startswith(str(base_normalized)):
                return None

            return full_path
        except Exception as e:
            self.logger.warning(f"路径安全检查失败: {str(e)}")
            return None

    # 新增辅助方法：获取文件类型
    def _get_file_type(self, file_path: Path) -> Tuple[str, bool]:
        """获取文件类型和是否为文本文件"""
        # 根据扩展名判断
        ext = file_path.suffix.lower()

        # 文本文件扩展名
        text_extensions = {
            '.txt', '.md', '.yml', '.yaml', '.json', '.xml', '.html', '.htm',
            '.css', '.js', '.py', '.java', '.c', '.cpp', '.h', '.hpp',
            '.sh', '.bash', '.bat', '.cmd', '.ps1', '.sql', '.ini', '.cfg',
            '.conf', '.properties', '.log', '.csv', '.tsv', '.rst', '.tex'
        }

        # 特殊文件类型
        if ext in {'.yml', '.yaml'}:
            return 'text/yaml', True
        elif ext == '.json':
            return 'application/json', True
        elif ext == '.xml':
            return 'application/xml', True
        elif ext == '.html' or ext == '.htm':
            return 'text/html', True
        elif ext == '.css':
            return 'text/css', True
        elif ext == '.js':
            return 'application/javascript', True
        elif ext in {'.py', '.java', '.c', '.cpp', '.h', '.hpp', '.sh', '.bash'}:
            return 'text/plain', True

        # 压缩文件类型
        elif ext == '.zip':
            return 'application/zip', False
        elif ext == '.tar':
            return 'application/x-tar', False
        elif ext in {'.gz', '.tgz'}:
            return 'application/gzip', False
        elif ext in {'.bz2', '.tbz', '.tbz2'}:
            return 'application/x-bzip2', False
        elif ext in {'.xz', '.txz'}:
            return 'application/x-xz', False

        # 默认文本文件判断
        elif ext in text_extensions:
            return 'text/plain', True
        else:
            # 尝试判断是否为文本文件
            try:
                with open(file_path, 'rb') as f:
                    chunk = f.read(1024)
                    # 检查是否包含空字节（二进制文件的特征）
                    if b'\x00' in chunk:
                        return 'application/octet-stream', False
                    # 尝试解码为UTF-8
                    chunk.decode('utf-8', errors='ignore')
                    return 'text/plain', True
            except:
                return 'application/octet-stream', False

    # 新增方法：列出模板目录下的所有文件
    def list_template_files(self, template_name: str, path: str = '') -> Tuple[bool, Union[List[Dict], str]]:
        """
        列出模板目录下的所有文件和目录

        Args:
            template_name: 模板名称
            path: 相对路径（相对于模板目录）

        Returns:
            (success, files_or_error)
        """
        try:
            # 检查模板是否存在
            template = self.get_template(template_name)
            if not template:
                return False, f"模板 '{template_name}' 不存在"

            # 获取模板目录
            template_dir = self.templates_root / template_name
            path = template_dir / path
            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}"

            # 构建完整路径，防止路径遍历攻击
            if path:
                safe_path = self._get_safe_path(template_dir, path)
                if not safe_path:
                    return False, f"无效的路径: {path}"
                target_dir = safe_path
            else:
                target_dir = template_dir

            # 确保是目录
            if not target_dir.is_dir():
                return False, f"不是目录: {path}"

            # 列出文件和目录
            files = []
            try:
                for item in target_dir.iterdir():
                    try:
                        stat_info = item.stat()
                        files.append({
                            'name': item.name,
                            'path': str(item.relative_to(template_dir)),
                            'size': stat_info.st_size if item.is_file() else 0,
                            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                            'is_directory': item.is_dir(),
                            'is_file': item.is_file()
                        })
                    except Exception as e:
                        self.logger.warning(f"获取文件信息失败 {item}: {str(e)}")
                        continue
            except Exception as e:
                return False, f"列出文件失败: {str(e)}"

            # 按目录优先排序
            files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))

            # 添加父目录（如果不是根目录）
            if target_dir != template_dir:
                parent_path = target_dir.parent.relative_to(template_dir)
                files.insert(0, {
                    'name': '..',
                    'path': str(parent_path) if str(parent_path) != '.' else '',
                    'size': 0,
                    'created_time': '',
                    'modified_time': '',
                    'is_directory': True,
                    'is_file': False
                })

            return True, files

        except Exception as e:
            self.logger.error(f"列出模板文件失败: {str(e)}", exc_info=True)
            return False, f"列出文件失败: {str(e)}"
    def _get_compression_type(self, filename: str) -> str:
        """获取压缩文件类型"""
        filename_lower = filename.lower()
        for ext in self.supported_formats:
            if filename_lower.endswith(ext):
                if ext == '.zip':
                    return 'zip'
                elif ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']:
                    return 'tar'
        return 'unknown'

    def _extract_archive(self, file_path: Path, extract_to: Path):
        """解压各种压缩格式"""
        filename = file_path.name.lower()

        if filename.endswith('.zip'):
            self._extract_zip_with_filename_repair(file_path, extract_to)

        elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
            # 确定压缩模式
            mode = 'r'
            if filename.endswith('.gz') or filename.endswith('.tgz'):
                mode = 'r:gz'
            elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                mode = 'r:bz2'
            elif filename.endswith('.xz') or filename.endswith('.txz'):
                mode = 'r:xz'
            elif filename.endswith('.tar'):
                mode = 'r'

            with tarfile.open(file_path, mode) as tar_ref:
                tar_ref.extractall(extract_to)

        else:
            raise ValueError(f"不支持的压缩格式: {file_path.name}")

    def _decode_zip_member_name(self, zip_info: zipfile.ZipInfo) -> str:
        """
        修复 ZIP 中文文件名乱码：
        - UTF-8 标记位开启时直接使用原始名称
        - 未开启时，按 cp437 反编码回原始字节，再尝试 gb18030/gbk 解码
        """
        original_name = zip_info.filename

        # UTF-8 filename flag
        if zip_info.flag_bits & 0x800:
            return original_name

        try:
            raw_bytes = original_name.encode('cp437')
        except Exception:
            return original_name

        # 优先 UTF-8（兼容部分工具），其次 GB 系编码（常见于 Windows 中文压缩包）
        for encoding in ('utf-8', 'gb18030', 'gbk', 'big5'):
            try:
                decoded = raw_bytes.decode(encoding)
                if decoded:
                    return decoded
            except Exception:
                continue

        return original_name

    def _safe_extract_target(self, base_dir: Path, member_name: str) -> Path:
        """构造安全的解压目标路径，防止路径穿越"""
        normalized = member_name.replace('\\', '/')
        parts = []
        for part in Path(normalized).parts:
            if part in ('', '.'):
                continue
            if part == '..':
                continue
            parts.append(part)

        relative_path = Path(*parts) if parts else Path()
        target = (base_dir / relative_path).resolve()
        base_resolved = base_dir.resolve()
        try:
            target.relative_to(base_resolved)
        except Exception:
            raise ValueError(f"非法解压路径: {member_name}")
        return target

    def _extract_zip_with_filename_repair(self, zip_path: Path, extract_to: Path):
        """解压 ZIP，并修复中文文件名编码问题"""
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for zip_info in zip_ref.infolist():
                repaired_name = self._decode_zip_member_name(zip_info)
                if not repaired_name:
                    continue

                target_path = self._safe_extract_target(extract_to, repaired_name)

                if zip_info.is_dir() or repaired_name.endswith('/'):
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zip_ref.open(zip_info, 'r') as src, open(target_path, 'wb') as dst:
                    shutil.copyfileobj(src, dst)

    def validate_yaml_content(self, yaml_content: str, template_type: str, filename: str = None) -> Tuple[bool, str]:
        """
        验证YAML内容的有效性

        Args:
            yaml_content: YAML内容字符串
            template_type: 模板类型（yaml或archive）
            filename: 文件名（可选，用于错误信息）

        Returns:
            (is_valid, error_message)
        """
        try:
            # 尝试解析YAML
            parsed = yaml.safe_load(yaml_content)

            if parsed is None:
                return False, "YAML内容为空或格式无效"

            # 检查是否为字典格式
            if not isinstance(parsed, dict):
                return False, "YAML顶层必须是字典格式"

            # 检查必须包含services部分
            if 'services' not in parsed:
                return False, "YAML文件必须包含services部分"

            # 检查services部分的格式
            services = parsed.get('services', {})
            if not isinstance(services, dict):
                return False, "services部分必须是字典格式"

            # 检查services部分不能为空
            if len(services) == 0:
                return False, "services部分不能为空"

            # 检查版本号（可选）
            version = parsed.get('version')
            if version and not isinstance(version, str):
                return False, "version字段必须是字符串格式"

            # 验证每个服务的格式
            for service_name, service_config in services.items():
                if not isinstance(service_config, dict):
                    return False, f"服务 '{service_name}' 的配置必须是字典格式"

                # 检查必要的字段
                if 'image' not in service_config:
                    self.logger.warning(f"服务 '{service_name}' 没有指定image字段")

            return True, "YAML格式有效"

        except yaml.YAMLError as e:
            return False, f"YAML格式错误: {e}"
        except Exception as e:
            return False, f"验证失败: {str(e)}"

    def create_template(self, name: str, description: str, template_type: str,
                        file_content: bytes, filename: str, created_by: str,
                        visibility: str = 'shared', owner_id: str = '', owner_name: str = '',
                        web_port_presets: Optional[List[Dict[str, Any]]] = None,
                        tags: Optional[List[str]] = None) -> Tuple[bool, str]:
        """创建模板（增强版，支持多种压缩格式）"""
        template_dir = None
        file_path = None
        db_cleanup_needed = False

        try:
            # 检查模板名称是否已存在
            table_name = self.db.get_table_name('service_templates')
            existing = self.db.fetch_one(
                f"SELECT id FROM {table_name} WHERE name = %s"
                if self.db.db_type == 'mysql' else
                f"SELECT id FROM {table_name} WHERE name = ?",
                (name,)
            )
            if existing:
                return False, f"模板名称 '{name}' 已存在"

            # 创建模板目录
            template_dir = self.templates_root / name
            template_dir.mkdir(parents=True, exist_ok=False)

            file_path = template_dir / filename

            # 检查文件扩展名
            file_ext = Path(filename).suffix.lower()

            # 根据模板类型处理文件
            if template_type == 'yaml':
                try:
                    # 验证是否为有效的YAML文件
                    try:
                        yaml_content = file_content.decode('utf-8')
                    except UnicodeDecodeError:
                        raise ValueError("文件编码错误，无法解码为UTF-8格式")

                    # 使用验证函数
                    is_valid, error_msg = self.validate_yaml_content(yaml_content, template_type, filename)
                    if not is_valid:
                        raise ValueError(error_msg)

                    # 写入文件
                    with open(file_path, 'wb') as f:
                        f.write(file_content)

                    self.logger.info(f"YAML模板 '{name}' 格式验证成功")

                except Exception as e:
                    raise ValueError(str(e))

            elif template_type == 'archive':
                # 保存压缩文件
                with open(file_path, 'wb') as f:
                    f.write(file_content)

                # 检查是否是支持的压缩格式
                is_supported = False
                for ext in self.supported_formats:
                    if filename.lower().endswith(ext):
                        is_supported = True
                        break

                if not is_supported:
                    raise ValueError(f"不支持的压缩格式: {filename}，支持的格式: {', '.join(self.supported_formats)}")

                try:
                    # 解压文件
                    self._extract_archive(file_path, template_dir)

                    # 查找并验证YAML文件
                    yaml_files = []
                    found_yaml = None

                    # 首先查找特定的YAML文件
                    for yaml_name in ['docker-compose.yaml', 'docker-compose.yml']:
                        for yaml_path in template_dir.rglob(yaml_name):
                            if yaml_path.is_file():
                                yaml_files.append(yaml_path)

                    # 如果没找到标准名称，查找任何YAML文件
                    if not yaml_files:
                        yaml_files = list(template_dir.rglob('*.yaml'))
                        yaml_files.extend(list(template_dir.rglob('*.yml')))

                    # 检查是否找到YAML文件
                    if not yaml_files:
                        raise ValueError("压缩文件中未找到YAML文件")

                    # 验证每个找到的YAML文件
                    yaml_content = None
                    for yaml_file in yaml_files:
                        try:
                            with open(yaml_file, 'r', encoding='utf-8') as f:
                                content = f.read()

                            # 使用验证函数
                            is_valid, error_msg = self.validate_yaml_content(content, template_type, yaml_file.name)
                            if is_valid:
                                yaml_content = content
                                found_yaml = yaml_file
                                self.logger.info(f"在压缩文件中找到有效的YAML文件: {yaml_file}")
                                break
                            else:
                                self.logger.warning(f"文件 {yaml_file} 验证失败: {error_msg}")
                        except Exception as e:
                            self.logger.warning(f"文件 {yaml_file} 读取失败: {str(e)}")
                            continue

                    # 检查是否找到有效的YAML文件
                    if not yaml_content or not found_yaml:
                        raise ValueError("压缩文件中未找到包含有效services部分的YAML文件")

                    # 额外验证：确保services部分不为空
                    parsed = yaml.safe_load(yaml_content)
                    services = parsed.get('services', {})
                    if not services or len(services) == 0:
                        raise ValueError("YAML文件中的services部分不能为空")

                    self.logger.info(f"压缩模板 '{name}' 验证成功，找到有效YAML文件: {found_yaml}")

                except (zipfile.BadZipFile, tarfile.ReadError) as e:
                    raise ValueError(f"无效的压缩文件格式: {str(e)}")
                except Exception as e:
                    if not str(e).startswith("压缩文件"):
                        raise ValueError(f"压缩文件处理失败: {str(e)}")
                    else:
                        raise e

            else:
                raise ValueError(f"不支持的模板类型: {template_type}")

            visibility_value = (visibility or 'shared').strip().lower()
            if visibility_value not in ('shared', 'private'):
                visibility_value = 'shared'

            # 准备元数据
            metadata = {
                'file_size': len(file_content),
                'original_filename': filename,
                'created_by': created_by,
                'created_at': datetime.now().isoformat(),
                'template_type': template_type,
                'compression_type': self.compression_map.get(file_ext, 'unknown') if template_type == 'archive' else None,
                'visibility': visibility_value,
                'owner_id': owner_id or None,
                'owner_name': owner_name or None
            }
            if web_port_presets is not None:
                metadata['web_port_presets'] = self._normalize_web_port_presets(web_port_presets)
            metadata['tags'] = self._normalize_template_tags(tags)
            if template_type == 'archive' and found_yaml:
                metadata['main_yaml_file'] = str(found_yaml.relative_to(template_dir))
                metadata['original_compose_backup'] = self._write_original_compose_backup(
                    template_dir=template_dir,
                    compose_content=yaml_content,
                    source_type='archive',
                    main_compose_path=metadata['main_yaml_file']
                )
            elif template_type == 'yaml':
                metadata['main_yaml_file'] = filename
                metadata['original_compose_backup'] = self._write_original_compose_backup(
                    template_dir=template_dir,
                    compose_content=yaml_content,
                    source_type='yaml',
                    main_compose_path=filename
                )

            metadata_json = json.dumps(metadata)

            # 插入数据库记录
            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"INSERT INTO {table_name} "
                    "(name, description, type, file_path, visibility, owner_id, owner_name, created_by, created_at, updated_at, metadata) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), %s)",
                    (name, description, template_type, str(file_path), visibility_value, owner_id or None, owner_name or None, created_by, metadata_json)
                )
            else:
                self.db.execute_query(
                    f"INSERT INTO {table_name} "
                    "(name, description, type, file_path, visibility, owner_id, owner_name, created_by, created_at, updated_at, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?)",
                    (name, description, template_type, str(file_path), visibility_value, owner_id or None, owner_name or None, created_by, metadata_json)
                )

            db_cleanup_needed = True
            self.logger.info(f"模板 '{name}' 创建成功，类型: {template_type}")

            # 在模板创建成功后自动解析 docker-compose 内容（yaml/archive 一致）
            if template_type in ['yaml', 'archive']:
                try:
                    parse_success, parse_msg = self.parse_template_compose(name)
                    if not parse_success:
                        self.logger.warning(f"模板创建成功但解析失败: {parse_msg}")
                except Exception as e:
                    self.logger.error(f"模板解析异常: {str(e)}")

            return True, f"模板 '{name}' 创建成功"

        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"创建模板失败: {error_msg}")

            # 清理逻辑
            try:
                # 1. 删除创建的目录（如果存在）
                if template_dir and template_dir.exists():
                    self.logger.info(f"清理模板目录: {template_dir}")
                    shutil.rmtree(template_dir, ignore_errors=True)

                # 2. 删除数据库记录（如果已插入）
                if db_cleanup_needed:
                    self.logger.info(f"清理数据库记录: {name}")
                    table_name = self.db.get_table_name('service_templates')
                    self.db.execute_query(
                        f"DELETE FROM {table_name} WHERE name = %s"
                        if self.db.db_type == 'mysql' else
                        f"DELETE FROM {table_name} WHERE name = ?",
                        (name,)
                    )

                # 3. 清理其他可能的文件
                if file_path and file_path.exists():
                    try:
                        file_path.unlink()
                    except:
                        pass

            except Exception as cleanup_error:
                self.logger.error(f"清理失败: {str(cleanup_error)}")

            return False, f"创建模板失败: {error_msg}"

    def parse_template_compose(self, name: str) -> Tuple[bool, str]:
        """
        解析模板的 docker-compose 配置

        Args:
            name: 模板名称

        Returns:
            (success, message)
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            # 获取 YAML 内容
            success, content, msg = self.get_yaml_content(name)
            if not success:
                return False, f"无法获取YAML内容: {content}"

            # 计算内容哈希
            content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

            # 解析 compose 内容
            parser = DockerComposeParser()
            success, parsed_data, error_msg = parser.parse_compose_file(content)

            # 更新 metadata
            metadata = template.get('metadata', {})
            if isinstance(metadata, str):
                metadata = json.loads(metadata)

            metadata['content_hash'] = content_hash
            metadata['parsed_at'] = datetime.now().isoformat()

            if success:
                metadata['parsed_compose'] = parsed_data
                metadata['parse_error'] = None
                metadata['parse_status'] = 'success'
            else:
                metadata['parsed_compose'] = None
                metadata['parse_error'] = error_msg
                metadata['parse_status'] = 'error'

            # 更新数据库
            metadata_json = json.dumps(metadata)
            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s",
                    (metadata_json, name)
                )
            else:
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (metadata_json, name)
                )

            if success:
                self.logger.info(f"模板 '{name}' 解析成功")
                return True, "解析成功"
            else:
                self.logger.warning(f"模板 '{name}' 解析失败: {error_msg}")
                return False, f"解析失败: {error_msg}"

        except Exception as e:
            self.logger.error(f"解析模板 '{name}' 异常: {str(e)}")
            return False, f"解析异常: {str(e)}"

    def check_parse_staleness(self, name: str) -> Tuple[bool, bool, str]:
        """
        检查解析结果是否过期

        Args:
            name: 模板名称

        Returns:
            (success, is_stale, message)
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, False, "模板不存在"

            metadata = template.get('metadata', {})
            if isinstance(metadata, str):
                metadata = json.loads(metadata)

            stored_hash = metadata.get('content_hash')
            if not stored_hash:
                return True, True, "未找到内容哈希"

            # 重新计算哈希
            success, content, _ = self.get_yaml_content(name)
            if not success:
                return False, False, "无法读取YAML内容"

            current_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

            is_stale = (stored_hash != current_hash)
            return True, is_stale, "内容已变更" if is_stale else "内容未变更"

        except Exception as e:
            self.logger.error(f"检查模板 '{name}' 过期状态失败: {str(e)}")
            return False, False, str(e)

    def get_template(self, name: str) -> Optional[Dict]:
        """获取模板信息（包含元数据）"""
        table_name = self.db.get_table_name('service_templates')
        template = self.db.fetch_one(
            f"SELECT * FROM {table_name} WHERE name = %s"
            if self.db.db_type == 'mysql' else
            f"SELECT * FROM {table_name} WHERE name = ?",
            (name,)
        )

        if template:
            # 解析metadata字段
            if template.get('metadata'):
                if isinstance(template['metadata'], str):
                    try:
                        template['metadata'] = json.loads(template['metadata'])
                    except:
                        template['metadata'] = {}
            else:
                template['metadata'] = {}
            template['tags'] = self._normalize_template_tags((template.get('metadata') or {}).get('tags'))

            # 获取文件信息
            file_path = Path(template['file_path'])
            if file_path.exists():
                template['file_size'] = file_path.stat().st_size
                template['file_modified'] = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            else:
                template['file_size'] = 0
                template['file_modified'] = None

            # 获取目录信息
            template_dir = self.templates_root / name
            if template_dir.exists():
                template['directory_size'] = self._get_directory_size(template_dir)
            else:
                template['directory_size'] = 0

            template = self._normalize_template_owner(template)

        return template

    def get_template_by_id(self, template_id: int) -> Optional[Dict]:
        """根据ID获取模板信息（包含元数据）"""
        table_name = self.db.get_table_name('service_templates')
        template = self.db.fetch_one(
            f"SELECT * FROM {table_name} WHERE id = %s"
            if self.db.db_type == 'mysql' else
            f"SELECT * FROM {table_name} WHERE id = ?",
            (template_id,)
        )
        if not template:
            return None
        return self.get_template(template.get('name'))

    @staticmethod
    def _normalize_visibility(value: Optional[str]) -> str:
        v = (value or 'shared').strip().lower()
        return v if v in ('shared', 'private') else 'shared'

    @staticmethod
    def _is_super_admin(user_id: str = '', username: str = '') -> bool:
        """
        超级管理员判定：
        - UID=1 强制为管理员（核心规则）
        - 兼容：用户名 admin 也视为管理员
        """
        uid = str(user_id or '').strip()
        uname = str(username or '').strip().lower()
        return uid == '1' or uname == 'admin'

    def can_view_template(self, template: Optional[Dict], user_id: str = '', username: str = '') -> bool:
        if not template:
            return False
        if self._is_super_admin(user_id, username):
            return True
        visibility = self._normalize_visibility(template.get('visibility'))
        if visibility == 'shared':
            return True
        owner_id = str(template.get('owner_id') or '').strip()
        owner_name = str(template.get('owner_name') or '').strip()
        if owner_id and user_id and owner_id == str(user_id).strip():
            return True
        if owner_name and username and owner_name == username:
            return True
        return False

    def can_manage_template(self, template: Optional[Dict], user_id: str = '', username: str = '') -> bool:
        if not template:
            return False
        if self._is_super_admin(user_id, username):
            return True
        owner_id = str(template.get('owner_id') or '').strip()
        owner_name = str(template.get('owner_name') or '').strip()
        if owner_id and user_id and owner_id == str(user_id).strip():
            return True
        if owner_name and username and owner_name == username:
            return True
        return False

    def decorate_template_permissions(self, template: Dict, user_id: str = '', username: str = '') -> Dict:
        item = dict(template)
        item['visibility'] = self._normalize_visibility(item.get('visibility'))
        can_manage = self.can_manage_template(item, user_id, username)
        item['permissions'] = {
            'can_view': self.can_view_template(item, user_id, username),
            'can_manage': can_manage,
            'can_copy': self.can_view_template(item, user_id, username),
            'can_delete': can_manage,
            'can_update': can_manage
        }
        return item

    def _get_directory_size(self, path: Path) -> int:
        """计算目录总大小"""
        total_size = 0
        for file_path in path.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size

    def _cleanup_extra_yaml_files_for_yaml_template(self, template: Dict) -> List[str]:
        """
        yaml类型模板只保留主YAML（file_path），清理同目录下其他yaml/yml文件。
        返回被删除的相对路径列表。
        """
        removed: List[str] = []
        try:
            if not template or template.get('type') != 'yaml':
                return removed
            name = str(template.get('name') or '').strip()
            if not name:
                return removed
            template_dir = self.templates_root / name
            if not template_dir.exists():
                return removed
            main_file = Path(template.get('file_path') or '')
            if not main_file.exists():
                return removed
            main_resolved = main_file.resolve()
            candidates = list(template_dir.rglob('*.yaml')) + list(template_dir.rglob('*.yml'))
            for p in candidates:
                try:
                    if p.resolve() == main_resolved:
                        continue
                    p.unlink()
                    removed.append(str(p.relative_to(template_dir)))
                except Exception:
                    continue
        except Exception as e:
            self.logger.warning(f"清理多余YAML文件失败: {str(e)}")
        return removed

    def get_template_file(self, name: str) -> Optional[Path]:
        """获取模板文件路径（兼容旧接口）"""
        try:
            template = self.get_template(name)
            if not template:
                return None

            file_path = Path(template['file_path'])
            if file_path.exists():
                return file_path
            else:
                return None
        except Exception as e:
            self.logger.error(f"获取模板文件失败: {str(e)}")
            return None

    def get_yaml_content(self, name: str) -> Tuple[bool, Union[str, Dict], str]:
        """
        获取模板的YAML内容

        Returns:
            (success, content_or_error, message)
            成功时: (True, yaml_content_string, '')
            失败时: (False, error_message, error_details)
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", ""

            template_type = template['type']
            file_path = Path(template['file_path'])

            if not file_path.exists():
                return False, f"模板文件不存在: {file_path}", ""

            if template_type == 'yaml':
                removed = self._cleanup_extra_yaml_files_for_yaml_template(template)
                if removed:
                    self.logger.info(f"模板 '{name}' 清理多余YAML: {removed}")
                # 直接读取YAML文件
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    return True, yaml_content, ""

            elif template_type == 'archive':
                # 从压缩文件中提取YAML
                template_dir = self.templates_root / name

                # 查找YAML文件
                yaml_files = []
                for pattern in ['docker-compose.yaml', 'docker-compose.yml']:
                    yaml_files.extend(list(template_dir.rglob(pattern)))

                if not yaml_files:
                    yaml_files = list(template_dir.rglob('*.yaml'))
                    yaml_files.extend(list(template_dir.rglob('*.yml')))

                if not yaml_files:
                    return False, "压缩文件中未找到YAML文件", "no_yaml_in_archive"

                # 读取第一个YAML文件
                yaml_file = yaml_files[0]
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    return True, yaml_content, ""

            else:
                return False, f"不支持的模板类型: {template_type}", "unsupported_type"

        except Exception as e:
            self.logger.error(f"获取YAML内容失败: {str(e)}")
            return False, f"获取YAML内容失败: {str(e)}", str(e)

    def update_yaml_content(self, name: str, yaml_content: str, updated_by: str) -> Tuple[bool, str]:
        """
        更新模板的YAML内容

        对于yaml格式：直接替换原文件
        对于archive格式：替换解压目录中的yaml文件，并重新打包
        """
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            # 验证YAML内容
            try:
                parsed = yaml.safe_load(yaml_content)
                if not parsed or 'services' not in parsed:
                    return False, "YAML内容必须包含services部分"
            except yaml.YAMLError as e:
                return False, f"YAML格式错误: {e}"

            template_type = template['type']
            template_dir = self.templates_root / name

            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}"

            if template_type == 'yaml':
                # 直接更新YAML文件
                file_path = Path(template['file_path'])
                original_yaml_content = file_path.read_bytes() if file_path.exists() else None

                # 写入新内容
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)

                # 更新文件大小信息
                new_size = file_path.stat().st_size
                metadata = template.get('metadata', {})
                metadata['file_size'] = new_size
                metadata['last_updated_by'] = updated_by
                metadata['last_updated_at'] = datetime.now().isoformat()

                table_name = self.db.get_table_name('service_templates')
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"YAML模板 '{name}' 更新成功，新大小: {new_size} 字节")

                removed = self._cleanup_extra_yaml_files_for_yaml_template(template)
                if removed:
                    self.logger.info(f"模板 '{name}' 已清理多余YAML: {removed}")

                # 重新解析 docker-compose
                try:
                    self.parse_template_compose(name)
                except Exception as e:
                    self.logger.error(f"重新解析失败: {str(e)}")
                    # 解析失败时恢复原内容
                    if original_yaml_content is not None:
                        with open(file_path, 'wb') as f:
                            f.write(original_yaml_content)

                return True, f"模板 '{name}' 更新成功"

            elif template_type == 'archive':
                # 更新压缩包中的YAML
                archive_path = Path(template['file_path'])
                original_archive_content = archive_path.read_bytes() if archive_path.exists() else None

                # 查找解压目录中的YAML文件
                yaml_files = []
                for pattern in ['docker-compose.yaml', 'docker-compose.yml']:
                    yaml_files.extend(list(template_dir.rglob(pattern)))

                if not yaml_files:
                    # 尝试查找任何YAML文件
                    yaml_files = list(template_dir.rglob('*.yaml'))
                    yaml_files.extend(list(template_dir.rglob('*.yml')))

                if not yaml_files:
                    return False, "未找到YAML文件进行更新"

                # 更新第一个找到的YAML文件（通常是主文件）
                yaml_file = yaml_files[0]
                original_yaml_content = yaml_file.read_bytes() if yaml_file.exists() else None

                # 写入新内容
                with open(yaml_file, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)

                # 重新创建压缩文件
                # 先删除原压缩文件
                archive_path.unlink()

                # 创建新压缩文件（根据原文件扩展名）
                filename = archive_path.name.lower()

                if filename.endswith('.zip'):
                    # 创建ZIP文件
                    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for file_path in template_dir.rglob('*'):
                            if file_path.is_file():
                                # 计算相对路径
                                rel_path = file_path.relative_to(template_dir)
                                # 添加文件到ZIP
                                zipf.write(file_path, rel_path)

                elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                    # 创建TAR文件
                    mode = 'w'
                    if filename.endswith('.gz') or filename.endswith('.tgz'):
                        mode = 'w:gz'
                    elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                        mode = 'w:bz2'
                    elif filename.endswith('.xz') or filename.endswith('.txz'):
                        mode = 'w:xz'
                    elif filename.endswith('.tar'):
                        mode = 'w'

                    with tarfile.open(archive_path, mode) as tarf:
                        for file_path in template_dir.rglob('*'):
                            if file_path.is_file():
                                # 计算相对路径
                                rel_path = file_path.relative_to(template_dir)
                                # 添加文件到TAR
                                tarf.add(file_path, arcname=rel_path)

                # 更新元数据
                new_size = archive_path.stat().st_size
                metadata = template.get('metadata', {})
                metadata['file_size'] = new_size
                metadata['last_updated_by'] = updated_by
                metadata['last_updated_at'] = datetime.now().isoformat()

                # 更新目录大小
                dir_size = self._get_directory_size(template_dir)
                metadata['directory_size'] = dir_size

                table_name = self.db.get_table_name('service_templates')
                self.db.execute_query(
                    f"UPDATE {table_name} SET updated_at = NOW(), metadata = %s WHERE name = %s"
                    if self.db.db_type == 'mysql' else
                    f"UPDATE {table_name} SET updated_at = datetime('now'), metadata = ? WHERE name = ?",
                    (json.dumps(metadata), name)
                )

                self.logger.info(f"压缩模板 '{name}' 更新成功，新大小: {new_size} 字节")

                # 重新解析 docker-compose
                try:
                    self.parse_template_compose(name)
                except Exception as e:
                    self.logger.error(f"重新解析失败: {str(e)}")
                    # 解析失败回滚
                    if original_yaml_content is not None:
                        with open(yaml_file, 'wb') as f:
                            f.write(original_yaml_content)
                    if original_archive_content is not None:
                        with open(archive_path, 'wb') as f:
                            f.write(original_archive_content)

                return True, f"模板 '{name}' 更新成功"

            else:
                return False, f"不支持的模板类型: {template_type}"

        except Exception as e:
            self.logger.error(f"更新YAML内容失败: {str(e)}", exc_info=True)
            return False, f"更新失败: {str(e)}"

    def get_template_file_info(self, name: str) -> Optional[Dict]:
        """获取模板文件详细信息"""
        try:
            template = self.get_template(name)
            if not template:
                return None

            file_path = Path(template['file_path'])

            if not file_path.exists():
                return None

            # 获取文件信息
            stat_info = file_path.stat()
            file_info = {
                'name': name,
                'type': template['type'],
                'file_path': str(file_path),
                'size': stat_info.st_size,
                'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'files_in_template': []
            }

            # 如果是压缩类型，获取压缩包内的文件列表
            if template['type'] == 'archive':
                filename = file_path.name.lower()

                if filename.endswith('.zip'):
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            file_info['files_in_template'] = zip_ref.namelist()
                            file_info['archive_info'] = {
                                'format': 'zip',
                                'file_count': len(zip_ref.namelist()),
                                'compressed_size': sum(zinfo.compress_size for zinfo in zip_ref.filelist),
                                'uncompressed_size': sum(zinfo.file_size for zinfo in zip_ref.filelist),
                                'compression_ratio': sum(zinfo.compress_size for zinfo in zip_ref.filelist) /
                                                     max(sum(zinfo.file_size for zinfo in zip_ref.filelist), 1)
                            }
                    except Exception as e:
                        self.logger.warning(f"读取ZIP文件信息失败: {e}")

                elif any(filename.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz']):
                    try:
                        mode = 'r'
                        if filename.endswith('.gz') or filename.endswith('.tgz'):
                            mode = 'r:gz'
                        elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                            mode = 'r:bz2'
                        elif filename.endswith('.xz') or filename.endswith('.txz'):
                            mode = 'r:xz'

                        with tarfile.open(file_path, mode) as tar_ref:
                            members = tar_ref.getmembers()
                            file_info['files_in_template'] = [m.name for m in members if m.isfile()]
                            file_info['archive_info'] = {
                                'format': 'tar',
                                'file_count': len([m for m in members if m.isfile()]),
                                'compression': mode.replace('r:', '') if ':' in mode else 'none'
                            }
                    except Exception as e:
                        self.logger.warning(f"读取TAR文件信息失败: {e}")

            return file_info

        except Exception as e:
            self.logger.error(f"获取模板文件信息失败: {str(e)}")
            return None

    def get_template_file_content(self, name: str, return_type: str = 'file') -> Tuple[bool, Union[bytes, str, Path], str]:
        """获取模板文件内容"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain"

            file_path = Path(template['file_path'])

            if not file_path.exists():
                return False, f"模板文件不存在: {file_path}", "text/plain"

            # 根据模板类型确定内容类型
            if template['type'] == 'yaml':
                content_type = 'text/yaml'
                file_extension = 'yaml'
            elif template['type'] == 'archive':
                # 根据文件扩展名确定内容类型
                filename = file_path.name.lower()
                if filename.endswith('.zip'):
                    content_type = 'application/zip'
                    file_extension = 'zip'
                elif filename.endswith('.tar'):
                    content_type = 'application/x-tar'
                    file_extension = 'tar'
                elif filename.endswith('.gz') or filename.endswith('.tgz'):
                    content_type = 'application/gzip'
                    file_extension = 'tar.gz'
                elif filename.endswith('.bz2') or filename.endswith('.tbz') or filename.endswith('.tbz2'):
                    content_type = 'application/x-bzip2'
                    file_extension = 'tar.bz2'
                elif filename.endswith('.xz') or filename.endswith('.txz'):
                    content_type = 'application/x-xz'
                    file_extension = 'tar.xz'
                else:
                    content_type = 'application/octet-stream'
                    file_extension = 'bin'
            else:
                content_type = 'application/octet-stream'
                file_extension = 'bin'

            # 根据返回类型处理文件
            if return_type == 'bytes':
                with open(file_path, 'rb') as f:
                    content = f.read()
                return True, content, content_type
            elif return_type == 'stream':
                # 返回文件流
                return True, file_path, content_type
            else:  # 'file' 类型
                return True, file_path, content_type

        except Exception as e:
            self.logger.error(f"获取模板文件内容失败: {str(e)}")
            return False, f"获取文件失败: {str(e)}", "text/plain"

    def get_template_as_zip(self, name: str, include_all_files: bool = True) -> Tuple[bool, Union[bytes, str], str]:
        """将模板打包为ZIP下载"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain"

            template_dir = self.templates_root / name

            if not template_dir.exists():
                return False, f"模板目录不存在: {template_dir}", "text/plain"

            # 创建内存中的ZIP文件
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                if include_all_files:
                    # 添加模板目录下的所有文件
                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            rel_path = file_path.relative_to(template_dir)
                            zip_file.write(file_path, rel_path)
                else:
                    # 只添加主要模板文件
                    main_file = Path(template['file_path'])
                    if main_file.exists():
                        zip_file.write(main_file, main_file.name)

            zip_content = zip_buffer.getvalue()
            zip_buffer.close()

            return True, zip_content, 'application/zip'

        except Exception as e:
            self.logger.error(f"打包模板为ZIP失败: {str(e)}")
            return False, f"打包失败: {str(e)}", "text/plain"

    def export_template(self, name: str, export_format: str = 'original') -> Tuple[bool, Any, str, str]:
        """导出模板"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在", "text/plain", ""

            template_type = template['type']
            file_path = Path(template['file_path'])

            # 确定文件名
            if export_format == 'original':
                if template_type == 'yaml':
                    export_format = 'yaml'
                else:
                    export_format = 'archive'

            # 根据导出格式处理
            if export_format == 'yaml':
                # 导出为YAML
                success, yaml_content, message = self.get_yaml_content(name)
                if success:
                    return True, yaml_content.encode('utf-8'), 'text/yaml', f"{name}.yaml"
                else:
                    return False, message, "text/plain", ""

            elif export_format == 'archive':
                # 导出为压缩文件
                if template_type == 'archive':
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    return True, content, self._get_content_type(file_path.name), f"{name}{Path(file_path).suffix}"
                else:
                    success, archive_content, content_type = self.get_template_as_zip(name, True)
                    if success:
                        return True, archive_content, content_type, f"{name}.zip"
                    else:
                        return False, archive_content, "text/plain", ""

            else:
                return False, f"不支持的导出格式: {export_format}", "text/plain", ""

        except Exception as e:
            self.logger.error(f"导出模板失败: {str(e)}")
            return False, f"导出失败: {str(e)}", "text/plain", ""

    def _get_content_type(self, filename: str) -> str:
        """根据文件名获取Content-Type"""
        filename_lower = filename.lower()

        if filename_lower.endswith('.zip'):
            return 'application/zip'
        elif filename_lower.endswith('.tar'):
            return 'application/x-tar'
        elif filename_lower.endswith('.tar.gz') or filename_lower.endswith('.tgz'):
            return 'application/gzip'
        elif filename_lower.endswith('.tar.bz2') or filename_lower.endswith('.tbz') or filename_lower.endswith('.tbz2'):
            return 'application/x-bzip2'
        elif filename_lower.endswith('.tar.xz') or filename_lower.endswith('.txz'):
            return 'application/x-xz'
        else:
            return 'application/octet-stream'

    def list_templates(self, page: int = 1, per_page: int = 20, user_id: str = '', username: str = '') -> Tuple[List[Dict], int]:
        """列出所有模板（包含文件大小信息）"""
        offset = (page - 1) * per_page
        table_name = self.db.get_table_name('service_templates')
        user_id = str(user_id or '').strip()
        username = str(username or '').strip()
        is_super_admin = self._is_super_admin(user_id, username)

        if self.db.db_type == 'mysql':
            if is_super_admin:
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                    (per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}"
                )
            elif user_id or username:
                where_clause = "visibility = 'shared' OR owner_id = %s OR owner_name = %s"
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE ({where_clause}) ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                    (user_id, username, per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE ({where_clause})",
                    (user_id, username)
                )
            else:
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE visibility = 'shared' ORDER BY updated_at DESC LIMIT %s OFFSET %s",
                    (per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE visibility = 'shared'"
                )
        else:
            if is_super_admin:
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}"
                )
            elif user_id or username:
                where_clause = "visibility = 'shared' OR owner_id = ? OR owner_name = ?"
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE ({where_clause}) ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (user_id, username, per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE ({where_clause})",
                    (user_id, username)
                )
            else:
                templates = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE visibility = 'shared' ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                    (per_page, offset)
                )
                count_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE visibility = 'shared'"
                )

        total = count_result.get('count', 0) if count_result else 0

        # 为每个模板添加文件大小信息
        for idx, template in enumerate(templates):
            # 解析metadata
            if template.get('metadata'):
                if isinstance(template['metadata'], str):
                    try:
                        template['metadata'] = json.loads(template['metadata'])
                    except:
                        template['metadata'] = {}
            else:
                template['metadata'] = {}

            # 获取文件信息
            file_path = Path(template['file_path'])
            if file_path.exists():
                template['file_size'] = file_path.stat().st_size
            else:
                template['file_size'] = 0

            # 获取目录信息
            template_dir = self.templates_root / template['name']
            if template_dir.exists():
                template['directory_size'] = self._get_directory_size(template_dir)
            else:
                template['directory_size'] = 0
            template['visibility'] = self._normalize_visibility(template.get('visibility'))
            templates[idx] = self._normalize_template_owner(template)

        templates = [self.decorate_template_permissions(t, user_id, username) for t in templates]

        return templates, total

    def delete_template(self, name: str) -> Tuple[bool, str]:
        """删除模板"""
        try:
            template = self.get_template(name)
            if not template:
                return False, f"模板 '{name}' 不存在"

            template_dir = self.templates_root / name
            if template_dir.exists():
                shutil.rmtree(template_dir, ignore_errors=True)

            table_name = self.db.get_table_name('service_templates')
            self.db.execute_query(
                f"DELETE FROM {table_name} WHERE name = %s"
                if self.db.db_type == 'mysql' else
                f"DELETE FROM {table_name} WHERE name = ?",
                (name,)
            )

            self.logger.info(f"模板 '{name}' 删除成功")
            return True, f"模板 '{name}' 删除成功"
        except Exception as e:
            self.logger.error(f"删除模板失败: {str(e)}")
            return False, f"删除模板失败: {str(e)}"

    def update_template_basic(self, template_id: int,
                              new_name: Optional[str] = None,
                              description: Optional[str] = None,
                              visibility: Optional[str] = None,
                              web_port_presets: Optional[List[Dict[str, Any]]] = None,
                              tags: Optional[List[str]] = None,
                              updated_by: str = '') -> Tuple[bool, str, Optional[Dict]]:
        """更新模板基础信息（支持重命名）"""
        try:
            template = self.get_template_by_id(template_id)
            if not template:
                return False, "模板不存在", None

            current_name = template['name']
            target_name = (new_name or current_name).strip()
            if not target_name:
                return False, "模板名称不能为空", None

            target_visibility = self._normalize_visibility(visibility or template.get('visibility'))
            target_description = template.get('description', '') if description is None else description

            current_dir = self.templates_root / current_name
            target_dir = self.templates_root / target_name
            old_file_path = Path(template['file_path'])
            moved = False

            if target_name != current_name:
                existed = self.get_template(target_name)
                if existed:
                    return False, f"模板名称 '{target_name}' 已存在", None
                if current_dir.exists():
                    if target_dir.exists():
                        return False, f"目标目录已存在: {target_dir}", None
                    shutil.move(str(current_dir), str(target_dir))
                    moved = True

            new_file_path = old_file_path
            if target_name != current_name and moved:
                try:
                    rel = old_file_path.relative_to(current_dir)
                    new_file_path = target_dir / rel
                except Exception:
                    new_file_path = target_dir / old_file_path.name

            metadata = template.get('metadata') or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            metadata['last_updated_by'] = updated_by or metadata.get('last_updated_by')
            metadata['last_updated_at'] = datetime.now().isoformat()
            metadata['visibility'] = target_visibility
            if web_port_presets is not None:
                metadata['web_port_presets'] = self._normalize_web_port_presets(web_port_presets)
            if tags is not None:
                metadata['tags'] = self._normalize_template_tags(tags)

            table_name = self.db.get_table_name('service_templates')
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"UPDATE {table_name} SET name = %s, description = %s, visibility = %s, "
                    "file_path = %s, updated_at = NOW(), metadata = %s WHERE id = %s",
                    (target_name, target_description, target_visibility, str(new_file_path), json.dumps(metadata), template_id)
                )
            else:
                self.db.execute_query(
                    f"UPDATE {table_name} SET name = ?, description = ?, visibility = ?, "
                    "file_path = ?, updated_at = datetime('now'), metadata = ? WHERE id = ?",
                    (target_name, target_description, target_visibility, str(new_file_path), json.dumps(metadata), template_id)
                )

            updated = self.get_template_by_id(template_id)
            return True, "模板更新成功", updated
        except Exception as e:
            self.logger.error(f"更新模板基础信息失败: {str(e)}", exc_info=True)
            return False, f"更新模板失败: {str(e)}", None

    def copy_template(self, source_name: str, target_name: str, created_by: str,
                      owner_id: str = '', owner_name: str = '',
                      visibility: str = 'private', description: str = '') -> Tuple[bool, str]:
        """复制模板为新模板"""
        try:
            source = self.get_template(source_name)
            if not source:
                return False, f"源模板 '{source_name}' 不存在"

            source_file = Path(source['file_path'])
            if not source_file.exists():
                return False, f"源模板文件不存在: {source_file}"

            with open(source_file, 'rb') as f:
                file_content = f.read()

            source_desc = source.get('description') or ''
            final_description = description if description else f"{source_desc} (copy from {source_name})".strip()
            source_meta = source.get('metadata') or {}
            if isinstance(source_meta, str):
                try:
                    source_meta = json.loads(source_meta)
                except Exception:
                    source_meta = {}
            original_filename = source_meta.get('original_filename') or source_file.name

            return self.create_template(
                name=target_name,
                description=final_description,
                template_type=source.get('type', 'yaml'),
                file_content=file_content,
                filename=original_filename,
                created_by=created_by,
                visibility=visibility,
                owner_id=owner_id,
                owner_name=owner_name,
                web_port_presets=source_meta.get('web_port_presets'),
                tags=self._normalize_template_tags(source_meta.get('tags')),
            )
        except Exception as e:
            self.logger.error(f"复制模板失败: {str(e)}", exc_info=True)
            return False, f"复制模板失败: {str(e)}"
