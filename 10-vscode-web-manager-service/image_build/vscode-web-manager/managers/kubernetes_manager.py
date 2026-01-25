"""
Kubernetes管理器
"""
import os
import re
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from config import Config, get_codewiki_env_vars, validate_codewiki_config, get_dynamic_env_vars
from utils.errors import CodeServerError

logger = logging.getLogger(__name__)

class KubernetesManager:
    def __init__(self, validate_connection: bool = True):
        self.namespace = Config.K8S_NAMESPACE
        self.storage_class = Config.K8S_STORAGE_CLASS
        self.api_url = Config.K8S_API_URL
        self.api_token = Config.K8S_API_TOKEN
        self.api_cert = Config.K8S_API_CERT
        self.api_key = Config.K8S_API_KEY
        self.ca_cert = Config.K8S_CA_CERT
        self.verify_ssl = Config.K8S_VERIFY_SSL

        if not Config.K8S_AVAILABLE:
            self.available = False
            logger.error("Kubernetes客户端不可用，请安装kubernetes-client")
            raise RuntimeError("Kubernetes客户端不可用")

        try:
            logger.info(f"开始初始化Kubernetes客户端...")
            logger.info(f"IN_K8S环境变量: {os.getenv('IN_K8S', '未设置')}")
            logger.info(f"K8S_API_URL: {self.api_url}")
            logger.info(f"K8S_NAMESPACE: {self.namespace}")

            # 导入kubernetes模块
            from kubernetes import client, config
            from kubernetes.client.rest import ApiException
            self.client = client
            self.config = config
            self.ApiException = ApiException

            if os.getenv("IN_K8S", "false").lower() == "true":
                logger.info("检测到IN_K8S=true，尝试使用集群内配置...")
                try:
                    config.load_incluster_config()
                    logger.info("✓ 使用集群内K8S配置成功")
                except Exception as e:
                    logger.error(f"✗ 加载集群内配置失败: {str(e)}")
                    raise
            elif self.api_url:
                # 使用自定义API URL和鉴权配置
                logger.info(f"使用自定义API URL: {self.api_url}")
                configuration = client.Configuration()
                configuration.host = self.api_url

                # 设置鉴权方式
                if self.api_token:
                    # Token认证
                    configuration.api_key['authorization'] = f"Bearer {self.api_token}"
                    configuration.api_key_prefix['authorization'] = 'Bearer'
                    logger.info(f"使用Token认证访问K8S API")
                elif self.api_cert and self.api_key:
                    # 证书认证
                    configuration.cert_file = self.api_cert
                    configuration.key_file = self.api_key
                    logger.info(f"使用证书认证访问K8S API")
                else:
                    # 尝试使用kubeconfig
                    logger.warning("自定义API URL但未提供鉴权信息，尝试使用kubeconfig")
                    try:
                        config.load_kube_config()
                        logger.info("✓ 使用kubeconfig配置成功")
                    except Exception as e:
                        logger.error(f"✗ 加载kubeconfig失败: {str(e)}")
                        raise

                # SSL配置
                if self.ca_cert:
                    configuration.ssl_ca_cert = self.ca_cert
                configuration.verify_ssl = self.verify_ssl

                # 应用配置
                client.Configuration.set_default(configuration)
                logger.info(f"✓ 使用自定义K8S API URL配置成功")
            else:
                # 默认使用kubeconfig
                logger.info("未指定API URL，尝试使用kubeconfig配置...")
                try:
                    config.load_kube_config()
                    logger.info("✓ 使用kubeconfig配置成功")
                except Exception as e:
                    logger.error(f"✗ 加载kubeconfig失败: {str(e)}")
                    raise

            # 初始化各个API客户端
            logger.info("初始化Kubernetes API客户端...")
            try:
                self.core_v1 = client.CoreV1Api()
                self.apps_v1 = client.AppsV1Api()
                self.batch_v1 = client.BatchV1Api()
                self.networking_v1 = client.NetworkingV1Api()
                self.storage_v1 = client.StorageV1Api()
                logger.info("✓ Kubernetes API客户端初始化成功")
            except Exception as e:
                logger.error(f"✗ 初始化API客户端失败: {str(e)}")
                raise

            self.available = True

            # 验证连接
            if validate_connection:
                logger.info("开始验证Kubernetes连接...")
                try:
                    self._validate_connection()
                    logger.info("✓ Kubernetes连接验证成功")
                except Exception as e:
                    logger.error(f"✗ Kubernetes连接验证失败: {str(e)}")
                    raise

            logger.info(f"✓ Kubernetes客户端初始化成功，命名空间: {self.namespace}")

        except Exception as e:
            logger.error(f"✗ Kubernetes客户端初始化失败")
            logger.error(f"错误类型: {type(e).__name__}")
            logger.error(f"错误信息: {str(e)}")

            # 打印详细的堆栈信息
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"详细堆栈信息:\n{error_details}")

            self.available = False

            # 根据不同的异常类型提供更详细的错误信息
            error_message = "Kubernetes客户端初始化失败"
            error_details = {"error_type": type(e).__name__, "error": str(e)}

            # 添加特定错误信息
            if "Unauthorized" in str(e) or "Forbidden" in str(e):
                error_message = "Kubernetes认证失败"
                error_details["suggestion"] = "请检查Token、证书或kubeconfig文件的权限"
            elif "Connection refused" in str(e) or "timed out" in str(e):
                error_message = "无法连接到Kubernetes API服务器"
                error_details["suggestion"] = "请检查K8S_API_URL是否正确，网络是否可达"
            elif "certificate verify failed" in str(e):
                error_message = "SSL证书验证失败"
                error_details["suggestion"] = "请检查K8S_CA_CERT证书或设置K8S_VERIFY_SSL=false"
            elif "No such file or directory" in str(e):
                error_message = "配置文件或证书文件不存在"
                error_details["suggestion"] = "请检查证书文件路径是否正确"

            raise CodeServerError(
                message=error_message,
                details=error_details,
                status_code=500
            )

    def _validate_connection(self):
        """严格验证K8S连接和配置"""
        validation_errors = []

        try:
            # 检查是否在K8S集群内部
            in_k8s = os.getenv("IN_K8S", "false").lower() == "true"

            if in_k8s:
                logger.info("在Kubernetes集群内部运行，使用ServiceAccount认证")

            # 尝试获取K8S版本信息
            try:
                version_info = self.client.VersionApi().get_code()
                logger.info(f"Kubernetes连接成功，版本: {version_info.git_version}")
            except Exception as e:
                validation_errors.append(f"无法获取Kubernetes版本: {str(e)}")
                raise RuntimeError(f"无法连接到Kubernetes API: {str(e)}")

            # 严格验证命名空间是否存在
            try:
                namespace_info = self.core_v1.read_namespace(name=self.namespace)
                logger.info(f"命名空间验证成功: {self.namespace} (状态: {namespace_info.status.phase})")
            except self.ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"无权访问命名空间 {self.namespace}，请检查权限配置")
                    raise RuntimeError(f"命名空间权限不足: {self.namespace}")
                elif e.status == 404:
                    validation_errors.append(f"命名空间不存在: {self.namespace}")
                    raise RuntimeError(f"命名空间不存在: {self.namespace}")
                else:
                    validation_errors.append(f"验证命名空间失败: {e.reason}")
                    raise RuntimeError(f"命名空间验证失败: {e.reason}")

            # 严格验证存储类是否存在
            try:
                storage_classes = self.storage_v1.list_storage_class()
                storage_class_names = [sc.metadata.name for sc in storage_classes.items]

                if not self.storage_class:
                    validation_errors.append("K8S_STORAGE_CLASS 配置不能为空")
                    raise RuntimeError("存储类配置为空")

                if self.storage_class not in storage_class_names:
                    validation_errors.append(f"存储类不存在: {self.storage_class}")
                    validation_errors.append(f"可用的存储类: {', '.join(storage_class_names)}")
                    raise RuntimeError(f"存储类不存在: {self.storage_class}")

                logger.info(f"存储类验证成功: {self.storage_class}")
            except self.ApiException as e:
                validation_errors.append(f"验证存储类失败: {e.reason}")
                raise RuntimeError(f"存储类验证失败: {e.reason}")
            except Exception as e:
                validation_errors.append(f"获取存储类列表失败: {str(e)}")
                raise RuntimeError(f"存储类验证失败: {str(e)}")

            # 验证服务类型是否有效
            valid_service_types = ["LoadBalancer", "NodePort", "ClusterIP"]
            if Config.K8S_SERVICE_TYPE not in valid_service_types:
                validation_errors.append(f"服务类型无效: {Config.K8S_SERVICE_TYPE}，有效值: {', '.join(valid_service_types)}")
                raise RuntimeError(f"服务类型无效: {Config.K8S_SERVICE_TYPE}")

            # 验证端口配置
            if Config.K8S_SERVICE_PORT < 1 or Config.K8S_SERVICE_PORT > 65535:
                validation_errors.append(f"服务端口无效: {Config.K8S_SERVICE_PORT}")
                raise RuntimeError(f"服务端口无效: {Config.K8S_SERVICE_PORT}")

            if Config.K8S_CONTAINER_PORT < 1 or Config.K8S_CONTAINER_PORT > 65535:
                validation_errors.append(f"容器端口无效: {Config.K8S_CONTAINER_PORT}")
                raise RuntimeError(f"容器端口无效: {Config.K8S_CONTAINER_PORT}")

            # 验证命名空间格式（Kubernetes命名空间命名规则）
            if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', self.namespace):
                validation_errors.append(f"命名空间格式无效: {self.namespace}，只能包含小写字母、数字和连字符")
                raise RuntimeError(f"命名空间格式无效: {self.namespace}")

            # 验证是否具有必要的权限
            try:
                # 检查是否有创建Deployment的权限
                self.apps_v1.list_namespaced_deployment(namespace=self.namespace, limit=1)
                logger.info(f"Deployment权限验证成功")
            except self.ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建Deployment的权限")
                    raise RuntimeError(f"权限不足: 无法创建Deployment")

            try:
                # 检查是否有创建Service的权限
                self.core_v1.list_namespaced_service(namespace=self.namespace, limit=1)
                logger.info(f"Service权限验证成功")
            except self.ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建Service的权限")
                    raise RuntimeError(f"权限不足: 无法创建Service")

            try:
                # 检查是否有创建PVC的权限
                self.core_v1.list_namespaced_persistent_volume_claim(namespace=self.namespace, limit=1)
                logger.info(f"PVC权限验证成功")
            except self.ApiException as e:
                if e.status == 403:
                    validation_errors.append(f"缺少创建PVC的权限")
                    raise RuntimeError(f"权限不足: 无法创建PVC")

            logger.info("所有Kubernetes配置验证通过")
            return True

        except Exception as e:
            if validation_errors:
                error_msg = "Kubernetes配置验证失败:\n" + "\n".join(f"  • {error}" for error in validation_errors)
                logger.error(error_msg)
            raise

    def generate_resource_name(self, project_id: str, resource_type: str) -> str:
        """生成资源名称"""
        short_id = project_id[:8]
        name = f"code-{resource_type}-{short_id}".lower()
        name = re.sub(r'[^a-z0-9-]', '-', name)
        return name[:63].strip('-')

    def create_pvc(self, project_id: str, storage_size: str = "5Gi") -> str:
        """创建PVC"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            pvc = self.client.V1PersistentVolumeClaim(
                metadata=self.client.V1ObjectMeta(
                    name=pvc_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1PersistentVolumeClaimSpec(
                    access_modes=["ReadWriteMany"],
                    storage_class_name=self.storage_class,
                    resources=self.client.V1ResourceRequirements(
                        requests={"storage": storage_size}
                    )
                )
            )

            self.core_v1.create_namespaced_persistent_volume_claim(
                namespace=self.namespace, body=pvc
            )
            logger.info(f"创建PVC: {pvc_name}")
            return pvc_name
        except self.ApiException as e:
            if e.status == 409:
                logger.warning(f"PVC已存在: {pvc_name}")
                return pvc_name
            logger.error(f"创建PVC失败: {e}")
            raise CodeServerError(
                message="创建PVC失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )

    def delete_pvc(self, project_id: str) -> bool:
        """删除PVC"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            self.core_v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )
            logger.info(f"删除PVC: {pvc_name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"PVC不存在: {pvc_name}")
                return True
            logger.error(f"删除PVC失败: {e}")
            raise CodeServerError(
                message="删除PVC失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e)
                },
                status_code=500
            )

    def recreate_pvc(self, project_id: str, storage_size: str = "5Gi") -> str:
        """重建PVC：先删除旧的，再创建新的"""
        try:
            # 先删除旧的PVC
            self.delete_pvc(project_id)
            # 等待PVC完全删除
            time.sleep(5)
            # 创建新的PVC
            pvc_name = self.create_pvc(project_id, storage_size)
            logger.info(f"重建PVC成功: {pvc_name}")
            return pvc_name
        except Exception as e:
            logger.error(f"重建PVC失败: {e}")
            raise

    def copy_archive_to_pvc(self, project_id: str, archive_path: str, pvc_name: str) -> bool:
        """复制压缩包到PVC并在PVC中解压 - 使用curl下载方式"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 检查HTTP配置
        if not Config.EXTERNAL_ACCESS_URL:
            raise CodeServerError(
                message="HTTP配置不完整，无法通过下载方式复制文件",
                details={"project_id": project_id, "config_error": "EXTERNAL_ACCESS_URL未设置"},
                status_code=500
            )

        job_name = f"extract-{project_id[:8]}"
        job_name = re.sub(r'[^a-z0-9-]', '-', job_name.lower())[:63]

        try:
            # 首先检查是否已有运行中的解压任务
            try:
                existing_jobs = self.batch_v1.list_namespaced_job(
                    namespace=self.namespace,
                    label_selector=f"job-name={job_name}"
                )
                if existing_jobs:
                    logger.info(f"解压任务已存在: {job_name}")
                    # 检查任务状态
                    if not existing_jobs.items:
                        logger.info(f"解压任务已失败，重新创建: {job_name}")
                        # 删除失败的任务
                        self.batch_v1.delete_namespaced_job(
                            name=job_name,
                            namespace=self.namespace,
                            propagation_policy="Background"
                        )
                    else:
                        job = existing_jobs.items[0]
                        if job.status.succeeded:
                            logger.info(f"解压任务已成功完成: {job_name}")
                            return True
                        elif job.status.failed:
                            logger.info(f"解压任务已失败，重新创建: {job_name}")
                            # 删除失败的任务
                            self.batch_v1.delete_namespaced_job(
                                name=job_name,
                                namespace=self.namespace,
                                propagation_policy="Background"
                            )
                        else:
                            logger.info(f"解压任务正在进行中: {job_name}")
                            return True
            except:
                pass

            # 检查压缩包文件是否存在
            if not os.path.exists(archive_path):
                raise CodeServerError(
                    message="压缩包文件不存在",
                    details={
                        "project_id": project_id,
                        "archive_path": archive_path
                    },
                    status_code=404
                )

            # 获取压缩包文件名和扩展名
            archive_filename = os.path.basename(archive_path)
            archive_ext = os.path.splitext(archive_filename)[1].lower()
            file_size = os.path.getsize(archive_path)

            logger.info(f"通过HTTP下载文件到PVC: {archive_filename}, 大小: {file_size} 字节")

            # 构建下载URL
            download_url = f"{Config.EXTERNAL_ACCESS_URL}{Config.API_PREFIX}/projects/{project_id}/download/archive-token?token={Config.ARCHIVE_DOWNLOAD_TOKEN}"

            # 解压命令
            extract_command = f"""
            # 安装必要的工具
    
            # 创建临时目录
            mkdir -p /temp
    
            echo "开始下载文件: {archive_filename}"
            echo "下载URL: {download_url}"
            echo "目标PVC: {pvc_name}"
    
            # 下载压缩包
            echo "使用curl下载文件..."
            curl -L --retry 3 --retry-delay 5 --max-time {Config.ARCHIVE_DOWNLOAD_TIMEOUT} \\
                 -o /temp/{archive_filename} \\
                 "{download_url}"
    
            # 检查下载结果
            download_status=$?
            if [ $download_status -ne 0 ]; then
                echo "下载失败，curl退出状态: $download_status"
                echo "尝试使用wget..."
                apk add --no-cache wget
                wget --tries=3 --timeout={Config.ARCHIVE_DOWNLOAD_TIMEOUT} \\
                     -O /temp/{archive_filename} \\
                     "{download_url}"
                wget_status=$?
                if [ $wget_status -ne 0 ]; then
                    echo "wget也失败，退出状态: $wget_status"
                    exit 1
                fi
            fi
    
            # 验证下载的文件
            if [ ! -f /temp/{archive_filename} ]; then
                echo "错误: 下载的文件不存在"
                exit 1
            fi
    
            actual_size=$(wc -c < /temp/{archive_filename})
            echo "下载完成，文件大小: $actual_size 字节"
    
            if [ $actual_size -lt 100 ]; then
                echo "警告: 下载的文件过小，可能是错误页面"
                echo "文件内容:"
                head -c 500 /temp/{archive_filename}
                exit 1
            fi
    
            echo "文件下载成功，开始解压..."
    
            # 切换到工作目录
            cd /workspace
    
            # 根据文件类型解压
            echo "开始解压文件..."
            case "{archive_ext}" in
                .zip)
                    echo "解压ZIP文件..."
                    unzip -o /temp/{archive_filename} -d /workspace/
                    ;;
                .tar)
                    echo "解压TAR文件..."
                    tar -xf /temp/{archive_filename} -C /workspace/
                    ;;
                .tar.gz|.tgz)
                    echo "解压TAR.GZ文件..."
                    tar -xzf /temp/{archive_filename} -C /workspace/
                    ;;
                .tar.bz2)
                    echo "解压TAR.BZ2文件..."
                    tar -xjf /temp/{archive_filename} -C /workspace/
                    ;;
                .gz)
                    echo "解压GZ文件..."
                    gzip -d /temp/{archive_filename} -c > /workspace/$(basename {archive_filename} .gz)
                    ;;
                *)
                    echo "未知的文件格式: {archive_ext}"
                    echo "尝试作为普通文件复制..."
                    cp /temp/{archive_filename} /workspace/
                    ;;
            esac
    
            # 清理临时文件
            rm -rf /temp/*
    
            # 检查解压结果
            echo "解压完成，检查工作目录内容:"
            ls -la /workspace/
            file_count=$(find /workspace -type f | wc -l)
            dir_count=$(find /workspace -type d | wc -l)
            echo "文件数量: $file_count"
            echo "目录数量: $dir_count"
    
            if [ $file_count -eq 0 ]; then
                echo "警告: 解压后没有找到任何文件"
            fi
    
            echo "任务完成"
            """

            # 设置环境变量
            env_vars = [
                self.client.V1EnvVar(name="DOWNLOAD_URL", value=download_url),
                self.client.V1EnvVar(name="ARCHIVE_FILENAME", value=archive_filename),
                self.client.V1EnvVar(name="PROJECT_ID", value=project_id),
                self.client.V1EnvVar(name="EXTERNAL_ACCESS_URL", value=Config.EXTERNAL_ACCESS_URL),
                self.client.V1EnvVar(name="ARCHIVE_DOWNLOAD_TIMEOUT", value=str(Config.ARCHIVE_DOWNLOAD_TIMEOUT))
            ]

            job = self.client.V1Job(
                metadata=self.client.V1ObjectMeta(
                    name=job_name,
                    namespace=self.namespace,
                    labels={
                        "app": "archive-download-extract",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    },
                    annotations={
                        "download-url": download_url,
                        "archive-filename": archive_filename,
                        "project-id": project_id
                    }
                ),
                spec=self.client.V1JobSpec(
                    backoff_limit=5,  # 允许重试3次
                    ttl_seconds_after_finished=600,  # 10分钟后删除
                    template=self.client.V1PodTemplateSpec(
                        metadata=self.client.V1ObjectMeta(
                            labels={
                                "app": "archive-download-extract",
                                "project-id": project_id,
                                "job-name": job_name
                            }
                        ),
                        spec=self.client.V1PodSpec(
                            restart_policy="OnFailure",  # 失败时重启
                            containers=[self.client.V1Container(
                                name="download-extract",
                                image="ghcr.io/runshine/vpn-monitor:latest",
                                command=["/bin/sh", "-c"],
                                args=[extract_command],
                                env=env_vars,
                                volume_mounts=[
                                    self.client.V1VolumeMount(
                                        name="workspace",
                                        mount_path="/workspace"
                                    ),
                                    self.client.V1VolumeMount(
                                        name="temp",
                                        mount_path="/temp"
                                    )
                                ],
                                resources=self.client.V1ResourceRequirements(
                                    requests={
                                        "cpu": "200m",
                                        "memory": "256Mi"
                                    },
                                    limits={
                                        "cpu": "1000m",
                                        "memory": "1024Mi"
                                    }
                                )
                            )],
                            volumes=[
                                self.client.V1Volume(
                                    name="workspace",
                                    persistent_volume_claim=self.client.V1PersistentVolumeClaimVolumeSource(
                                        claim_name=pvc_name
                                    )
                                ),
                                self.client.V1Volume(
                                    name="temp",
                                    empty_dir=self.client.V1EmptyDirVolumeSource()
                                )
                            ]
                        )
                    )
                )
            )

            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=job)
            logger.info(f"创建下载解压任务: {job_name}")
            logger.info(f"下载URL: {download_url}")
            logger.info(f"目标PVC: {pvc_name}")

            # 等待任务完成
            max_wait_time = 600  # 10分钟
            start_time = time.time()
            last_status = None

            while time.time() - start_time < max_wait_time:
                time.sleep(5)
                try:
                    job_status = self.batch_v1.read_namespaced_job_status(
                        name=job_name, namespace=self.namespace
                    )

                    current_status = {
                        "active": job_status.status.active or 0,
                        "succeeded": job_status.status.succeeded or 0,
                        "failed": job_status.status.failed or 0
                    }

                    # 只有状态变化时才记录
                    if current_status != last_status:
                        logger.info(
                            f"任务状态: 活跃={current_status['active']}, 成功={current_status['succeeded']}, 失败={current_status['failed']}")
                        last_status = current_status

                    if job_status.status.succeeded:
                        logger.info(f"下载解压任务成功完成: {job_name}")

                        # 获取成功日志
                        try:
                            pods = self.core_v1.list_namespaced_pod(
                                namespace=self.namespace,
                                label_selector=f"job-name={job_name}"
                            )
                            if pods.items:
                                pod = pods.items[0]
                                log_content = self.core_v1.read_namespaced_pod_log(
                                    name=pod.metadata.name,
                                    namespace=self.namespace,
                                    container="download-extract",
                                    tail_lines=50  # 获取更多日志用于记录
                                )
                                logger.info(f"下载解压任务成功日志(最后50行):\n{log_content}")
                        except Exception as log_error:
                            logger.warning(f"获取成功日志失败: {log_error}")

                        return True

                    elif job_status.status.failed:
                        logger.error(f"下载解压任务失败: {job_name}")

                        # 详细记录失败信息
                        error_details = {
                            "project_id": project_id,
                            "job_name": job_name,
                            "download_url": download_url,
                            "pvc_name": pvc_name,
                            "archive_filename": archive_filename,
                            "archive_size": file_size,
                            "error_timestamp": datetime.now(timezone.utc).isoformat()
                        }

                        pods_details = []
                        pods = self.core_v1.list_namespaced_pod(
                            namespace=self.namespace,
                            label_selector=f"job-name={job_name}"
                        )

                        for pod in pods.items:
                            pod_detail = {
                                "pod_name": pod.metadata.name,
                                "pod_status": pod.status.phase,
                                "creation_timestamp": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
                                "containers": []
                            }

                            try:
                                pod_status = self.core_v1.read_namespaced_pod_status(
                                    name=pod.metadata.name, namespace=self.namespace
                                )

                                if pod_status.status.container_statuses:
                                    for container in pod_status.status.container_statuses:
                                        container_detail = {
                                            "container_name": container.name,
                                            "ready": container.ready,
                                            "restart_count": container.restart_count,
                                            "image": container.image
                                        }

                                        if container.state.terminated and container.state.terminated.exit_code != 0:
                                            container_detail.update({
                                                "exit_code": container.state.terminated.exit_code,
                                                "reason": container.state.terminated.reason,
                                                "message": container.state.terminated.message,
                                                "started_at": container.state.terminated.started_at.isoformat() if container.state.terminated.started_at else None,
                                                "finished_at": container.state.terminated.finished_at.isoformat() if container.state.terminated.finished_at else None
                                            })

                                            # 获取容器日志
                                            try:
                                                log_content = self.core_v1.read_namespaced_pod_log(
                                                    name=pod.metadata.name,
                                                    namespace=self.namespace,
                                                    container=container.name,
                                                    tail_lines=200  # 获取更多日志用于诊断
                                                )
                                                container_detail["logs"] = log_content

                                                # 记录关键错误信息
                                                error_lines = []
                                                for line in log_content.split('\n'):
                                                    line_lower = line.lower()
                                                    if any(keyword in line_lower for keyword in
                                                           ['error', 'failed', 'exit', 'failed to', 'unable to', 'cannot']):
                                                        error_lines.append(line.strip())

                                                if error_lines:
                                                    container_detail["error_lines"] = error_lines[:10]  # 只保留前10个错误行

                                            except Exception as log_error:
                                                container_detail["log_error"] = str(log_error)

                                        elif container.state.waiting:
                                            container_detail.update({
                                                "state": "waiting",
                                                "reason": container.state.waiting.reason,
                                                "message": container.state.waiting.message
                                            })

                                        pod_detail["containers"].append(container_detail)
                            except Exception as pod_error:
                                pod_detail["pod_error"] = str(pod_error)

                            pods_details.append(pod_detail)

                        error_details["pods"] = pods_details

                        # 获取Job事件信息
                        try:
                            events = self.core_v1.list_namespaced_event(
                                namespace=self.namespace,
                                field_selector=f"involvedObject.name={job_name},involvedObject.kind=Job"
                            )

                            job_events = []
                            for event in events.items[:10]:  # 只取最近10个事件
                                job_events.append({
                                    "type": event.type,
                                    "reason": event.reason,
                                    "message": event.message,
                                    "count": event.count,
                                    "first_timestamp": event.first_timestamp.isoformat() if event.first_timestamp else None,
                                    "last_timestamp": event.last_timestamp.isoformat() if event.last_timestamp else None
                                })

                            if job_events:
                                error_details["job_events"] = job_events
                        except Exception as event_error:
                            error_details["events_error"] = str(event_error)

                        # 记录详细的错误信息到日志
                        logger.error(f"PVC拷贝失败详细信息:")
                        logger.error(f"项目ID: {project_id}")
                        logger.error(f"Job名称: {job_name}")
                        logger.error(f"下载URL: {download_url}")
                        logger.error(f"PVC名称: {pvc_name}")
                        logger.error(f"压缩包: {archive_filename} ({file_size} 字节)")

                        for pod_detail in pods_details:
                            logger.error(f"Pod: {pod_detail['pod_name']}, 状态: {pod_detail['pod_status']}")
                            for container in pod_detail.get('containers', []):
                                if 'exit_code' in container:
                                    logger.error(
                                        f"  容器 {container['container_name']}: 退出代码 {container['exit_code']}, 原因: {container.get('reason', '未知')}")
                                    if 'error_lines' in container:
                                        for error_line in container['error_lines']:
                                            logger.error(f"    错误: {error_line}")

                        # 抛出详细的错误信息
                        raise CodeServerError(
                            message="通过HTTP下载并解压文件到PVC失败",
                            details=error_details,
                            status_code=500
                        )

                except self.ApiException as e:
                    logger.warning(f"获取任务状态失败: {e}")
                    continue

            # 如果超时，记录详细错误
            timeout_details = {
                "project_id": project_id,
                "job_name": job_name,
                "download_url": download_url,
                "pvc_name": pvc_name,
                "archive_filename": archive_filename,
                "timeout_seconds": max_wait_time,
                "last_known_status": last_status,
                "error_timestamp": datetime.now(timezone.utc).isoformat()
            }

            logger.error(f"PVC拷贝任务超时: {timeout_details}")

            raise CodeServerError(
                message="下载解压文件超时",
                details=timeout_details,
                status_code=504
            )

        except CodeServerError:
            # 重新抛出，保留原有异常
            raise
        except Exception as e:
            logger.error(f"创建下载解压任务失败: {e}")

            # 记录创建任务时的错误
            creation_error_details = {
                "project_id": project_id,
                "archive_path": archive_path,
                "pvc_name": pvc_name,
                "error_type": type(e).__name__,
                "error": str(e),
                "error_timestamp": datetime.now(timezone.utc).isoformat()
            }

            raise CodeServerError(
                message="创建文件下载解压任务失败",
                details=creation_error_details,
                status_code=500
            )


    def create_deployment(self, project_id: str, password: str, pvc_name: str, cpu_limit: str = "1000m",
                          memory_limit: str = "1024Mi") -> str:
        """创建Deployment"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = self.client.V1Deployment(
                metadata=self.client.V1ObjectMeta(
                    name=deploy_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1DeploymentSpec(
                    replicas=1,
                    selector=self.client.V1LabelSelector(
                        match_labels={"app": "code-server", "project-id": project_id}
                    ),
                    template=self.client.V1PodTemplateSpec(
                        metadata=self.client.V1ObjectMeta(
                            labels={"app": "code-server", "project-id": project_id}
                        ),
                        spec=self.client.V1PodSpec(
                            containers=[self.client.V1Container(
                                name="code-server",
                                image=Config.K8S_CODE_SERVER_IMAGE,
                                image_pull_policy=Config.K8S_CODE_SERVER_PULL_POLICY,
                                ports=[self.client.V1ContainerPort(container_port=Config.K8S_CONTAINER_PORT)],
                                env=[
                                    self.client.V1EnvVar(name="PASSWORD", value=password),
                                    self.client.V1EnvVar(name="PUID", value="1000"),
                                    self.client.V1EnvVar(name="PGID", value="1000"),
                                    self.client.V1EnvVar(name="TZ", value="Asia/Shanghai"),
                                    self.client.V1EnvVar(name="PROJECT_ID", value=project_id),
                                    self.client.V1EnvVar(name="SUDO_PASSWORD", value=password)
                                ] + [
                                    self.client.V1EnvVar(name=key, value=value)
                                    for key, value in get_dynamic_env_vars("code_server").items()
                                ],
                                volume_mounts=[self.client.V1VolumeMount(
                                    name="workspace",
                                    mount_path="/config/workspace"
                                )],
                                resources=self.client.V1ResourceRequirements(
                                    requests={
                                        "cpu": "500m",
                                        "memory": "512Mi"
                                    },
                                    limits={
                                        "cpu": cpu_limit,
                                        "memory": memory_limit
                                    }
                                ),
                                readiness_probe=self.client.V1Probe(
                                    http_get=self.client.V1HTTPGetAction(
                                        path="/",
                                        port=Config.K8S_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=10,
                                    period_seconds=5,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                ),
                                liveness_probe=self.client.V1Probe(
                                    http_get=self.client.V1HTTPGetAction(
                                        path="/",
                                        port=Config.K8S_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=30,
                                    period_seconds=10,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                )
                            )],
                            volumes=[self.client.V1Volume(
                                name="workspace",
                                persistent_volume_claim=self.client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                )
                            )]
                        )
                    )
                )
            )

            self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace, body=deployment
            )
            logger.info(f"创建Deployment: {deploy_name}")
            return deploy_name
        except self.ApiException as e:
            if e.status == 409:
                logger.warning(f"Deployment已存在: {deploy_name}")
                return deploy_name
            logger.error(f"创建Deployment失败: {e}")
            raise CodeServerError(
                message="创建Deployment失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )


    def create_service(self, project_id: str) -> Dict[str, Any]:
        """创建Service"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_resource_name(project_id, "svc")

        try:
            service = self.client.V1Service(
                metadata=self.client.V1ObjectMeta(
                    name=svc_name,
                    namespace=self.namespace,
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1ServiceSpec(
                    type=Config.K8S_SERVICE_TYPE,
                    selector={"app": "code-server", "project-id": project_id},
                    ports=[self.client.V1ServicePort(
                        port=Config.K8S_SERVICE_PORT,
                        target_port=Config.K8S_CONTAINER_PORT,
                        name="http"
                    )]
                )
            )

            svc = self.core_v1.create_namespaced_service(namespace=self.namespace, body=service)
            logger.info(f"创建Service: {svc_name}, 类型: {Config.K8S_SERVICE_TYPE}")

            access_info = {
                "name": svc_name,
                "port": Config.K8S_SERVICE_PORT,
                "type": Config.K8S_SERVICE_TYPE
            }

            # 根据服务类型获取访问信息
            if Config.K8S_SERVICE_TYPE == "LoadBalancer":
                # 等待LoadBalancer IP分配
                for i in range(30):
                    time.sleep(5)
                    try:
                        svc = self.core_v1.read_namespaced_service(
                            name=svc_name, namespace=self.namespace
                        )
                        if svc.status.load_balancer.ingress:
                            ingress = svc.status.load_balancer.ingress[0]
                            if ingress.ip:
                                access_info["ip"] = ingress.ip
                                access_info["url"] = f"http://{ingress.ip}:{Config.K8S_SERVICE_PORT}"
                                break
                            elif ingress.hostname:
                                access_info["hostname"] = ingress.hostname
                                access_info["url"] = f"https://{ingress.hostname}:{Config.K8S_SERVICE_PORT}"
                                break
                    except self.ApiException:
                        continue

            elif Config.K8S_SERVICE_TYPE == "NodePort":
                # 获取NodePort
                if svc.spec.ports and svc.spec.ports[0].node_port:
                    node_port = svc.spec.ports[0].node_port
                    access_info["node_port"] = node_port

                    # 获取节点IP
                    try:
                        nodes = self.core_v1.list_node()
                        if nodes.items:
                            node = nodes.items[0]
                            for addr in node.status.addresses:
                                if addr.type == "ExternalIP":
                                    access_info["node_ip"] = addr.address
                                    access_info["url"] = f"http://{addr.address}:{node_port}"
                                    break
                                elif addr.type == "InternalIP":
                                    access_info["node_ip"] = addr.address
                                    access_info["url"] = f"http://{addr.address}:{node_port}"
                    except:
                        access_info["url"] = f"NodePort: {node_port}"

            elif Config.K8S_SERVICE_TYPE == "ClusterIP":
                access_info["cluster_ip"] = svc.spec.cluster_ip
                access_info["url"] = f"http://{svc_name}.{self.namespace}.svc.cluster.local:{Config.K8S_SERVICE_PORT}"

            return access_info
        except self.ApiException as e:
            if e.status == 409:
                logger.warning(f"Service已存在: {svc_name}")
                # 获取现有服务信息
                try:
                    svc = self.core_v1.read_namespaced_service(
                        name=svc_name, namespace=self.namespace
                    )
                    return {"name": svc_name, "port": Config.K8S_SERVICE_PORT}
                except:
                    return {"name": svc_name}
            logger.error(f"创建Service失败: {e}")
            raise CodeServerError(
                message="创建Service失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e),
                    "status": e.status,
                    "reason": e.reason
                },
                status_code=500
            )


    def create_ingress(self, project_id: str, host: str = None) -> Optional[str]:
        """创建Ingress（可选）"""
        if not self.available:
            return None

        ingress_name = self.generate_resource_name(project_id, "ingress")
        svc_name = self.generate_resource_name(project_id, "svc")

        if not host:
            host = f"{project_id[:8]}.{os.getenv('VSCODE_INGRESS_DOMAIN', 'code-server.sothothv2.com')}"

        try:
            ingress = self.client.V1Ingress(
                metadata=self.client.V1ObjectMeta(
                    name=ingress_name,
                    namespace=self.namespace,
                    annotations={
                        "nginx.ingress.kubernetes.io/rewrite-target": "/",
                        "nginx.ingress.kubernetes.io/proxy-body-size": "1024m"
                    },
                    labels={
                        "app": "code-server",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1IngressSpec(
                    ingress_class_name="nginx",
                    tls=[self.client.V1IngressTLS(
                        hosts=[host],
                        secret_name="wildcard-code-server.sothothv2.com-tls"
                    )],
                    rules=[self.client.V1IngressRule(
                        host=host,
                        http=self.client.V1HTTPIngressRuleValue(
                            paths=[self.client.V1HTTPIngressPath(
                                path="/",
                                path_type="Prefix",
                                backend=self.client.V1IngressBackend(
                                    service=self.client.V1IngressServiceBackend(
                                        name=svc_name,
                                        port=self.client.V1ServiceBackendPort(
                                            number=Config.K8S_SERVICE_PORT
                                        )
                                    )
                                )
                            )]
                        )
                    )]
                )
            )

            self.networking_v1.create_namespaced_ingress(
                namespace=self.namespace, body=ingress
            )
            logger.info(f"创建Ingress: {ingress_name}, Host: {host}")
            return host
        except Exception as e:
            logger.warning(f"创建Ingress失败（可能是Ingress控制器未安装）: {e}")
            # Ingress创建失败不是致命错误
            return None


    def delete_runtime_resources(self, project_id: str) -> Dict[str, Any]:
        """
        删除运行时资源（Deployment, Service, Ingress），但不删除PVC
        """
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        results = {}
        errors = []

        # 删除Ingress（如果存在）
        ingress_name = self.generate_resource_name(project_id, "ingress")
        try:
            self.networking_v1.delete_namespaced_ingress(
                name=ingress_name, namespace=self.namespace
            )
            results["ingress"] = {"deleted": True, "name": ingress_name}
        except self.ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "ingress",
                    "name": ingress_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["ingress"] = {"deleted": False, "error": str(e)}

        # 删除Service
        svc_name = self.generate_resource_name(project_id, "svc")
        try:
            self.core_v1.delete_namespaced_service(
                name=svc_name, namespace=self.namespace
            )
            results["service"] = {"deleted": True, "name": svc_name}
        except self.ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "service",
                    "name": svc_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["service"] = {"deleted": False, "error": str(e)}

        # 删除Deployment
        deploy_name = self.generate_resource_name(project_id, "deploy")
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            results["deployment"] = {"deleted": True, "name": deploy_name}
        except self.ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "deployment",
                    "name": deploy_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["deployment"] = {"deleted": False, "error": str(e)}

        # 注意：不删除PVC，保留数据

        if errors:
            raise CodeServerError(
                message="删除Kubernetes运行时资源时发生错误",
                details={
                    "project_id": project_id,
                    "errors": errors,
                    "results": results
                },
                status_code=500
            )

        return results


    def delete_all_resources(self, project_id: str) -> Dict[str, Any]:
        """
        删除所有资源（包括PVC）
        """
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        results = {}
        errors = []

        # 先删除运行时资源
        try:
            runtime_results = self.delete_runtime_resources(project_id)
            results.update(runtime_results)
        except CodeServerError as e:
            # 记录错误但继续删除PVC
            errors.extend(e.details.get("errors", []))
            results.update(e.details.get("results", {}))

        # 删除PVC
        pvc_name = self.generate_resource_name(project_id, "pvc")
        try:
            self.core_v1.delete_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )
            results["pvc"] = {"deleted": True, "name": pvc_name}
        except self.ApiException as e:
            if e.status != 404:
                error_info = {
                    "resource": "pvc",
                    "name": pvc_name,
                    "error": str(e),
                    "status": e.status
                }
                errors.append(error_info)
                results["pvc"] = {"deleted": False, "error": str(e)}

        if errors:
            raise CodeServerError(
                message="删除Kubernetes资源时发生错误",
                details={
                    "project_id": project_id,
                    "errors": errors,
                    "results": results
                },
                status_code=500
            )

        return results


    def scale_deployment(self, project_id: str, replicas: int) -> bool:
        """调整Deployment副本数"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            deployment.spec.replicas = replicas
            self.apps_v1.replace_namespaced_deployment(
                name=deploy_name, namespace=self.namespace, body=deployment
            )
            logger.info(f"调整Deployment {deploy_name} 副本数为: {replicas}")
            return True
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"调整副本数失败: {e}")
            raise CodeServerError(
                message="调整Deployment副本数失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "replicas": replicas,
                    "error": str(e)
                },
                status_code=500
            )


    def get_deployment_status(self, project_id: str) -> Dict[str, Any]:
        """获取Deployment状态"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )

            # 获取Pod信息
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=code-server,project-id={project_id}"
            )

            pod_info = []
            for pod in pods.items[:3]:  # 最多显示3个pod
                pod_info.append({
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name
                })

            return {
                "name": deploy_name,
                "namespace": self.namespace,
                "replicas": getattr(deployment.status, 'replicas', 0) or getattr(deployment.status, 'replicas', 0) or 0,
                "ready_replicas": deployment.status.ready_replicas if deployment.status else 0,
                "available_replicas": deployment.status.available_replicas if deployment.status else 0,
                "pods": pod_info,
                "conditions": [
                    {
                        "type": cond.type,
                        "status": cond.status,
                        "reason": cond.reason,
                        "message": cond.message
                    }
                    for cond in (deployment.status.conditions if deployment.status else [])
                ]
            }
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取Deployment状态失败: {e}")
            raise CodeServerError(
                message="获取Deployment状态失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )


    def get_service_info(self, project_id: str) -> Dict[str, Any]:
        """获取Service信息"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_resource_name(project_id, "svc")

        try:
            service = self.core_v1.read_namespaced_service(
                name=svc_name, namespace=self.namespace
            )

            info = {
                "name": svc_name,
                "namespace": self.namespace,
                "type": service.spec.type,
                "cluster_ip": service.spec.cluster_ip,
                "ports": [
                    {
                        "name": port.name,
                        "port": port.port,
                        "target_port": port.target_port,
                        "node_port": port.node_port
                    }
                    for port in service.spec.ports
                ]
            }

            if service.status.load_balancer and service.status.load_balancer.ingress:
                info["load_balancer"] = []
                for ingress in service.status.load_balancer.ingress:
                    info["load_balancer"].append({
                        "ip": ingress.ip,
                        "hostname": ingress.hostname
                    })

            return info
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="Service不存在",
                    details={
                        "project_id": project_id,
                        "service_name": svc_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取Service信息失败: {e}")
            raise CodeServerError(
                message="获取Service信息失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e)
                },
                status_code=500
            )


    def get_pvc_status(self, project_id: str) -> Dict[str, Any]:
        """获取PVC状态"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        pvc_name = self.generate_resource_name(project_id, "pvc")

        try:
            pvc = self.core_v1.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=self.namespace
            )

            return {
                "name": pvc.metadata.name,
                "namespace": pvc.metadata.namespace,
                "storage_class": pvc.spec.storage_class_name,
                "status": pvc.status.phase,
                "capacity": pvc.status.capacity.get("storage") if pvc.status.capacity else None,
                "access_modes": pvc.spec.access_modes,
                "volume_name": pvc.spec.volume_name if hasattr(pvc.spec, 'volume_name') else None,
                "creation_timestamp": pvc.metadata.creation_timestamp
            }
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="PVC不存在",
                    details={
                        "project_id": project_id,
                        "pvc_name": pvc_name,
                        "error": str(e)
                    },
                    status_code=404
                )
            logger.error(f"获取PVC信息失败: {e}")
            raise CodeServerError(
                message="获取PVC信息失败",
                details={
                    "project_id": project_id,
                    "pvc_name": pvc_name,
                    "error": str(e)
                },
                status_code=500
            )

    # ==================== CodeWiki 相关方法 ====================

    def generate_codewiki_resource_name(self, project_id: str, resource_type: str) -> str:
        """生成CodeWiki资源名称"""
        short_id = project_id[:8]
        name = f"codewiki-{resource_type}-{short_id}".lower()
        name = re.sub(r'[^a-z0-9-]', '-', name)
        return name[:63].strip('-')

    def _get_codewiki_env_vars(self):
        """
        获取从YAML配置读取的CodeWiki配置环境变量

        Returns:
            包含V1EnvVar对象的列表
        """
        env_vars = []
        codewiki_config = get_codewiki_env_vars()

        for env_name, value in codewiki_config.items():
            env_vars.append(self.client.V1EnvVar(name=env_name, value=value))
            logger.info(f"CodeWiki配置: {env_name}={value[:20]}..." if len(value) > 20 else f"CodeWiki配置: {env_name}={value}")

        return env_vars

    def create_codewiki_deployment(self, project_id: str, pvc_name: str, api_key: str = None,
                                   cpu_limit: str = "1000m", memory_limit: str = "2048Mi") -> str:
        """创建CodeWiki Deployment"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_codewiki_resource_name(project_id, "deploy")

        try:
            deployment = self.client.V1Deployment(
                api_version="apps/v1",
                kind="Deployment",
                metadata=self.client.V1ObjectMeta(
                    name=deploy_name,
                    namespace=self.namespace,
                    labels={
                        "app": "codewiki",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1DeploymentSpec(
                    replicas=1,
                    selector=self.client.V1LabelSelector(
                        match_labels={"app": "codewiki", "project-id": project_id}
                    ),
                    template=self.client.V1PodTemplateSpec(
                        metadata=self.client.V1ObjectMeta(
                            labels={"app": "codewiki", "project-id": project_id}
                        ),
                        spec=self.client.V1PodSpec(
                            containers=[self.client.V1Container(
                                name="codewiki",
                                image=Config.K8S_CODEWIKI_IMAGE,
                                image_pull_policy=Config.K8S_CODEWIKI_PULL_POLICY,
                                ports=[self.client.V1ContainerPort(container_port=Config.K8S_CODEWIKI_CONTAINER_PORT)],
                                # 从文件读取CodeWiki配置（必需的环境变量）
                                env=[
                                    # 基础环境变量
                                    self.client.V1EnvVar(name="PROJECT_ID", value=project_id),
                                    self.client.V1EnvVar(name="PUID", value="1000"),
                                    self.client.V1EnvVar(name="PGID", value="1000"),
                                    self.client.V1EnvVar(name="TZ", value="Asia/Shanghai"),
                                    self.client.V1EnvVar(name="ROOT_PATH", value="/codewiki"),
                                ] + self._get_codewiki_env_vars() + [
                                    self.client.V1EnvVar(name=key, value=value)
                                    for key, value in get_dynamic_env_vars("codewiki").items()
                                ],
                                volume_mounts=[self.client.V1VolumeMount(
                                    name="workspace",
                                    mount_path="/config/workspace"
                                )],
                                resources=self.client.V1ResourceRequirements(
                                    requests={
                                        "cpu": "500m",
                                        "memory": "1024Mi"
                                    },
                                    limits={
                                        "cpu": cpu_limit,
                                        "memory": memory_limit
                                    }
                                ),
                                readiness_probe=self.client.V1Probe(
                                    http_get=self.client.V1HTTPGetAction(
                                        path="/codewiki/health",
                                        port=Config.K8S_CODEWIKI_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=10,
                                    period_seconds=5,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                ),
                                liveness_probe=self.client.V1Probe(
                                    http_get=self.client.V1HTTPGetAction(
                                        path="/codewiki/health",
                                        port=Config.K8S_CODEWIKI_CONTAINER_PORT,
                                        scheme="HTTP"
                                    ),
                                    initial_delay_seconds=30,
                                    period_seconds=10,
                                    timeout_seconds=1,
                                    success_threshold=1,
                                    failure_threshold=3
                                )
                            )],
                            volumes=[self.client.V1Volume(
                                name="workspace",
                                persistent_volume_claim=self.client.V1PersistentVolumeClaimVolumeSource(
                                    claim_name=pvc_name
                                )
                            )]
                        )
                    )
                )
            )

            self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace, body=deployment
            )
            logger.info(f"创建CodeWiki Deployment: {deploy_name}")
            return deploy_name
        except self.ApiException as e:
            if e.status == 409:
                logger.warning(f"CodeWiki Deployment已存在: {deploy_name}")
                return deploy_name
            logger.error(f"创建CodeWiki Deployment失败: {e}")
            raise CodeServerError(
                message="创建CodeWiki Deployment失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )

    def create_codewiki_service(self, project_id: str) -> Dict[str, Any]:
        """创建CodeWiki Service"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_codewiki_resource_name(project_id, "svc")

        try:
            service = self.client.V1Service(
                metadata=self.client.V1ObjectMeta(
                    name=svc_name,
                    namespace=self.namespace,
                    labels={
                        "app": "codewiki",
                        "project-id": project_id,
                        "managed-by": "source-manager"
                    }
                ),
                spec=self.client.V1ServiceSpec(
                    type=Config.K8S_SERVICE_TYPE,
                    selector={"app": "codewiki", "project-id": project_id},
                    ports=[self.client.V1ServicePort(
                        port=Config.K8S_CODEWIKI_SERVICE_PORT,
                        target_port=Config.K8S_CODEWIKI_CONTAINER_PORT,
                        name="http"
                    )]
                )
            )

            svc = self.core_v1.create_namespaced_service(namespace=self.namespace, body=service)
            logger.info(f"创建CodeWiki Service: {svc_name}")

            access_info = {
                "name": svc_name,
                "port": Config.K8S_CODEWIKI_SERVICE_PORT,
                "type": Config.K8S_SERVICE_TYPE
            }

            if Config.K8S_SERVICE_TYPE == "ClusterIP":
                access_info["cluster_ip"] = svc.spec.cluster_ip
                access_info["url"] = f"http://{svc_name}.{self.namespace}.svc.cluster.local:{Config.K8S_CODEWIKI_SERVICE_PORT}/codewiki"

            return access_info
        except self.ApiException as e:
            if e.status == 409:
                logger.warning(f"CodeWiki Service已存在: {svc_name}")
                return {"name": svc_name}
            logger.error(f"创建CodeWiki Service失败: {e}")
            raise CodeServerError(
                message="创建CodeWiki Service失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e)
                },
                status_code=500
            )

    def delete_codewiki_runtime_resources(self, project_id: str) -> Dict[str, Any]:
        """删除CodeWiki运行时资源（Deployment, Service），但不删除PVC"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        results = {}
        errors = []

        # 删除Service
        svc_name = self.generate_codewiki_resource_name(project_id, "svc")
        try:
            self.core_v1.delete_namespaced_service(
                name=svc_name, namespace=self.namespace
            )
            results["service"] = {"deleted": True, "name": svc_name}
        except self.ApiException as e:
            if e.status != 404:
                errors.append({"resource": "service", "name": svc_name, "error": str(e), "status": e.status})
                results["service"] = {"deleted": False, "error": str(e)}

        # 删除Deployment
        deploy_name = self.generate_codewiki_resource_name(project_id, "deploy")
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            results["deployment"] = {"deleted": True, "name": deploy_name}
        except self.ApiException as e:
            if e.status != 404:
                errors.append({"resource": "deployment", "name": deploy_name, "error": str(e), "status": e.status})
                results["deployment"] = {"deleted": False, "error": str(e)}

        if errors:
            raise CodeServerError(
                message="删除CodeWiki Kubernetes资源时发生错误",
                details={
                    "project_id": project_id,
                    "errors": errors,
                    "results": results
                },
                status_code=500
            )

        return results

    def scale_codewiki_deployment(self, project_id: str, replica: int) -> bool:
        """调整CodeWiki Deployment副本数"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_codewiki_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )
            deployment.spec.replica = replica
            self.apps_v1.replace_namespaced_deployment(
                name=deploy_name, namespace=self.namespace, body=deployment
            )
            logger.info(f"调整CodeWiki Deployment {deploy_name} 副本数为: {replica}")
            return True
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="CodeWiki Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name
                    },
                    status_code=404
                )
            logger.error(f"调整CodeWiki Deployment副本数失败: {e}")
            raise CodeServerError(
                message="调整CodeWiki Deployment副本数失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "replica": replica,
                    "error": str(e)
                },
                status_code=500
            )

    def get_codewiki_deployment_status(self, project_id: str) -> Dict[str, Any]:
        """获取CodeWiki Deployment状态"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        deploy_name = self.generate_codewiki_resource_name(project_id, "deploy")

        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deploy_name, namespace=self.namespace
            )

            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=codewiki,project-id={project_id}"
            )

            pod_info = []
            for pod in pods.items[:3]:
                pod_info.append({
                    "name": pod.metadata.name,
                    "status": pod.status.phase,
                    "ip": pod.status.pod_ip,
                    "node": pod.spec.node_name
                })

            return {
                "name": deploy_name,
                "namespace": self.namespace,
                "replica": getattr(deployment.status, 'replica', 0) or getattr(deployment.status, 'replicas', 0) or 0,
                "ready_replica": deployment.status.ready_replica if deployment.status else 0,
                "available_replica": deployment.status.available_replica if deployment.status else 0,
                "pods": pod_info,
                "conditions": [
                    {
                        "type": cond.type,
                        "status": cond.status,
                        "reason": cond.reason,
                        "message": cond.message
                    }
                    for cond in (deployment.status.conditions if deployment.status else [])
                ]
            }
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="CodeWiki Deployment不存在",
                    details={
                        "project_id": project_id,
                        "deployment_name": deploy_name
                    },
                    status_code=404
                )
            logger.error(f"获取CodeWiki Deployment状态失败: {e}")
            raise CodeServerError(
                message="获取CodeWiki Deployment状态失败",
                details={
                    "project_id": project_id,
                    "deployment_name": deploy_name,
                    "error": str(e)
                },
                status_code=500
            )

    def get_codewiki_service_info(self, project_id: str) -> Dict[str, Any]:
        """获取CodeWiki Service信息"""
        if not self.available:
            raise CodeServerError(
                message="Kubernetes客户端不可用",
                details={"project_id": project_id},
                status_code=503
            )

        svc_name = self.generate_codewiki_resource_name(project_id, "svc")

        try:
            service = self.core_v1.read_namespaced_service(
                name=svc_name, namespace=self.namespace
            )

            info = {
                "name": svc_name,
                "namespace": self.namespace,
                "type": service.spec.type,
                "cluster_ip": service.spec.cluster_ip,
                "ports": [
                    {
                        "name": port.name,
                        "port": port.port,
                        "target_port": port.target_port,
                        "node_port": port.node_port
                    }
                    for port in service.spec.ports
                ]
            }
            return info
        except self.ApiException as e:
            if e.status == 404:
                raise CodeServerError(
                    message="CodeWiki Service不存在",
                    details={
                        "project_id": project_id,
                        "service_name": svc_name
                    },
                    status_code=404
                )
            logger.error(f"获取CodeWiki Service信息失败: {e}")
            raise CodeServerError(
                message="获取CodeWiki Service信息失败",
                details={
                    "project_id": project_id,
                    "service_name": svc_name,
                    "error": str(e)
                },
                status_code=500
            )