-- 创建数据库
CREATE DATABASE IF NOT EXISTS source_manager
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE source_manager;

-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
                                     id INT AUTO_INCREMENT PRIMARY KEY,
                                     username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    hashed_password VARCHAR(200) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
    );

-- 创建项目表
CREATE TABLE IF NOT EXISTS projects (
                                        id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    original_filename VARCHAR(500),
    archive_path VARCHAR(500),
    extract_path VARCHAR(500),
    file_count INT DEFAULT 0,
    total_size BIGINT DEFAULT 0,
    archive_size BIGINT DEFAULT 0,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_name (name),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

-- 创建项目文件表
CREATE TABLE IF NOT EXISTS project_files (
                                             id INT AUTO_INCREMENT PRIMARY KEY,
                                             project_id VARCHAR(64) NOT NULL,
    file_path VARCHAR(1000) NOT NULL,
    file_name VARCHAR(300) NOT NULL,
    file_size BIGINT DEFAULT 0,
    file_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_project_id (project_id),
    INDEX idx_file_name (file_name),
    INDEX idx_project_file (project_id, file_name),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );

-- 创建code-server表
CREATE TABLE IF NOT EXISTS code_servers (
                                            id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    deployment_name VARCHAR(100),
    service_name VARCHAR(100),
    pvc_name VARCHAR(100),
    service_ip VARCHAR(100),
    service_port INT,
    access_url VARCHAR(500),
    status ENUM('pending', 'creating', 'running', 'error', 'deleting', 'stopped') DEFAULT 'pending',
    pod_name VARCHAR(100),
    pod_status VARCHAR(50),
    node_name VARCHAR(100),
    password_hash VARCHAR(200),
    cpu_request VARCHAR(20) DEFAULT '500m',
    cpu_limit VARCHAR(20) DEFAULT '1000m',
    memory_request VARCHAR(20) DEFAULT '512Mi',
    memory_limit VARCHAR(20) DEFAULT '1024Mi',
    storage_size VARCHAR(20) DEFAULT '5Gi',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL,
    stopped_at TIMESTAMP NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_project_id (project_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
    );

-- 创建管理员用户（初始密码：admin123）
INSERT IGNORE INTO users (username, email, hashed_password, is_superuser)
VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
    TRUE
);