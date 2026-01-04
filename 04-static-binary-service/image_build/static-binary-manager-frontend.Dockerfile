# 构建阶段
FROM node:20-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制 package.json
COPY package*.json ./

# 智能安装依赖：如果有 package-lock.json 则用 npm ci，否则用 npm install
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# 复制源代码
COPY . .

# 构建应用
RUN npm run build

# 运行阶段 - 使用nginx
FROM nginx:alpine

# 复制nginx配置文件
# COPY nginx.conf /etc/nginx/nginx.conf

# 从构建阶段复制构建产物，并修改权限
COPY --from=builder --chown=nginx:nodejs /app/dist /usr/share/nginx/html

# 暴露80端口
EXPOSE 80

# 启动nginx
CMD ["nginx", "-g", "daemon off;"]