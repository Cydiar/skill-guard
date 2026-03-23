FROM python:3.12-slim

# Install git for clone tasks
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先复制依赖文件，利用层缓存加速重复构建
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

EXPOSE 8011

# 默认启动 API 服务（生产模式，无 --reload）
# worker 服务通过 docker-compose command 覆盖此指令
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8011"]
