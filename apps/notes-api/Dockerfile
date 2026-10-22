# linux/arm64 실습 빌드의 Python 기반 이미지를 digest로 고정함.
ARG PYTHON_BASE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
FROM ${PYTHON_BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app.py /app/app.py
USER 10001:10001
EXPOSE 8000
CMD ["python", "app.py", "serve"]
