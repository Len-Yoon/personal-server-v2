ARG POSTGRES_BASE
FROM ${POSTGRES_BASE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY tools/data_backup /opt/data_backup
COPY tools/data_image/init_roles.py /opt/init_roles.py
COPY tools/data_image/init.sh /docker-entrypoint-initdb.d/10-v2.sh
RUN chmod 755 /docker-entrypoint-initdb.d/10-v2.sh
USER 999:999
