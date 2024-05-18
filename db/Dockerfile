# Используем базовый образ с PostgreSQL
FROM postgres:latest
# Устанавливаем переменную среды для задания пароля для пользователя по умолчанию
ENV POSTGRES_PASSWORD kali

EXPOSE $DB_PORT
# Копируем исходный SQL-скрипт внутрь контейнера
#COPY ./init.sql /docker-entrypoint-initdb.d/
COPY ./init.sh /docker-entrypoint-initdb.d/

# Изменяем права доступа к файлу SQL-скрипта, чтобы он мог быть выполнен при инициализации базы данне
RUN chmod a+r /docker-entrypoint-initdb.d/*
RUN chmod +x /docker-entrypoint-initdb.d/init.sh

RUN mkdir -p /var/log/postgresql && \
    chown -R postgres:postgres /var/log/postgresql && \
    chmod 777 /var/log/postgresql

RUN mkdir -p /oracle/pg_data/archive/
RUN chmod -R 777 /oracle/pg_data

CMD ["postgres", "-c", "port=5432", "-c", "listen_addresses=*", \
       "-c", "archive_mode=on", "-c", "archive_command=cp %p /oracle/pg_data/archive/%f", \
       "-c", "max_wal_senders=10", "-c", "wal_level=replica", \
       "-c", "wal_log_hints=on", "-c", "log_replication_commands=on", \
       "-c", "logging_collector=on", "-c", "log_directory=/var/log/postgresql/", \
       "-c", "log_filename=postgresql.log"]
