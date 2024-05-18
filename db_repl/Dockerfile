#Используем базовый образ с PostgreSQL
FROM postgres:latest
# Устанавливаем переменную среды для задания пароля для пользователя по умолчанию
ENV POSTGRES_PASSWORD kali

EXPOSE $DB_PORT
# Создание файла pgpass
RUN echo "db:5432:*:replicator:repl_password" > /var/lib/postgresql/.pgpass

RUN chown postgres:postgres /var/lib/postgresql/.pgpass
RUN chmod 600 /var/lib/postgresql/.pgpass

CMD ["bash", "-c", "rm -rf /var/lib/postgresql/data/* && while ! pg_isready -h db -p 5432 -U postgres; do sleep 1; done && su - postgres -c 'pg_basebackup -h db -U replicator -D /var/lib/postgresql/data -P -R'"]
