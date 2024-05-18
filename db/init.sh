#!/bin/bash

set -e

# Добавление строки в файл pg_hba.conf для разрешения подключений для репликации
echo "host replication replicator all scram-sha-256" >> /var/lib/postgresql/data/pg_hba.conf

psql -v ON_ERROR_STOP=1 --username "$DB_USER" --dbname "$DB_DATABASE" <<-EOSQL
    ALTER USER "$DB_USER" WITH PASSWORD '$DB_PASSWORD';
    CREATE ROLE "$DB_REPL_USER" REPLICATION LOGIN PASSWORD '$DB_REPL_PASSWORD';
    CREATE TABLE emails( id serial PRIMARY KEY,email VARCHAR (100) NOT NULL);
    CREATE TABLE phone_numbers( id serial PRIMARY KEY,phone_number VARCHAR (20) NOT NULL);
    INSERT INTO emails (email) VALUES ('example1@example.com');
    INSERT INTO emails (email) VALUES ('example2@example.com');
    INSERT INTO phone_numbers (phone_number) VALUES ('+79123456789');
    INSERT INTO phone_numbers (phone_number) VALUES ('+79876543210');

EOSQL

exec "$@"
