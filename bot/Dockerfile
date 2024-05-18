# Используем базовый образ Python
FROM python:3.8-slim

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Копируем файлы проекта в контейнер
WORKDIR /app
COPY . .

RUN mkdir -p /app/logs && \
    chmod 777 /app/logs

# Устанавливаем зависимости Python
RUN pip install --no-cache-dir -r requirements.txt

# Устанавливаем переменную окружения для логирования
ENV LOG_FILE_PATH="/app/bot.log"

# Команда для запуска бота
CMD ["python", "bot.py"]
