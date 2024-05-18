from telegram.ext import Updater, CommandHandler, MessageHandler, ConversationHandler, Filters
import logging
import paramiko
import re
import psycopg2
from psycopg2 import sql
import os

# Включаем logging
logging.basicConfig(filename='bot.log', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Данные для SSH-подключения
SSH_HOST = os.environ['RM_HOST']
SSH_PORT = os.environ['RM_PORT']
SSH_USERNAME = os.environ['RM_USER']
SSH_PASSWORD = os.environ['RM_PASSWORD']

# Регулярное выражение для поиска email-адресов
EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Регулярное выражение для поиска номеров телефонов
PHONE_REGEX = r'\+?7[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|\+?7[ -]?\d{10}|\+?7[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}|8[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}|8[ -]?\d{10}|8[ -]?\d{3}[ -]?\d{3}[ -]?\d{4}'

# Регулярное выражение для проверки сложности пароля
PASSWORD_REGEX = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$'

CHOOSING = 1

# Функция для установки SSH-подключения
def establish_ssh_connection():
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=SSH_HOST, port=SSH_PORT, username=SSH_USERNAME, password=SSH_PASSWORD)
    return ssh_client

# Функция для выполнения команды по SSH и возврата результата
def execute_ssh_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    return output if not error else error

# Функция проверки сложности пароля
def verify_password(password):
    if re.match(PASSWORD_REGEX, password):
        return 'Пароль сложный'
    else:
        return 'Пароль простой'

# Команда: /find_email
def find_email(update, context):
    context.user_data['search_type'] = 'email-адреса'
    update.message.reply_text('Отправьте мне текст, в котором нужно найти email-адреса.')
    return CHOOSING

# Команда: /find_phone_number
def find_phone_number(update, context):
    context.user_data['search_type'] = 'номера телефонов'
    update.message.reply_text('Отправьте мне текст, в котором нужно найти номера телефонов.')
    return CHOOSING

# Функция для поиска email-адресов
def find_emails(text):
    return re.findall(EMAIL_REGEX, text)

# Функция для поиска номеров телефонов
def find_phone_numbers(text):
    return re.findall(PHONE_REGEX, text)


# Функция обработки введенного пользователем пароля для проверки сложности
def verify_password_text(update, context):
    password = update.message.text
    result = verify_password(password)
    update.message.reply_text(result)

def verify_password_command(update, context):
    update.message.reply_text('Введите пароль для проверки сложности.')
    context.user_data['search_type'] = 'пароль'


# Команда: /get_release
def get_release(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'lsb_release -a')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_uname
def get_uname(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'uname -a')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_uptime
def get_uptime(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'uptime')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_df
def get_df(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'df -h')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_free
def get_free(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'free -h')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_mpstat
def get_mpstat(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'mpstat')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_w
def get_w(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'w')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_auths
def get_auths(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'last -n 10')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_critical
def get_critical(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'journalctl -p crit -n 5')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_ps
def get_ps(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'ps aux | head -n 11')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_ss
def get_ss(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'ss -tuln')
    update.message.reply_text(output)
    ssh_client.close()

# Команда: /get_services
def get_services(update, context):
    ssh_client = establish_ssh_connection()
    output = execute_ssh_command(ssh_client, 'service --status-all')
    update.message.reply_text(output)
    ssh_client.close()

# Обработчик для команды /get_apt_list
def get_apt_list(update, context):
    update.message.reply_text('Хотите вывести все пакеты? Ответьте "да" или "нет".')
    return CHOOSING

# Обработчик для ответа пользователя на запрос вывода всех пакетов
def handle_apt_list_request(update, context):
    user_reply = update.message.text.lower()
    if user_reply == 'да':
        # Вывод всех пакетов
        ssh_client = establish_ssh_connection()
        output = execute_ssh_command(ssh_client, 'dpkg -l | head -n 11')
        update.message.reply_text(output)
        ssh_client.close()
        context.user_data.clear()  # Очищаем данные пользователя
        return ConversationHandler.END
    elif user_reply == 'нет':
        # Запрос имени пакета для поиска
        update.message.reply_text('Хорошо, введите имя пакета для поиска.')
        return CHOOSING
    else:
        # Ищем пакет по введенному имени
        ssh_client = establish_ssh_connection()
        output = execute_ssh_command(ssh_client, f'dpkg -l | grep {user_reply}')
        update.message.reply_text(output)
        ssh_client.close()
        context.user_data.clear()  # Очищаем данные пользователя
        return ConversationHandler.END

def cancel(update, context):
    update.message.reply_text('Операция отменена.')
    context.user_data.clear()  # Очищаем данные пользователя
    return ConversationHandler.END

# Команда: /get_repl_logs
def get_repl_logs(update, context):
    # Путь к файлу с логами PostgreSQL
    LOG_FILE_PATH = '/app/logs/postgresql.log'

    try:
        # Читаем содержимое файла
        log_contents = os.popen("grep replication /app/logs/postgresql.log | head -n 30").read()
        update.message.reply_text(log_contents)
    except FileNotFoundError:
        update.message.reply_text('Файл с логами репликации не найден.')
    except Exception as e:
        update.message.reply_text(f'Произошла ошибка при чтении логов репликации: {str(e)}')

# Функция для выполнения SQL-запроса к базе данных PostgreSQL
def execute_sql_query(sql_query):
    conn = psycopg2.connect(
    dbname=os.environ['DB_DATABASE'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD'],
    host="db",
    port="5432"
    )
    # Создание курсора
    cur = conn.cursor()
    # Выполнение SQL-запроса
    cur.execute(sql_query)
    # Если запрос на чтение данных, возвращаем результаты
    if sql_query.strip().lower().startswith("select"):
        results = cur.fetchall()
        cur.close()
        conn.close()
        return results
    
# Команда: /get_emails
def get_emails(update, context):
    # SQL-запрос для получения всех email-адресов из таблицы emails
    sql_query = "SELECT email FROM emails;"
    # Выполнение SQL-запроса
    results = execute_sql_query(sql_query)
    # Отправка результатов в чат
    if results:
        emails = [row[0] for row in results]
        update.message.reply_text("Список email-адресов:\n" + "\n".join(emails))
    else:
        update.message.reply_text("В таблице нет email-адресов.")

# Команда: /get_phone_numbers
def get_phone_numbers(update, context):
    # SQL-запрос для получения всех номеров телефонов из таблицы phone_numbers
    sql_query = "SELECT phone_number FROM phone_numbers;"
    # Выполнение SQL-запроса
    results = execute_sql_query(sql_query)
    # Отправка результатов в чат
    if results:
        phone_numbers = [row[0] for row in results]
        update.message.reply_text("Список номеров телефонов:\n" + "\n".join(phone_numbers))
    else:
        update.message.reply_text("В таблице нет номеров телефонов.")


# Функция для записи найденных email-адресов в базу данных
def save_emails_to_database(update, context, emails):
    try:
        conn = psycopg2.connect(
        dbname=os.environ['DB_DATABASE'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        host="db",
        port="5432"
        )
        cur = conn.cursor()
        for email in emails:
            cur.execute(
                sql.SQL("INSERT INTO emails (email) VALUES (%s)"),
                [email]
            )
        conn.commit()
        cur.close()
        conn.close()
        update.message.reply_text("Email-адреса успешно сохранены в базе данных.")
    except Exception as e:
        update.message.reply_text(f"Ошибка при сохранении в базу данных: {str(e)}")

# Функция для записи найденных номеров телефонов в базу данных
def save_phone_numbers_to_database(update, context, phone_numbers):
    try:
        conn = psycopg2.connect(
        dbname=os.environ['DB_DATABASE'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        host="db",
        port="5432"
        )
        cur = conn.cursor()
        for phone_number in phone_numbers:
            cur.execute(
                sql.SQL("INSERT INTO phone_numbers (phone_number) VALUES (%s)"),
                [phone_number]
            )
        conn.commit()
        cur.close()
        conn.close()
        update.message.reply_text("Номера телефонов успешно сохранены в базе данных.")
    except Exception as e:
        update.message.reply_text(f"Ошибка при сохранении в базу данных: {str(e)}")

def process_found_emails(update, context, emails):
    context.user_data['search_type'] = 'email-адреса'  # Обновляем значение search_type
    if emails:
        update.message.reply_text(f"Найденные email-адреса: {', '.join(emails)}")
        context.user_data['found_emails'] = emails
        update.message.reply_text("Хотите сохранить найденные email-адреса в базе данных? Ответьте 'да' или 'нет'.")
    else:
        handle_save_response(update, context)

def process_found_phone_numbers(update, context, phone_numbers):
    context.user_data['search_type'] = 'номера телефонов'  # Обновляем значение search_type
    if phone_numbers:
        update.message.reply_text(f"Найденные номера телефонов: {', '.join(phone_numbers)}")
        context.user_data['found_phone_numbers'] = phone_numbers
        update.message.reply_text("Хотите сохранить найденные номера телефонов в базе данных? Ответьте 'да' или 'нет'.")
    else:
        handle_save_response(update, context)


# Обработчик ответа пользователя о сохранении данных в базе данных
def handle_save_response(update, context):
    user_reply = update.message.text.lower()
    search_type = context.user_data.get('search_type')

    if user_reply == 'да':
        if search_type == 'email-адреса':
            found_emails = context.user_data.get('found_emails')
            if found_emails:
                save_emails_to_database(update, context, found_emails)
            else:
                update.message.reply_text("Нет email-адресов для сохранения.")
        elif search_type == 'номера телефонов':
            found_phone_numbers = context.user_data.get('found_phone_numbers')
            if found_phone_numbers:
                save_phone_numbers_to_database(update, context, found_phone_numbers)
            else:
                update.message.reply_text("Нет номеров телефонов для сохранения.")
    elif user_reply == 'нет':
        update.message.reply_text('Данные не будут сохранены в базе данных.')

    if user_reply not in ['да', 'нет']:
        # Обрабатываем случай, когда в ответе не 'да' или 'нет'
        update.message.reply_text("Пожалуйста, ответьте 'да' или 'нет'.")        
    if context.user_data.get('search_type') == 'email-адреса' and not found_emails:
        update.message.reply_text('В тексте не найдены email-адреса.')
    elif context.user_data.get('search_type') == 'номера телефонов' and not found_phone_numbers:
        update.message.reply_text('В тексте не найдены номера телефонов.')

def echo(update, context):
    search_type = context.user_data.get('search_type')
    if search_type:
        if search_type == 'email-адреса':
            emails = find_emails(update.message.text)
            process_found_emails(update, context, emails)
        elif search_type == 'номера телефонов':
            phone_numbers = find_phone_numbers(update.message.text)
            process_found_phone_numbers(update, context, phone_numbers)
        elif search_type == 'пароль':
            verify_password_text(update,context)
    else:
        update.message.reply_text('Запрос некорректный.')

def start(update, context):
    update.message.reply_text( "Привет! Я бот для поиска email-адресов, номеров телефонов, проверки сложности пароля, "
        "мониторинга Linux системы и просмотра базы данных.\n\n"
        "Выберите одну из следующих команд:\n\n"
        "1. /find_email - Найти email-адреса в тексте\n"
        "2. /find_phone_number - Найти номера телефонов в тексте\n"
        "3. /verify_password - Проверить сложность пароля\n\n"
        "Используйте команды для мониторинга Linux:\n\n"
        "4. /get_release - Получить информацию о версии операционной системы\n"
        "5. /get_uname - Получить информацию о системе\n"
        "6. /get_uptime - Получить информацию о времени работы системы\n"
        "7. /get_df - Получить информацию о дисковом пространстве\n"
        "8. /get_free - Получить информацию о доступной памяти\n"
        "9. /get_mpstat - Получить информацию о процессоре\n"
        "10. /get_w - Получить информацию о пользователях системы\n"
        "11. /get_auths - Получить информацию о последних авторизациях\n"
        "12. /get_critical - Получить информацию о критических событиях в журналах\n"
        "13. /get_ps - Получить информацию о запущенных процессах\n"
        "14. /get_ss - Получить информацию о сетевых соединениях\n"
        "15. /get_apt_list - Получить список установленных пакетов\n"
        "16. /get_services - Получить статус служб на системе\n"
        "17. /get_repl_logs - Получить логи репликации PostgreSQL\n"
        "Или используйте следующие команды для просмотра базы данных:\n"
        "18. /get_emails - Получить список email-адресов из базы данных\n"
        "19. /get_phone_numbers - Получить список номеров телефонов из базы данных\n")


def main():
    token = os.environ['TOKEN']
    updater = Updater(token, use_context=True)

    dp = updater.dispatcher

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list)],
        states={
            CHOOSING: [MessageHandler(Filters.text & ~Filters.command, handle_apt_list_request)]
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("find_email", find_email))
    dp.add_handler(CommandHandler("find_phone_number", find_phone_number))
    dp.add_handler(CommandHandler("verify_password", verify_password_command))
    dp.add_handler(CommandHandler("get_release", get_release))
    dp.add_handler(CommandHandler("get_uname", get_uname))
    dp.add_handler(CommandHandler("get_uptime", get_uptime))
    dp.add_handler(CommandHandler("get_df", get_df))
    dp.add_handler(CommandHandler("get_free", get_free))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat))
    dp.add_handler(CommandHandler("get_w", get_w))
    dp.add_handler(CommandHandler("get_auths", get_auths))
    dp.add_handler(CommandHandler("get_critical", get_critical))
    dp.add_handler(CommandHandler("get_ps", get_ps))
    dp.add_handler(CommandHandler("get_ss", get_ss))
    dp.add_handler(CommandHandler("get_services", get_services))
    dp.add_handler(conv_handler)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command & Filters.regex(PASSWORD_REGEX), verify_password_text))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    dp.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))

    conv_handler = ConversationHandler(
    entry_points=[CommandHandler('find_email', find_email), CommandHandler('find_phone_number', find_phone_number)],
    states={
        CHOOSING: [MessageHandler(Filters.text & ~Filters.command, handle_save_response)]
    },
    fallbacks=[]
    )
    
    updater.start_polling()

    updater.idle()

if __name__ == '__main__':
    main()
