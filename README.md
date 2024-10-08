<h3> Код для анализа логов веб-сервера IIS, сохраненных в базе данных PostgreSQL. </h3>

Он выполняет несколько задач: <br />
- Вставка логов в таблицу
- Анализ данных по различным критериям (с помощью запросов к бд)
- Сохранение результатов в Excel-файлы

Описание функциональности:<br />
1.Работа с базой данных:<br />
- Код использует SQLAlchemy для подключения к базе данных PostgreSQL.<br />
- В базе данных создается таблица `iis_logs`, которая содержит поля для хранения информации IIS.<br />

2.Вставка логов из текстового файла:
- Функция `insert_logs_from_text` - чтение логов из текстового файла построчно.
- Она обрабатывает данные, игнорирует "побочную" информацию (строки, начинающиеся с "#") и пустые строки, а затем вставляет каждую запись в таблицу `iis_logs`.

3.Функции анализа данных:
- `analyze_failed_logins()`: анализ неудачных попыток входа в систему (статусы 401 и 403).
- `analyze_suspicious_requests()`: поиск подозрительных запросов (например, с наличием символов `<`, `>` или `'` в URI).
- `analyze_admin_access()`: анализ доступа к административным страницам (по URI, начинающимся с `/admin` или `/dashboard`).
- `analyze_phishing_attempts()`: поиск страниц входа и регистрации для выявления фишинговых попыток.
- `analyze_ddos()`: анализ потенциальных DDoS-атак на основе количества запросов от одного IP за последний час.

4.Сохранение результатов анализа:
- Результаты каждого анализа сохраняются в отдельный Excel-файл с помощью функции `save_query`.

Что можно поправить:
- Если формат логов в текстовом файле отличается от предполагаемого (например, если поля разделены не пробелами, а другими символами).
- Добавить логирование действий программы (успешные вставки, ошибки, результаты анализа) для более удобного мониторинга работы.

