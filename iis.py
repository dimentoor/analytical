import pandas as pd
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, TIMESTAMP, BigInteger
import auth

DB_USER = auth.DB_USER
DB_PASSWORD = auth.DB_PASSWORD
DB_HOST = auth.DB_HOST
DB_PORT = auth.DB_PORT
DB_NAME = auth.DB_NAME

# database connection
engine = create_engine(f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')
metadata = MetaData()

# create table iis_logs
iis_logs = Table('iis_logs', metadata,
                 Column('id', Integer, primary_key=True, autoincrement=True),
                 Column('log_date', TIMESTAMP),
                 Column('c_ip', String(15)),
                 Column('cs_username', String(100)),
                 Column('cs_method', String(10)),
                 Column('cs_uri_stem', String(255)),
                 Column('cs_uri_query', String(255)),
                 Column('sc_status', Integer),
                 Column('sc_bytes', BigInteger),
                 Column('cs_bytes', BigInteger),
                 Column('cs_user_agent', String(255))
                 )

# create table in database
metadata.create_all(engine)


# add logs
# row - log, divided into parts, each of which corresponds to fields of the table
def insert_logs_from_text(file_path):
    with engine.connect() as connection:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                # skip "#" and "null string"
                if not line or line.startswith('#'):
                    continue

                data = line.split()
                log_date = data[0]
                c_ip = data[1]
                cs_username = data[2]
                cs_method = data[3]
                cs_uri_stem = data[4]
                cs_uri_query = data[5]
                sc_status = int(data[6])
                sc_bytes = int(data[7])
                cs_bytes = int(data[8])
                cs_user_agent = data[9]

                insert_query = iis_logs.insert().values(
                    log_date=log_date,
                    c_ip=c_ip,
                    cs_username=cs_username,
                    cs_method=cs_method,
                    cs_uri_stem=cs_uri_stem,
                    cs_uri_query=cs_uri_query,
                    sc_status=sc_status,
                    sc_bytes=sc_bytes,
                    cs_bytes=cs_bytes,
                    cs_user_agent=cs_user_agent
                )
                connection.execute(insert_query)


# executing SQL queries
def fetch_data(query):
    with engine.connect() as connection:
        df = pd.read_sql(query, connection)
    return df


# save .xlsx
def save_query(file_name, df):
    output_file = f'{file_name}.xlsx'
    df.to_excel(output_file, index=False)
    print(f"Результат сохранен в {output_file}")


# 1. Анализ неудачных попыток входа в систему
def analyze_failed_logins():
    query = """
    SELECT log_date, c_ip, cs_username, cs_uri_stem, sc_status
    FROM iis_logs
    WHERE sc_status IN (401, 403)
    ORDER BY log_date DESC;
    """
    df = fetch_data(query)
    print("Неудачные попытки входа:")
    print(df)
    return df


# 2. Поиск подозрительных запросов
def analyze_suspicious_requests():
    query = """
    SELECT log_date, c_ip, cs_uri_stem, cs_uri_query
    FROM iis_logs
    WHERE cs_uri_query LIKE '%<%' OR cs_uri_query LIKE '%>%' OR cs_uri_query LIKE '%\'%'
    ORDER BY log_date DESC;
    """
    df = fetch_data(query)
    print("Подозрительные запросы:")
    print(df)
    return df


# 3. Анализ использования административных привилегий
def analyze_admin_access():
    query = """
    SELECT log_date, c_ip, cs_username, cs_uri_stem
    FROM iis_logs
    WHERE cs_uri_stem LIKE '/admin%' OR cs_uri_stem LIKE '/dashboard%'
    ORDER BY log_date DESC;
    """
    df = fetch_data(query)
    print("Доступ к административным страницам:")
    print(df)
    return df


# 4. Поиск фишинговых страниц
def analyze_phishing_attempts():
    query = """
    SELECT log_date, c_ip, cs_username, cs_uri_stem
    FROM iis_logs
    WHERE cs_uri_stem LIKE '/login%' OR cs_uri_stem LIKE '/signup%'
    ORDER BY log_date DESC;
    """
    df = fetch_data(query)
    print("Фишинговые страницы:")
    print(df)
    return df


# 5. Анализ DDoS-атак
def analyze_ddos():
    query = """
    SELECT c_ip, COUNT(*) AS request_count, SUM(cs_bytes) AS total_bytes
    FROM iis_logs
    WHERE log_date >= NOW() - INTERVAL '1 hour'
    GROUP BY c_ip
    HAVING COUNT(*) > 1000
    ORDER BY request_count DESC;
    """
    df = fetch_data(query)
    print("Возможные DDoS атаки:")
    print(df)
    return df


if __name__ == '__main__':
    # add logs (.txt)
    insert_logs_from_text('logs.txt')

    # sql + save to .xlsx
    save_query("analyze_failed_logins", analyze_failed_logins())
    save_query("analyze_suspicious_requests", analyze_suspicious_requests())
    save_query("analyze_admin_access", analyze_admin_access())
    save_query("analyze_phishing_attempts", analyze_phishing_attempts())
    save_query("analyze_ddos", analyze_ddos())

    # close connection
    engine.dispose()
