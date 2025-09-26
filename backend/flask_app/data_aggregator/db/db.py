from dotenv import load_dotenv
import psycopg2
import os

load_dotenv()

conn = psycopg2.connect(
    database=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_SECRET"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT"),
)


def get_db_connection():
    print(os.getenv("DB_NAME"))
    return psycopg2.connect(conn)
