import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

DATABASE_CONFIG = {
    "host": "localhost",
    "database": "auth_system",
    "user": "postgres",
    "password": "your_password_here",  # Change this to your PostgreSQL password
    "port": 5432
}

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = psycopg2.connect(**DATABASE_CONFIG, cursor_factory=RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_db_cursor(conn):
    """Get a cursor from connection"""
    return conn.cursor()