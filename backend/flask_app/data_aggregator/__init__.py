from .db import db


def main():
    return db.get_db_connection()
