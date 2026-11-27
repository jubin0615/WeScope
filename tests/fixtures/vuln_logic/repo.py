"""상품 저장소. 검색어는 다른 파일(app.py의 /search)에서 넘어온다."""
import sqlite3


def search_products(term):
    conn = sqlite3.connect("shop.sqlite3")
    # ai-expect: cross-file-injection-sql
    return conn.execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'").fetchall()
