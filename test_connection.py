from db_connect import get_connection

conn = get_connection()
cursor = conn.cursor()
cursor.execute("SELECT * FROM institutions;")
for row in cursor.fetchall():
    print(row)
conn.close()