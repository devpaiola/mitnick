def find_user(cursor, request):
    username = request.args["username"]
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
