def find_user(cursor, request):
    username = request.args["username"]
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
