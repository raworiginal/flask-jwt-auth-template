from flask import Flask, jsonify, request, g
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from auth_middleware import token_required
import os
import jwt
import bcrypt

load_dotenv()

app = Flask(__name__)


def get_db_connection():
  connection = psycopg2.connect(host='localhost',
                                database='flask_auth_db',
                                user=os.getenv('POSTGRES_USERNAME'),
                                password=os.getenv('POSTGRES_PASSWORD'))
  return connection


@app.route("/sign-token", methods=['GET'])
def sign_token():
  user = {
      "id": 1,
      "username": "test",
      "password": "test"
  }
  token = jwt.encode(user, os.getenv("JWT_SECRET"), algorithm="HS256")
  return jsonify({"token": token})


@app.route('/verify-token', methods=['POST'])
def verify_token():
  try:
    token = request.headers.get('Authorization').split(' ')[1]
    decoded_token = jwt.decode(token, os.getenv(
        'JWT_SECRET'), algorithms=["HS256"])
    return jsonify({"user": decoded_token})
  except Exception as err:
    return jsonify({"err": str(err)})


@app.route('/auth/sign-up', methods=['POST'])
def sign_up():
  try:
    new_user_data = request.get_json()
    connection = get_db_connection()
    cursor = connection.cursor(
        cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        "SELECT * FROM users WHERE username = %s;",
        (new_user_data["username"],)
    )
    existing_user = cursor.fetchone()
    if existing_user:
      cursor.close()
      return jsonify({"err": "Username already taken"}), 400
    hashed_password = bcrypt.hashpw(
        bytes(new_user_data["password"], 'utf-8'), bcrypt.gensalt())
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id, username",
        (new_user_data["username"],
         hashed_password.decode('utf-8')))
    created_user = cursor.fetchone()
    connection.commit()
    connection.close()
    # Construct the payload
    payload = {
        "username": created_user["username"],
        "id": created_user["id"]}
    # Create the token, attaching the payload
    token = jwt.encode({"payload": payload}, os.getenv('JWT_SECRET'))
    # Send the token instead of the user
    return jsonify({"token": token}), 201
  except Exception as err:
    return jsonify({"err": str(err)}), 401


@app.route('/auth/sign-in', methods=["POST"])
def sign_in():
  try:
    sign_in_form_data = request.get_json()
    connection = get_db_connection()
    cursor = connection.cursor(
        cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute(
        "SELECT * FROM users WHERE username = %s;",
        (sign_in_form_data["username"],)
    )
    existing_user = cursor.fetchone()
    if existing_user is None:
      return jsonify({"err": "Invalid credentials."}), 401
    password_is_valid = bcrypt.checkpw(
        bytes(
            sign_in_form_data["password"],
            'utf-8'),
        bytes(
            existing_user["password"],
            'utf-8'))
    if not password_is_valid:
      return jsonify({"err": "Invalid credentials."}), 401
    payload = {
        "username": existing_user["username"], "id": existing_user["id"]}
    token = jwt.encode({"payload": payload}, os.getenv('JWT_SECRET'))
    return jsonify({"token": token}), 200
  except Exception as err:
    return jsonify({"err": str(err)}), 500
  finally:
    connection.close()


@app.route("/users")
def users_index():
  connection = get_db_connection()
  cursor = connection.cursor(
      cursor_factory=psycopg2.extras.RealDictCursor
  )
  cursor.execute("SELECT id, username FROM users;")
  users = cursor.fetchall()
  connection.close()
  return jsonify(users), 200


if __name__ == "__main__":
  app.run(debug=True)
