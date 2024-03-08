"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from api.models import db, Users
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required


api = Blueprint('api', __name__)
CORS(api)  # Allow CORS requests to this API


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():
    response_body = {}
    response_body['message'] = "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    return jsonify(response_body), 200


# Create a route to authenticate your users and return JWTs. 
# The create_access_token() function is used to actually generate the JWT.
""" @api.route("/login", methods=["POST"])
def login():
    response_body = {}
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    # Reemplazar por lógica consultando la DB.
    if email != "test@test" or password != "test":
        response_body['message'] = "Bad username or password"
        return response_body, 401
    user = {'email': email,
            'id': 1,
            'is_admin': True,}
    profile = {'lastname': 'Chocobar',
               'name': 'Hector',
               'stutus': True,
               'role': 'Mentor'}
    access_token = create_access_token(identity=[user, profile])  # Lo que el back quiere agregar en el token
    response_body['access_token'] = access_token
    response_body['message'] = "Usuario logeado con éxito"
    response_body['results'] = {'user': user, 'profile': profile}
    return response_body, 200 """


@api.route("/login", methods=["POST"])
def create_token():
    response_body = {}
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    user = db.session.query(Users).filter(email=email, password=password, is_active=True).first()
    if user is None:
        return jsonify({"msg": "ACCES DENIED, YOU DIDN'T SAY THE MAGIC WORD ;)"}), 401
    access_token = create_access_token(identity = user.id)
    response_body['msg'] = "YOU ROCK!!"
    return jsonify({ "token": access_token, "user_id": user.id }), 200



# Protect a route with jwt_required, which will kick out requests without a valid JWT present.
@api.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    print(current_user)
    return jsonify(logged_in_as=current_user), 200


# Protect a route with jwt_required, which will kick out requests without a valid JWT present.
@api.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    response_body = {}
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    if current_user[1]['name'] == 'Matteo':
        response_body['message'] = 'Perfil de Irene, tiene acceso'
        print(current_user)
        return response_body, 200
    response_body['message'] = 'Perfil SIN ACCESO'
    return response_body, 401
