from datetime import datetime
from flask import Flask, session, make_response, request
from flask_restful import Resource, Api, reqparse
import jwt

app = Flask(__name__)
JWT_SECRET_KEY = 'your_secret'
JWT_ALGORITHM = "HS256"

api = Api(app)

class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', default=None, help="username")
        parser.add_argument('password', default=None, help="password")
        args = parser.parse_args()
        
        print(args)
        username = args.username
        password = args.password
        print(username, password)

        if not username or not password:
            return make_response("Invalid username or password", 401)

        # Assume that username and password are validated
        # TODO give "exp": 
        encoded_jwt = jwt.encode({"username": username, "iat": datetime.utcnow()}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        response = make_response(encoded_jwt, 200)
        response.set_cookie("jwt", encoded_jwt, httponly=True)

        return response



class Logout(Resource):
    def get(self):
        # TODO make it decorator
        print(request.headers)
        try:
            if "Authorization" in request.headers:
                token = request.headers["Authorization"]
            elif "jwt" in request.cookies:
                token = request.cookies.get('jwt')
            else:
                raise ValueError("No token")
            
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": False})
            assert token == jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]) # validate expiry time
            response = make_response("logged out", 200) 
            response.set_cookie("jwt", "", httponly=True, expires=0)
        except Exception as e:
            print(e)
            return make_response("Invalid token", 401)

        return response

api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

print("This is the first change!")
print("This is the second change!")

if __name__ == '__main__':
    app.run(debug=True, port=5001)
