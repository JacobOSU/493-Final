import boat
import load
import constants
from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests
from functools import wraps
import json
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
import json
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from flask import Flask, Response, redirect, render_template, session, url_for
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from datetime import datetime

app = Flask(__name__)
#app.register_blueprint(boat.bp)
app.register_blueprint(load.bp)

client = datastore.Client()



# Update the values of the following 3 variables
CLIENT_ID = '3nfXsISokRVvLT1LJlw5p4rc9L7uU8cq'
CLIENT_SECRET = 'OFMLU63A0Qziiy74ifP2bsC9ScvalElQFs9gG-bykdmXGGOSz-BNvfMivenfhky9'
DOMAIN = 'dev-xbdol1absd1uegvc.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

#app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


# Controllers API
@app.route("/")
def home():
    user_info = session.get("user")
    if user_info:
        id_token = user_info.get("id_token")
        unique_id = user_info["userinfo"]["sub"]
        #payload = verify_jwt(request)
        #owner_id = payload["sub"]
        #new_user = datastore.entity.Entity(key=client.key(constants.users))
        #new_user.update({"owner_id": owner_id,
        #"email": session.get("user"),
        #"date_created": datetime.now().date()})
        #client.put(new_user)
        #new_user["id"] = new_user.key.id
    else:
        id_token = None
        unique_id = None
    if id_token is not None:
        query = client.query(kind=constants.users)
        query.add_filter('JWT', '=', id_token)
        result = list(query.fetch())

        # Check if user already exists in db
        if len(result) == 0:
            new_user = datastore.entity.Entity(key=client.key(constants.users))
            user_info_json = session["user"]
            unique_id = user_info_json["userinfo"]["sub"]
            new_user.update({"JWT": id_token, "owner_id": unique_id})
            client.put(new_user)
    return render_template(
        "home.html",
        session=session.get("user"),
        id_token = id_token,
        unique_id = unique_id,
        pretty=json.dumps(session.get("user"), indent=4),
    )



@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /boats to use this API"\


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}



#/////////////////////////////////////////////////////////////////////////////
#/////////////////////////////////////////////////////////////////////////////
@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
    
    
    if request.method == 'POST':
        accept_header = request.headers.get('Accept')
        if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
            error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
            return Response(error_string, status=406, mimetype='application/json')
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
            return Response(error_string, status=415, mimetype='application/json')
        try:
            content = request.get_json()
            boat_name = content["name"]
            query = client.query(kind=constants.boats)
            query.add_filter('name', '=', boat_name)
            result = list(query.fetch())

            # Check if boat name already exists
            if len(result) != 0:
                error_string = '{"Error": "Boat name already exists"}'
                return Response(error_string, status=403, mimetype='application/json')
            
            name = content["name"]
            boat_type = content["type"]
            boat_length = content["length"]

            # Check if the name is at most 30 characters long
            if len(name) > 30 or len(name) < 3:
                error_string = json.dumps({"Error": "Name must be between 3 and 30 characters long"})
                return Response(error_string, status=400, mimetype='application/json')
            # Check if the name contains only letters, numbers, and spaces
            if not all(char.isalnum() or char.isspace() for char in name):
                error_string = json.dumps({"Error": "Name can only contain letters, numbers, and spaces"})
                return Response(error_string, status=400, mimetype='application/json')
            
            #Check if boat type is between 3 and 30 characters long
            if len(boat_type) > 30 or len(boat_type) < 3:
                error_string = json.dumps({"Error": "Boat type must be between 3 and 30 characters long"})
                return Response(error_string, status=400, mimetype='application/json')
            # Check if the type contains only letters, numbers, and spaces
            if not all(char.isalnum() or char.isspace() for char in boat_type):
                error_string = json.dumps({"Error": "Boat type can only contain letters, numbers, and spaces"})
                return Response(error_string, status=400, mimetype='application/json')
            
            # Check that boat length is an integer
            if not isinstance(boat_length, int):
                error_string = '{ "Error": "Boat length must be a number" }'
                return Response(error_string, status=400, mimetype="application/json")
            # Check that boat length is within 5-1000 ft long
            if  boat_length > 2000 or boat_length < 5:
                error_string = json.dumps({"Error": "Boat length must be between 5 and 2000 feet long"})
                return Response(error_string, status=400, mimetype='application/json')
            
            payload = verify_jwt(request)
            boat_owner = payload["sub"]

            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({'name': content['name'], 
                            'type': content['type'],
                            'length': content['length'],
                            'public': content['public'],
                            'owner': boat_owner,
                            'loads': []
                            })
            client.put(new_boat)
            new_boat['id'] = new_boat.key.id
            new_boat['self'] = request.base_url + '/' + str(new_boat.key.id)
            return Response(json.dumps(new_boat), status=201, mimetype='application/json')
        except:
            error_string = '{"Error": "The request object is missing at least one of the required attributes"}'
            return Response(error_string, status=400, mimetype='application/json')
    elif request.method == 'GET':
        accept_header = request.headers.get('Accept')
        if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
            error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
            return Response(error_string, status=406, mimetype='application/json')
        try:
            payload = verify_jwt(request)
            owner = payload["sub"]
            query = client.query(kind=constants.boats)
            query.add_filter('owner', '=', owner)
            boat_results = list(query.fetch())
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + '/' + str(e.key.id)
            output = {"boats": results}
            output["total_items"] = len(boat_results)
            if next_url:
                output["next"] = next_url
            return Response(json.dumps(output), status=200, mimetype='application/json')
        except:
            #public_boats = []
            query = client.query(kind="boats")
            query.add_filter('public', '=', True)
            boat_results = list(query.fetch())
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + '/' + str(e.key.id)
            output = {"boats": results}
            output["total_items"] = len(boat_results)
            if next_url:
                output["next"] = next_url
            return Response(json.dumps(output), status=200, mimetype='application/json')
    elif request.method == 'PUT':
        error_string = '{"Error": "Cannot edit list of boats"}'
        return Response(error_string, status=405, mimetype='application/json')
    elif request.method == 'DELETE':
        error_string = '{"Error": "Cannot delete list of boats"}'
        return Response(error_string, status=405, mimetype='application/json')
    else:
        return 'Method not recognized'

@app.route('/boats/<id>', methods=['PUT','DELETE', 'GET', 'PATCH'])
def boats_put_delete(id):
    if id == "null":
        error_string = '{"Error": "No boat with this boat_id exists"}'
        return Response(error_string, status=404, mimetype='application/json')
    if request.method == 'PUT':
        accept_header = request.headers.get('Accept')
        if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
            error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
            return Response(error_string, status=406, mimetype='application/json')
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
            return Response(error_string, status=415, mimetype='application/json')
        try:
            
            
            content = request.get_json()
            boat_name = content["name"]
            query = client.query(kind=constants.boats)
            query.add_filter('name', '=', boat_name)
            result = list(query.fetch())

            # Check if boat name already exists
            if len(result) != 0:
                error_string = '{"Error": "Boat name already exists"}'
                return Response(error_string, status=403, mimetype='application/json')
            
            name = content["name"]
            boat_type = content["type"]
            boat_length = content["length"]

            # Check if the name is at most 30 characters long
            if len(name) > 30 or len(name) < 3:
                error_string = json.dumps({"Error": "Name must be between 3 and 30 characters long"})
                return Response(error_string, status=400, mimetype='application/json')
            # Check if the name contains only letters, numbers, and spaces
            if not all(char.isalnum() or char.isspace() for char in name):
                error_string = json.dumps({"Error": "Name can only contain letters, numbers, and spaces"})
                return Response(error_string, status=400, mimetype='application/json')
            
            #Check if boat type is between 3 and 30 characters long
            if len(boat_type) > 30 or len(boat_type) < 3:
                error_string = json.dumps({"Error": "Boat type must be between 3 and 30 characters long"})
                return Response(error_string, status=400, mimetype='application/json')
            # Check if the type contains only letters, numbers, and spaces
            if not all(char.isalnum() or char.isspace() for char in boat_type):
                error_string = json.dumps({"Error": "Boat type can only contain letters, numbers, and spaces"})
                return Response(error_string, status=400, mimetype='application/json')
            
            # Check that boat length is an integer
            if not isinstance(boat_length, int):
                error_string = '{ "Error": "Boat length must be a number" }'
                return Response(error_string, status=400, mimetype="application/json")
            # Check that boat length is within 5-1000 ft long
            if  boat_length > 2000 or boat_length < 5:
                error_string = json.dumps({"Error": "Boat length must be between 5 and 2000 feet long"})
                return Response(error_string, status=400, mimetype='application/json')
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat is None:
                error_string = '{"Error": "No boat with this boat_id exists"}'
                return Response(error_string, status=404, mimetype='application/json')
            
            payload = verify_jwt(request)
            owner = payload["sub"]

            if owner != boat["owner"]:
                return Response(status=403)

            boat.update({"name": content["name"], "type": content["type"],
            "length": content["length"], "public": content["public"]})
            client.put(boat)
            return ('',200)
        except:
            error_string = '{"Error": "The request object is missing at least one of the required attributes or JWT is invalid"}'
            return Response(error_string, status=400, mimetype='application/json')
    elif request.method == 'DELETE':
        if id is None or id == 'null':
            return Response(status=401)
        boat_key = client.key("boats", int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            return Response("No boat with this boat_id exists", status=403, mimetype='application/json')
        try:
            payload = verify_jwt(request)
            owner = payload["sub"]
            if owner == boat["owner"]:
                for load_entity in boat['loads']:
                    load_id = load_entity['id']
                    load_key = client.key(constants.loads, int(load_id))
                    load = client.get(key=load_key)
                    load.update({"carrier": None})
                    client.put(load)
                client.delete(boat_key) 
                return Response(status=204, mimetype='application/json')
            else:
                return Response(status=403, mimetype='application/json')
        except:
            return Response(status=401, mimetype='application/json')
        

    elif request.method == 'GET':
        try:
            accept_header = request.headers.get('Accept')
            if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
                error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
                return Response(error_string, status=406, mimetype='application/json')
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            boat["id"] = str(id)
            boat["self"] = request.base_url
            return Response(json.dumps(boat), status=200, mimetype='application/json')
        except:
            error_string = '{ "Error": "No boat with this boat_id exists" }'
            return Response(error_string, status=404, mimetype='application/json')
    elif request.method == 'PATCH':
        accept_header = request.headers.get('Accept')
        if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
            error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
            return Response(error_string, status=406, mimetype='application/json')
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
            return Response(error_string, status=415, mimetype='application/json')
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat is None:    
            error_string = '{ "Error": "No boat with this boat_id exists" }'
            return Response(error_string, status=404, mimetype="application/json")
        try:
            content = request.get_json()
            if "name" in content and content["name"] is not None and content["name"] != "":
                boat_name = content["name"]
                query = client.query(kind=constants.boats)
                query.add_filter('name', '=', boat_name)
                result = list(query.fetch())
                if len(result) != 0:
                    error_string = '{"Error": "Boat name already exists"}'
                    return Response(error_string, status=403, mimetype='application/json')

                name = content.get("name", "")
                boat_type = content.get("type", "")
                # Check if the name is at most 30 characters long
                if len(name) > 30 or len(name) < 3:
                    error_string = json.dumps({"Error": "Name must be between 3 and 30 characters long"})
                    return Response(error_string, status=400, mimetype='application/json')
                # Check if the name contains only letters, numbers, and spaces
                if not all(char.isalnum() or char.isspace() for char in name):
                    error_string = json.dumps({"Error": "Name can only contain letters, numbers, and spaces"})
                    return Response(error_string, status=400, mimetype='application/json')
                boat.update({"name": content["name"]})


            if "type" in content and content["type"] is not None and content["type"] != "":
                if len(boat_type) > 30 or len(boat_type) < 3:
                    error_string = json.dumps({"Error": "Boat type must be between 3 and 30 characters long"})
                    return Response(error_string, status=400, mimetype='application/json')
                # Check if the type contains only letters, numbers, and spaces
                if not all(char.isalnum() or char.isspace() for char in boat_type):
                    error_string = json.dumps({"Error": "Boat type can only contain letters, numbers, and spaces"})
                    return Response(error_string, status=400, mimetype='application/json')
                boat.update({"type": content["type"]})


            if "length" in content and content["length"] is not None and content["length"] != "":
                boat_length = content["length"]
                if not isinstance(boat_length, int):
                    error_string = '{ "Error": "Boat length must be a number" }'
                    return Response(error_string, status=400, mimetype="application/json")
                if  boat_length > 2000 or boat_length < 5:
                    error_string = json.dumps({"Error": "Boat length must be between 5 and 2000 feet long"})
                    return Response(error_string, status=400, mimetype='application/json')
                boat.update({"length": content["length"]})
            
            
            client.put(boat)
            boat["id"] = id
            boat["self"] = request.base_url
            return Response(json.dumps(boat), status=200, mimetype='application/json')
        except:
            error_string = '{ "Error": "The request object is missing at least one of the required attributes or request mimetype not JSON" }'
            return Response(error_string, status=400, mimetype='application/json')
    else:
        return 'Method not recogonized'

@app.route('/boats/<lid>/loads/<gid>', methods=['PUT','DELETE'])
def add_load_to_boat(lid, gid):
    if request.method == 'PUT':
        try:
            boat_key = client.key(constants.boats, int(lid))
            boat = client.get(key=boat_key)
            load_key = client.key(constants.loads, int(gid))
            load = client.get(key=load_key)
        except:
            error_string = '{ "Error": "The specified boat and/or load does not exist"}'
            return Response(error_string, status=404, mimetype='application/json')

        if boat is None or load is None:
            error_string = '{"Error": "The specified boat and/or load does not exist"}'
            return Response(error_string, status=404, mimetype='application/json')
        
        if load["carrier"] is not None:
            error_string = '{"Error": "The load is already loaded on another boat"}'
            return Response(error_string, status=403, mimetype='application/json')
        
        add_boat_to_load = {}
        add_boat_to_load["id"] = str(lid)
        add_boat_to_load["name"] = boat["name"]
        add_boat_to_load["self"] = 'https://assignment-7-493.uc.r.appspot.com/boats/' + str(lid)
        load.update({"carrier": add_boat_to_load})
        client.put(load)
        add_load = {}
        add_load["id"] = str(gid)
        add_load["self"] = 'https://assignment-7-493.uc.r.appspot.com/loads/' + str(gid)
        if 'loads' in boat.keys():
            boat['loads'].append(add_load)
        else:
            boat['loads'] = [add_load]
        client.put(boat)
        return('',204)
    if request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(lid))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(gid))
        load = client.get(key=load_key)
        #print('load["carrier"]["id"] is: ', load["carrier"]["id"])
        #print('boat id is: ', lid)
        #print(load["carrier"]["id"] != lid)
        #print("boat[loads] is ", boat["loads"])

        if boat is None or load is None:
            error_string = '{"Error": "No boat with this boat_id is loaded with the load with this load_id"}'
            return Response(error_string, status=404, mimetype='application/json')
        if "carrier" not in load or load["carrier"] is None or load["carrier"]["id"] != lid: #or not boat["loads"][gid]:
            error_string = '{"Error": "No boat with this boat_id is loaded with the load with this load_id"}'
            return Response(error_string, status=404, mimetype='application/json')
        if 'loads' in boat:
            load_list = []
            boat_load_pair = False
            for load_entity in boat['loads']:
                if load_entity['id'] == str(gid):
                    boat_load_pair = True
                    load_key = client.key(constants.loads, int(gid))
                    load = client.get(key=load_key)
                    load.update({"carrier": None})
                    client.put(load)
                if load_entity['id'] != str(gid):
                    load_list.append(load_entity)
            if boat_load_pair:
                boat['loads'] = load_list
                client.put(boat)
                return('',204)
            else:
                error_string = '{"Error": "No boat with this boat_id is loaded with the load with this load_id"}'
                return Response(error_string, status=404, mimetype='application/json')
        else:
            error_string = 'The boat does not have the load'
            return Response(error_string, status=403)

@app.route('/boats/<id>/loads', methods=['GET'])
def get_reservations(id):
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    if boat is None:
        error_string = '{"Error": "No boat with this boat_id exists"}'
        return Response(error_string, status=404, mimetype='application/json')
    load_list  = []
    if 'loads' in boat:
        for load_entity in boat['loads']:
            load_key = client.key(constants.loads, int(load_entity["id"]))
            load_list.append(load_key)
        attach_load_list = []
        for key in load_list:
            add_load = client.get(key=key)
            attach_load_list.append(add_load)
        return_loads = {"loads": attach_load_list}
        return Response(json.dumps(return_loads), status=200, mimetype='application/json')
        #return Response(json.dumps(client.get_multi(load_list)), status=200, mimetype='application/json')
    else:
        return json.dumps([])


#///////////////////////////////////////////////////////////////////////////////////////////////////////////











#@app.route('/')
#def index():
#    return "Please navigate to /lodgings to use this API"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)