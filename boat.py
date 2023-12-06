from flask import Blueprint, request, Response
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('boat', __name__, url_prefix='/boats')

@bp.route('', methods=['POST','GET'])
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
            
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({'name': content['name'], 
                            'type': content['type'],
                            'length': content['length'],
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
        query = client.query(kind=constants.boats)
        q_limit = int(request.args.get('limit', '3'))
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
            e["self"] = 'https://summejac493-assignment1.uc.r.appspot.com/boats/' + str(e.key.id)
        output = {"boats": results}
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

@bp.route('/<id>', methods=['PUT','DELETE', 'GET'])
def boats_put_delete(id):
    
    if request.method == 'PUT':
        accept_header = request.headers.get('Accept')
        if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
            error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
            return Response(error_string, status=406, mimetype='application/json')
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
            return Response(error_string, status=415, mimetype='application/json')
        #try:
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
        boat.update({"name": content["name"], "type": content["type"],
        "length": content["length"]})
        client.put(boat)
        return ('',200)
        #except:
            #error_string = '{"Error": "The request object is missing at least one of the required attributes"}'
            #return Response(error_string, status=400, mimetype='application/json')
    elif request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            error_string = '{"Error": "No boat with this boat_id exists"}'
            return Response(error_string, status=404, mimetype='application/json')
        for load_entity in boat['loads']:
                load_id = load_entity['id']
                load_key = client.key(constants.loads, int(load_id))
                load = client.get(key=load_key)
                load.update({"carrier": None})
                client.put(load)
        
        client.delete(boat_key)
        return ('',204)
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
    else:
        return 'Method not recogonized'

@bp.route('/<lid>/loads/<gid>', methods=['PUT','DELETE'])
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

@bp.route('/<id>/loads', methods=['GET'])
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
