from flask import Blueprint, request, Response
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads')

@bp.route('', methods=['POST','GET'])
def loads_get_post():
    accept_header = request.headers.get('Accept')
    if accept_header is None or ('application/json' not in accept_header and '*/*' not in accept_header):
        error_string = '{"Error": "Accept header requests mimetype not supported by this endpoint."}'
        return Response(error_string, status=406, mimetype='application/json')
    content_type = request.headers.get('Content-Type')
    if content_type != 'application/json':
        error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
        return Response(error_string, status=415, mimetype='application/json')
    
    if request.method == 'POST':
        try:
            # Check if the item name is between 3-30 characters
            content = request.get_json()
            item_name = content["item"]
            if len(item_name) > 30 or len(item_name) < 3:
                error_string = json.dumps({"Error": "Item name must be between 3 and 30 characters long"})
                return Response(error_string, status=400, mimetype='application/json')
            # Check if the item name contains only letters, numbers, and spaces
            if not all(char.isalnum() or char.isspace() for char in item_name):
                error_string = json.dumps({"Error": "Name can only contain letters, numbers, and spaces"})
                return Response(error_string, status=400, mimetype='application/json')
            
            load_volume = content["volume"]
            # Check that load volume is an integer
            if not isinstance(load_volume, int):
                error_string = '{ "Error": "Load volume must be a number" }'
                return Response(error_string, status=400, mimetype="application/json")
            
            #Check if boat type is between 3 and 30 characters long
            if load_volume > 100000 or load_volume < 1:
                error_string = json.dumps({"Error": "Load volume must be between 1 and 100000 lbs"})
                return Response(error_string, status=400, mimetype='application/json')
            
            new_load = datastore.entity.Entity(key=client.key(constants.loads))
            new_load.update({"volume": content["volume"],
                            "item": content["item"],
                            "creation_date": content["creation_date"],
                            "carrier": None})
            client.put(new_load)
            new_load["id"] = new_load.key.id
            new_load["self"] = request.base_url + '/' + str(new_load.key.id)
            return Response(json.dumps(new_load), status=201, mimetype='application/json')
        except:
            error_string = '{"Error": "The request object is missing at least one of the required attributes"}'
            return Response(error_string, status=400, mimetype='application/json')
    elif request.method == 'GET':
        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))
        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.base_url + '/' + str(e.key.id)
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        return Response(json.dumps(output), status=200, mimetype='application/json')


@bp.route('/<id>', methods=['PUT','DELETE', 'GET'])
def loads_put_delete(id):
    if request.method == 'PUT':
        content_type = request.headers.get('Content-Type')
        if content_type != 'application/json':
            error_string = '{"Error": "Received Unsupported mimetype. Please use application/json"}'
            return Response(error_string, status=415, mimetype='application/json')
        content = request.get_json()

        # Check if the item name is between 3-30 characters
        item_name = content["item"]
        if len(item_name) > 30 or len(item_name) < 3:
            error_string = json.dumps({"Error": "Item name must be between 3 and 30 characters long"})
            return Response(error_string, status=400, mimetype='application/json')
        
        # Check if the item name contains only letters, numbers, and spaces
        if not all(char.isalnum() or char.isspace() for char in item_name):
            error_string = json.dumps({"Error": "Name can only contain letters, numbers, and spaces"})
            return Response(error_string, status=400, mimetype='application/json')
        
        load_volume = content["volume"]
        # Check that load volume is an integer
        if not isinstance(load_volume, int):
            error_string = '{ "Error": "Load volume must be a number" }'
            return Response(error_string, status=400, mimetype="application/json")
        
        #Check if boat type is between 3 and 30 characters long
        if load_volume > 100000 or load_volume < 1:
            error_string = json.dumps({"Error": "Load volume must be between 1 and 100000 lbs"})
            return Response(error_string, status=400, mimetype='application/json')
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        
        # Remove load from previous boat
        #if load["carrier"]["id"]:
        #    load_list = []
        #    boat_id = load["carrier"]["id"]
        #    boat_key = client.key(constants.boats, int(boat_id))
        #    boat = client.get(key=boat_key)
        #    for load_entity in boat['loads']:
        #        if load_entity['id'] != id:
        #            load_list.append(load_entity)
        #    boat.update({"loads": load_list})

        load.update({"volume": content["volume"],
                    "item": content["item"],
                    "creation_date": content["creation_date"]})
                    #"carrier": content["carrier"]})
        client.put(load)

        # Add load to new boat
        #add_load = {}
        #add_load["id"] = str(id)
        #add_load["self"] = 'https://assignment-7-493.uc.r.appspot.com/loads/' + str(id)
        #if 'loads' in boat.keys():
        #    boat['loads'].append(add_load)
        #else:
        #    boat['loads'] = [add_load]
        #client.put(boat)
        return ('',200)
    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load is None:
            error_string = '{"Error": "No load with this load_id exists"}'
            return Response(error_string, status=404, mimetype='application/json')
        if load["carrier"]:
            load_list = []
            boat_id = load["carrier"]["id"]
            boat_key = client.key(constants.boats, int(boat_id))
            boat = client.get(key=boat_key)
            for load_entity in boat['loads']:
                if load_entity['id'] != id:
                    load_list.append(load_entity)
            boat.update({"loads": load_list})
            client.put(boat)
        client.delete(load_key)
        return ('',204)
    elif request.method == 'GET':
        try:
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            load["id"] = str(id)
            load["self"] = request.base_url
            return Response(json.dumps(load), status=200, mimetype='application/json')
        except:
            error_string = '{ "Error": "No load with this load_id exists"}'
            return Response(error_string, status=404, mimetype='application/json')
    else:
        return 'Method not recognized'
