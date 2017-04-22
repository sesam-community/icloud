from functools import wraps
from flask import Flask, request, Response, abort
from dateutil.parser import parse
import json
import requests
import os
import logging
import threading
import copy
from pyicloud import PyiCloudService



app = Flask(__name__)
config = {}
config_since = None

logger = None

_lock_config = threading.Lock()


class DataAccess:
    def __init__(self):
        self._entities = {
                          "contacts": [], "file-folders": [], "photos": []}
        self._odata = None


    def get_entities(self, since, datatype, user, password, folder, json_content):

        api = PyiCloudService(user, password)

        if not datatype in self._entities:
            abort(404)

        with _lock_config:
            # Make a deep copy so we can serve multiple threads with potentially different config
            config_copy = copy.deepcopy(config)


        try:
            if datatype == "contacts":
                logger.info("Reading contacts: %s" % (folder))
                for e in api.contacts.all():
                    e = to_transit(e)
                    e.update({"_id": e["contactId"]})
                    yield e

            if datatype == "file-folders":
                logger.info("Reading file-folders: %s" % (folder))
                for d in api.files.dir():
                    yield from self.getfilefolder(api, api.files[d])

            if datatype == "photos":
                logger.info("Reading photos: %s" % (folder))
                for e in api.photos.all:
                    e = to_transit(e)
                    e.update({"_id": e["item_id"]})
                    yield e

        except BaseException as e:
            logger.exception("Crashed while trying to read data from icloud")
            raise e

    def getfilefolder(self, api, folder):
        for f in folder.get_children():
            e = to_transit(f.data)
            e.update({"_id": f.item_id})
            yield e
            if f.type == "folder" or f.type == "package":
                yield from self.getfilefolder(api, folder[f.name])


data_access_layer = DataAccess()


def to_transit(d):
    new = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = to_transit(v)
        new[k.replace(".","")] = string_date(v)
    return new


def string_date(string):
    try:
        parse(string)
        return to_transit_datetime(parse(string))
    except:
        if isinstance(string, str):
            string = string.replace("dbid:","").replace("id:","")
        return string


def datetime_format(dt):
    return '%04d' % dt.year + dt.strftime("-%m-%dT%H:%M:%SZ")


def to_transit_datetime(dt_int):
    return "~t" + datetime_format(dt_int)


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return authenticate()
        return f(*args, **kwargs)

    return decorated


@app.route('/<datatype>', methods=['GET', 'POST'])
@requires_auth
def get_entities(datatype):
    logger.info("Get %s using request: %s" % (datatype, request.url))
    since = request.args.get('since')
    folder = get_var("folder") or ""
    auth = request.authorization
    json_content = [None]
    if request.values.get('content'):
        # JSON from a form post
        json_content = json.loads(request.values.get('content'))
    elif request.get_data():
        # JSON from a HTTP POST
        json_content = json.loads(request.get_data().decode('utf-8'))

    if isinstance(json_content, dict):
        json_content = [json_content]

    def generate(entities):
        # Wrapper generator to produce streaming json
        i = 0
        yield "["
        for index, entity in enumerate(entities):
            if index > 0:
                yield ","

            i = index
            yield json.dumps(entity)
        logger.info("Produced '%s entitites, closing stream" % i)
        yield "]"


    logger.info("Reading entities...")
    try:
        return Response(generate(data_access_layer.get_entities(since, datatype, auth.username, auth.password, folder, json_content)),
                        mimetype='application/json')
    except BaseException as e:
        logger.exception("Failed to read entities!")
        return Response(status=500, response="An error occured during generation of entities")


def get_var(var):
    envvar = None
    if var.upper() in os.environ:
        envvar = os.environ[var.upper()]
    else:
        envvar = request.args.get(var)
    logger.info("Setting %s = %s" % (var, envvar))
    return envvar


if __name__ == '__main__':
    # Set up logging
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logger = logging.getLogger('dropbox-microservice')

    # Log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(stdout_handler)

    logger.setLevel(logging.DEBUG)

    app.run(threaded=True, debug=True, host='0.0.0.0')
