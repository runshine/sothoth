import html
import logging
import re
import time
import os
import threading
from io import BytesIO

from flask import Flask, jsonify, request, send_file, abort
import pymysql
from dbutils.pooled_db import PooledDB

app = Flask(__name__)
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)
nginx_config_template=""


@app.route('/utils/<name>/<release>/<arch>', methods=['GET'])
def download_utils(name,release,arch):
    if os.path.exists("/data/utils/{}-{}-{}".format(name,release,arch)):
        return send_file("/data/utils/{}-{}-{}".format(name,release,arch), as_attachment=True, download_name="{}".format(name))
    else:
        return abort(404)


@app.route('/package/<name>/<release>/<arch>', methods=['GET'])
def download_package(name,release,arch):
    suffix_list = ["tar.gz","tar.zst","tar","zip"]
    for suffix in suffix_list:
        if os.path.exists("/data/package/{}-{}-{}.{}".format(name,release,arch,suffix)):
            return send_file("/data/package/{}-{}-{}.{}".format(name,release,arch,suffix), as_attachment=True, download_name="{}.{}".format(name,suffix))
    return abort(404)


if __name__ == '__main__':
    app.run(host="0.0.0.0",port="8081",debug=False,threaded=True)