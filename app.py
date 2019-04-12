#!/usr/bin/python3
import os
import logging
import secrets

from flask import Flask, request, jsonify, abort, render_template

from database import db_session, init_db
from models import KycRequest

init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

@app.route('/')
def hello():
    request_count = KycRequest.count(db_session)
    return 'Hello World! %d requests created' % request_count

@app.route('/request', methods=['POST'])
def request_create():
    content = request.json
    token = content['token']
    req = KycRequest.from_token(db_session, token)
    if req:
        print("%s already exists" % token)
        abort(400)
    print("creating for %s" % token)
    greenid_verification_id = secrets.token_hex(16)
    req = KycRequest(token, greenid_verification_id)
    db_session.add(req)
    db_session.commit()
    return jsonify(req.to_json())

@app.route('/status', methods=['POST'])
def status():
    content = request.json
    token = content['token']
    print("looking for %s" % token)
    req = KycRequest.from_token(db_session, token)
    if req:
        return jsonify(req.to_json())
    return abort(404)

@app.route('/request/<token>', methods=['GET', 'POST'])
def request_action(token=None):
    CMP = 'completed'
    req = KycRequest.from_token(db_session, token)
    if not req:
        return abort(404, "sorry, request not found")
    if request.method == 'GET':
        return render_template('request.html', token=token, completed=req.status==CMP)
    req.status = CMP
    db_session.add(req)
    db_session.commit()
    return render_template('request.html', token=token, completed=True)

if __name__ == '__main__':
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
