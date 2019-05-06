#!/usr/bin/python3
import os
import logging
import secrets
import hmac
import hashlib
import base64
import sys

from flask import Flask, request, jsonify, abort, render_template
import zeep

from database import db_session, init_db
from models import KycRequest

init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

GREENID_WEBSERVICE_ENDPOINT = 'https://test-au.vixverify.com/Registrations-Registrations/DynamicFormsServiceV3?WSDL'
GREENID_ACCOUNT_ID = os.environ.get('GREENID_ACCOUNT_ID', '')
GREENID_SIMPLEUI_AUTH = os.environ.get('GREENID_SIMPLEUI_AUTH', '')
GREENID_API_AUTH = os.environ.get('GREENID_API_AUTH', '')
API_KEY = os.environ.get('API_KEY', '')
API_SECRET = os.environ.get('API_SECRET', '')
if not GREENID_ACCOUNT_ID:
    print('ERROR: no greenid account id')
    sys.exit(1)
if not GREENID_SIMPLEUI_AUTH:
    print('ERROR: no greenid simpleui auth')
    sys.exit(1)
if not GREENID_API_AUTH:
    print('ERROR: no greenid api auth')
    sys.exit(1)
if not API_KEY:
    print('ERROR: no api key')
    sys.exit(1)
if not API_SECRET:
    print('ERROR: no api secret')
    sys.exit(1)

def setup_logging(level):
    # setup logging
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

def get_verification_token(verification_id):
    client = zeep.Client(GREENID_WEBSERVICE_ENDPOINT)
    return client.service.getVerificationToken(GREENID_ACCOUNT_ID, GREENID_API_AUTH, verification_id, None)

def get_verification_result(verification_id):
    client = zeep.Client(GREENID_WEBSERVICE_ENDPOINT)
    current_status = client.service.getVerificationResult(GREENID_ACCOUNT_ID, GREENID_API_AUTH, verification_id, None, None)
    return current_status.verificationResult.overallVerificationStatus

def create_sig(api_secret, message):
    _hmac = hmac.new(api_secret.encode('latin-1'), msg=message, digestmod=hashlib.sha256)
    signature = _hmac.digest()
    signature = base64.b64encode(signature).decode("utf-8")
    return signature

def check_auth(api_key, sig, body):
    if api_key != API_KEY:
        return False
    our_sig = create_sig(API_SECRET, body)
    return sig == our_sig

@app.route('/')
def hello():
    request_count = KycRequest.count(db_session)
    return 'Hello World! %d requests created' % request_count

@app.route('/request', methods=['POST'])
def request_create():
    sig = request.headers.get('X-Signature')
    content = request.json
    api_key = content['api_key']
    token = content['token']
    if not check_auth(api_key, sig, request.data):
        print('auth failure')
        abort(400)
    req = KycRequest.from_token(db_session, token)
    if req:
        print('%s already exists' % token)
        abort(400)
    print("creating for %s" % token)
    greenid_verification_id = None
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
        return abort(404, 'sorry, request not found')
    verification_token = None
    if request.method == 'POST':
        # update verification id if we got one
        verification_id = request.form['verificationId']
        if verification_id:
            req.greenid_verification_id = verification_id
            db_session.add(req)
            db_session.commit()
        if req.greenid_verification_id:
            # get verification token so we can continue if needed
            verification_token = get_verification_token(req.greenid_verification_id)
            # get status from green id
            result = get_verification_result(req.greenid_verification_id)
            result = result.lower()
            if result[0:8] == 'verified':
                req.status = CMP
                db_session.add(req)
                db_session.commit()
    if req.greenid_verification_id:
        # get verification token so we can continue if needed
        verification_token = get_verification_token(req.greenid_verification_id)
    return render_template('request.html', token=token, completed=req.status==CMP, account_id=GREENID_ACCOUNT_ID, api_code=GREENID_SIMPLEUI_AUTH, verification_token=verification_token)

if __name__ == '__main__':
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
