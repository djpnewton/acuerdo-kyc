#!/usr/bin/python3
import os
import logging
import hmac
import hashlib
import base64
import sys
from io import BytesIO
import threading

from flask import Flask, request, jsonify, abort, render_template, make_response
import requests
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from database import db_session, init_db
from models import KycRequest, AplyId, EzyPay, User, UserRequest, KycRequestWebhook

init_db()
logger = logging.getLogger(__name__)
app = Flask(__name__)

PRODUCTION = os.environ.get('PRODUCTION', '')
APLYID_BASE_URL = 'https://integration.aply.co.nz/api/v2'
if PRODUCTION:
    APLYID_BASE_URL = 'https://app.aplyid.com/api/v2'
APLYID_API_KEY = os.environ.get('APLYID_API_KEY', '')
APLYID_API_SECRET = os.environ.get('APLYID_API_SECRET', '')
APLYID_WEBHOOK_BEARER_TOKEN = os.environ.get('APLYID_WEBHOOK_BEARER_TOKEN', '')
B2_ACCT_ID = os.environ.get('B2_ACCT_ID', '')
B2_APP_KEY = os.environ.get('B2_APP_KEY', '')
B2_BUCKET = os.environ.get('B2_BUCKET', '')
EZPAY_WEBSERVICE_ENDPOINT = os.environ.get('EZPAY_WEBSERVICE_ENDPOINT', '')
API_KEY = os.environ.get('API_KEY', '')
API_SECRET = os.environ.get('API_SECRET', '')
SITE_URL = os.environ.get('SITE_URL', '')
PARENT_SITE = os.environ.get('PARENT_SITE', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', '')
EMAIL_TO = os.environ.get('EMAIL_TO', '')
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
if not APLYID_API_KEY:
    print('ERROR: no aplyid api key')
    sys.exit(1)
if not APLYID_API_SECRET:
    print('ERROR: no aplyid api secret')
    sys.exit(1)
if not APLYID_WEBHOOK_BEARER_TOKEN:
    print('ERROR: no aplyid webhook bearer token')
    sys.exit(1)
if not B2_ACCT_ID:
    print('ERROR: no backblaze b2 account id')
    sys.exit(1)
if not B2_APP_KEY:
    print('ERROR: no backblaze b2 app key')
    sys.exit(1)
if not B2_BUCKET:
    print('ERROR: no backblaze b2 bucket')
    sys.exit(1)
if not EZPAY_WEBSERVICE_ENDPOINT:
    print('ERROR: no ezpay endpoint')
    sys.exit(1)
if not API_KEY:
    print('ERROR: no api key')
    sys.exit(1)
if not API_SECRET:
    print('ERROR: no api secret')
    sys.exit(1)
if not SITE_URL:
    print('ERROR: no site url')
    sys.exit(1)
if not PARENT_SITE:
    print('ERROR: no parent site')
    sys.exit(1)
if not EMAIL_FROM:
    print('ERROR: no from email')
    sys.exit(1)
if not EMAIL_TO:
    print('ERROR: no to email')
    sys.exit(1)
if not SENDGRID_API_KEY:
    print('ERROR: no sendgrid api key')
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

def aplyid_send_text(phone, token):
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        params = {'reference': token, 'contact_phone': phone}
        r = requests.post(APLYID_BASE_URL + '/send_text', headers=headers, json=params)
        r.raise_for_status()
        return r.json()['transaction_id']
    except Exception as ex:
        print('failed to get transaction id')
        print(ex)
    return None

def aplyid_download_pdf(transaction_id):
    try:
        headers = {'Aply-API-Key': APLYID_API_KEY, 'Aply-Secret': APLYID_API_SECRET}
        r = requests.get(APLYID_BASE_URL + '/biometric/pdf/%s.pdf' % transaction_id, headers=headers)
        r.raise_for_status()
        return BytesIO(r.content)
    except Exception as ex:
        print('failed to get pdf')
        print(ex)
        print(r.text)
    return None

def backblaze_auth_headers():
    # get auth token
    creds = base64.b64encode((B2_ACCT_ID + ':' + B2_APP_KEY).encode('ascii')).decode('ascii')
    headers = {'Authorization': 'Basic ' + creds}
    return headers

def backblaze_authorize_account():
    headers = backblaze_auth_headers()
    r = requests.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', headers=headers)
    r.raise_for_status()
    data = r.json()
    api_url = data['apiUrl']
    download_url = data['downloadUrl']
    auth_token = data['authorizationToken']
    return api_url, download_url, auth_token

def backblaze_get_bucket_id(api_url, auth_token):
    # if we have an application key get the account id that represents the mastker application key
    ACCOUNT_ID = B2_ACCT_ID
    if len(B2_ACCT_ID) > 12:
        ACCOUNT_ID = B2_ACCT_ID[3:][:12]
    headers = {'Authorization': auth_token}
    body = {'accountId': ACCOUNT_ID, 'bucketName': B2_BUCKET}
    r = requests.post(api_url + '/b2api/v2/b2_list_buckets', headers=headers, json=body)
    r.raise_for_status()
    data = r.json()
    bucket_id = data['buckets'][0]['bucketId']
    return bucket_id

def backblaze_get_upload_url(api_url, auth_token, bucket_id):
    headers = {'Authorization': auth_token}
    body = {'bucketId': bucket_id}
    r = requests.post(api_url + '/b2api/v2/b2_get_upload_url', headers=headers, json=body)
    r.raise_for_status()
    data = r.json()
    upload_url = data['uploadUrl']
    upload_auth_token = data['authorizationToken']
    return upload_url, upload_auth_token

def backblaze_upload_pdf(upload_url, upload_auth_token, token, pdf):
    # calc pdf size and sha1
    pdf_content = pdf.getbuffer()
    pdf_size = str(len(pdf_content))
    pdf_sha1 = hashlib.sha1(pdf_content).hexdigest()
    # upload pdf
    headers = {'Authorization': upload_auth_token, 'X-Bz-File-Name': '%s.pdf' % token, 'Content-Type': 'application/pdf', 'Content-Length': pdf_size, 'X-Bz-Content-Sha1': pdf_sha1}
    r = requests.post(upload_url, headers=headers, data=pdf_content)
    r.raise_for_status()

def backblaze_download_pdf(download_url, auth_token, token):
    headers = {'Authorization': auth_token}
    file_url = '{0}/file/{1}/{2}.pdf'.format(download_url, B2_BUCKET, token)
    r = requests.get(file_url, headers=headers)
    r.raise_for_status()
    return r.content

def backup_aplyid_pdf(token, transaction_id, pdf):
    try:
        api_url, download_url, auth_token = backblaze_authorize_account()
        bucket_id = backblaze_get_bucket_id(api_url, auth_token)
        upload_url, upload_auth_token = backblaze_get_upload_url(api_url, auth_token, bucket_id)
        backblaze_upload_pdf(upload_url, upload_auth_token, token, pdf)
        return True
    except Exception as ex:
        logger.error('failed to backup pdf')
        logger.error(ex)
    return False

def download_pdf_backup(token):
    try:
        api_url, download_url, auth_token = backblaze_authorize_account()
        pdf = backblaze_download_pdf(download_url, auth_token, token)
        return pdf
    except Exception as ex:
        logger.error('failed to download pdf')
        logger.error(ex)
    return None

def ezpay_get_verification_result(email, password):
    params = {"action": "userlogin", "email": email, "password": password, "pin": 1234, "pinagain": 1234}
    r = requests.post(EZPAY_WEBSERVICE_ENDPOINT, json=params)
    if r.status_code == 200:
        json = r.json()
        if json["success"]:
            if "creditlimit" in json and "creditstatus" in json:
                if json["creditstatus"] not in ("Applicant", "Declined", "EzPlus", "Pending", "Score"):
                    return True, None
        else:
            if json["message"] == "The email and password you entered don't match.":
                return False, json["message"]
            if json["message"] == "Your account does not appear to have ezpay setup. Please contact customer support.":
                return False, "Your account does not have EZPAY setup."
    return False, "Verification using EZPAY failed."

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

class AsyncRequest(threading.Thread):
    def __init__(self, task_name, url):
        threading.Thread.__init__(self)
        self.task_name = task_name
        self.url = url

    def run(self):
        try:
            logger.info('::%s - requesting: %s' % (self.task_name, self.url))
            requests.get(self.url)
        except:
            pass

def call_webhook(req):
    if req.webhook:
        AsyncRequest('kyc request webhook', req.webhook.url).start()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.route('/')
def hello():
    if PRODUCTION:
        return 'kyc svc'
    else:
        return 'kyc svc (DEV MODE)'

@app.route('/request', methods=['POST'])
def request_create():
    sig = request.headers.get('X-Signature')
    content = request.json
    api_key = content['api_key']
    token = content['token']
    email = content['email']
    webhook = None
    try:
        webhook = content['webhook']
    except:
        pass
    if not check_auth(api_key, sig, request.data):
        print('auth failure')
        abort(400)
    req = KycRequest.from_token(db_session, token)
    if req:
        print('%s already exists' % token)
        abort(400)
    print("creating for %s" % token)
    req = KycRequest(token)
    db_session.add(req)
    if webhook:
        logger.info(':: adding webhook: %s' % webhook)
        db_session.add(KycRequestWebhook(req, webhook))
    db_session.commit()
    # add user (store email in db)
    user = User.from_email(db_session, email)
    if not user:
        user = User(email)
        db_session.add(user)
        db_session.flush() # fill user.id
    user_request = UserRequest(user, req)
    db_session.add(user_request)
    db_session.commit()
    # render json
    return jsonify(req.to_json())

@app.route('/test_ezpay', methods=['POST'])
def test_ezpay():
    content = request.json
    email = content['email']
    password = content['password']
    result, verification_message = ezpay_get_verification_result(email, password)
    return jsonify({"email": email, "result": result, "verification_message": verification_message})

@app.route('/status', methods=['POST'])
def status():
    content = request.json
    token = content['token']
    print("looking for %s" % token)
    req = KycRequest.from_token(db_session, token)
    if req:
        return jsonify(req.to_json())
    return abort(404)

#def send_aplyid_notification_email(transaction_id, result):
#    print("sending email to %s" % EMAIL_TO)
#    subject = '%s verification' % SITE_URL
#    html_content = 'transaction id %s has result: %s<br/><br/>' % (transaction_id, result)
#    message = Mail(from_email=EMAIL_FROM, to_emails=EMAIL_TO, subject=subject, html_content=html_content)
#
#    sg = SendGridAPIClient(SENDGRID_API_KEY)
#    response = sg.send(message)

#@app.route('/request/<token>/reset', methods=['GET'])
#def request_action_reset(token=None):
#    req = KycRequest.from_token(db_session, token)
#    if not req:
#        return abort(404, 'sorry, request not found')
#    req.status = req.STATUS_CREATED
#    req.aplyid = None
#    db_session.add(req)
#    db_session.commit()
#    req = KycRequest.from_token(db_session, token)
#    return 'ok (req.aplyid = {})'.format(req.aplyid)

@app.route('/request/<token>', methods=['GET', 'POST'])
def request_action(token=None):
    req = KycRequest.from_token(db_session, token)
    if not req:
        return abort(404, 'sorry, request not found')
    # get user email from db
    email = ''
    user_req = UserRequest.from_request(db_session, req)
    if user_req:
        user = User.from_id(db_session, user_req.user_id)
        if user:
            email = user.email
    # process any posted data
    aplyid_transaction_id = None
    if req.aplyid:
        aplyid_transaction_id = req.aplyid.transaction_id
    verification_message = None
    if request.method == 'POST':
        aplyid_phone = request.form.get('aplyidPhone')
        if aplyid_phone:
            print("aplyid_phone: " + aplyid_phone)
            transaction_id = aplyid_send_text(aplyid_phone, req.token)
            if transaction_id:
                aplyid = AplyId(req, transaction_id)
                db_session.add(aplyid)
                db_session.commit()
                aplyid_transaction_id = transaction_id
            else:
                verification_message = 'unable to send text message, please ensure the mobile number is valid (country code first without the "+", followed by the phone number without any leading zeros "0")'
        # check ezpay verification
        ezpay_pass = request.form.get('ezpayPass')
        if ezpay_pass:
            result, verification_message = ezpay_get_verification_result(email, ezpay_pass)
            print(verification_message)
            if result:
                req.status = req.STATUS_COMPLETED
                db_session.add(req)
                db_session.commit()
                call_webhook(req)
    # render template
    return render_template('request.html', production=PRODUCTION, parent_site=PARENT_SITE, token=token, completed=req.status==req.STATUS_COMPLETED, email=email, aplyid_transaction_id=aplyid_transaction_id, verification_message=verification_message)

@app.route('/aplyid_pdf/<token>', methods=['GET'])
def aplyid_pdf(token=None):
    req = KycRequest.from_token(db_session, token)
    if not req:
        return abort(404, 'sorry, request not found')
    pdf = download_pdf_backup(token)
    if not pdf:
        return 'failed to download pdf'
    response = make_response(pdf)
    response.headers.set('Content-Type', 'application/pdf')
    return response

@app.route('/aplyid_webhook', methods=['POST'])
def aplyid_webhook():
    logger.info('aplyid webhook entry')
    # check bearer token
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return abort(403, 'auth header not present')
    parts = auth_header.split(' ')
    if len(parts) != 2 or parts[0] != 'Bearer' or parts[1] != APLYID_WEBHOOK_BEARER_TOKEN:
        return abort(403)
    logger.info('aplyid webhook authorized')
    # parse body
    if not request.is_json:
        logger.info('aplyid webhook not json')
        return 'ok'
    data = request.get_json(silent=True)
    if not data:
        logger.info('aplyid webhook payload is empty or was not parsable')
        return 'ok'
    logger.info('aplyid webhook, event: {0}, msg: {1}'.format(data['event'], data['message']))
    if (data['event'] == 'completed' or data['event'] == 'updated') and \
       'verification' in data and \
       (data['verification']['status'] == 'pass' or data['verification']['status'] == 'reviewed'):
        token = data['reference']
        transaction_id = data['transaction_id']
        req = KycRequest.from_token(db_session, token)
        if not req:
            logger.error('aplyid webhook error - request not found')
            return abort(404, 'sorry, request not found')
        if not req.aplyid or req.aplyid.transaction_id != transaction_id:
            logger.error('aplyid webhook error - transaction id does not match')
            return abort(404, 'sorry, transaction id does not match')
        req.status = req.STATUS_COMPLETED
        db_session.add(req)
        db_session.commit()
        call_webhook(req)
        logger.info('aplyid webhook completed - updated db')
        # save pdf
        pdf = aplyid_download_pdf(transaction_id)
        if not pdf:
            logger.error('aplyid webhook error - unable to download pdf')
            return abort(400, 'sorry, unable to download pdf')
        if not backup_aplyid_pdf(token, transaction_id, pdf):
            logger.error('aplyid webhook error - unable to backup pdf')
            return abort(400, 'sorry, unable to backup pdf')
    return 'ok'

#@app.route('/test_pdf_upload')
#def test_pdf_upload():
#    pdf = BytesIO(b'hello dan')
#    return str(backup_aplyid_pdf('token', 'transaction_id', pdf))
#
#@app.route('/test_pdf_download_upload/<transaction_id>')
#def test_pdf_download_upload(transaction_id):
#    pdf = aplyid_download_pdf(transaction_id)
#    if not pdf:
#        return 'failed to download pdf'
#    return str(backup_aplyid_pdf('token', transaction_id, pdf))
#
#@app.route('/test_pdf_download/<transaction_id>')
#def test_pdf_download(transaction_id):
#    from flask import send_file
#    pdf = aplyid_download_pdf(transaction_id)
#    if not pdf:
#        return 'failed to download pdf'
#    return send_file(pdf, attachment_filename='test.pdf', mimetype='application/pdf')
#
#@app.route('/test_send_text/<number>')
#def test_send_text(number):
#    transaction_id = aplyid_send_text(number, 't')
#    if not transaction_id:
#        return 'failed to send text'
#    return transaction_id

if __name__ == '__main__':
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
