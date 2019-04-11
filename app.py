#!/usr/bin/python3
import os
import logging

from flask import Flask

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
    return 'Hello World!'

if __name__ == '__main__':
    setup_logging(logging.DEBUG)

    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
