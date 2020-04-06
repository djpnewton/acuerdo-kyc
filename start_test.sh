#/bin/bash

python3.7 -m pip install -r requirements.txt

export API_KEY=test
export API_SECRET=bigsecret

export GREENID_ACCOUNT_ID=zapnz
export GREENID_API_AUTH=SsG-43e-XSd-tCK
export GREENID_SIMPLEUI_AUTH=TCv-U9j-L88-gDb

export HARMONY_PASS=kW06qQcjccN8anHmcnQ9tjZWIKX4v8ug
export HARMONY_USER=zapnztestuser

export EZPAY_WEBSERVICE_ENDPOINT=https://www.redrat.co.nz/ezpay-app-json

export PARENT_SITE=nada

python3.7 app.py
