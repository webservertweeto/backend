from flask import Flask, request, jsonify
import boto3
import os
import botocore.exceptions
import botocore.errorfactory
import hmac
import hashlib
import base64
from os.path import join, dirname
from dotenv import load_dotenv


app = Flask(__name__)
application = app
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
USER_POOL_ID = os.environ.get("USER_POOL_ID")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

#----------------------------HELPER FUNCTIONS----------------------------#
def authorizeuser():
    pass

def get_secret_hash(username,CLIENT_ID,CLIENT_SECRET):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

#Cognito
@app.route('/signup', methods = ["POST"])
def signup():

    pass

#Cognito
@app.route('/resendverificationcode', methods = ["POST"])
def resendverificationcode():
    pass

#Cognito + DynamoDB
@app.route('/confirmsignup', methods = ["POST"])
def confirmsignup():
    pass


#Cognito
@app.route('/login', methods = ["POST"])
def login():
    pass

#Cognito + DynamoDB
@app.route('/getuser', methods = ["POST"])
def getuser():
    pass

#Cognito
@app.route('/forgotpassword', methods = ["POST"])
def forgotpassword():
    pass

#Cognito
@app.route('/confirmforgotpassword', methods = ["POST"])
def confirmforgotpassword():
    pass


if __name__ == '__main__':


    app.run()