from flask import Flask, request, jsonify
import boto3
import os

app = Flask(__name__)
application = app


#----------------------------HELPER FUNCTIONS----------------------------#
def authorizeuser():
    pass

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
def signup():
    pass

#Cognito
@app.route('/forgotpassword', methods = ["POST"])
def forgotpassword():
    pass

#Cognito
@app.route('/confirmforgotpassword', methods = ["POST"])
def confirmforgotpassword():
    pass


