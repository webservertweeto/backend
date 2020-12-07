from flask import Flask, request
import boto3
import os
import botocore.exceptions
import botocore.errorfactory
import hmac
import hashlib
import base64
from os.path import join, dirname
from dotenv import load_dotenv
import json

app = Flask(__name__)
application = app


#----------------------------ENVIRONMENT VARIABLES----------------------------#
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
USER_POOL_ID = os.environ.get("USER_POOL_ID")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
AWS_ACCESS_KEY_ID=os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY=os.environ.get("AWS_SECRET_ACCESS_KEY")
REGION_NAME=os.environ.get("REGION_NAME")
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
    
    #Verify input parameters
    try:
        jsonData = request.json
        email = str(jsonData["email"])
        password = str(jsonData["password"])
        name = str(jsonData["name"])

    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email, passwoard, and your name."
        }
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True,
                'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
            },
            'body': body
        }

    try:
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)  
        resp = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(email,CLIENT_ID,CLIENT_SECRET),
            Username=email,
            Password=password, 
            UserAttributes=[
            {
                'Name': "name",
                'Value': name
            },
            {
                'Name': "email",
                'Value': email
            }
            ],
            ValidationData=[
            {
                'Name': "username",
                'Value': email
            }])
        body = {
            "Success": "Please check your email to retrieve the verification code."
        }
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True,
                'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
            },
            'body': body
        }
        
    except client.exceptions.UsernameExistsException as e:
        body = {
            "Error": "This account already exists."
        }
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True,
                'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
            },
            'body': body
        }
    except client.exceptions.InvalidPasswordException as e:
        body = {
            "Error": "Please ensure that your password has at least 8 characters and contains a mix of uppercase letters, lowercase letters, special characters and numbers."
        }
        return {
        'statusCode': 400,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True,
            'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
        },
        'body': body
        } 
        
    except botocore.exceptions.ParamValidationError as e:
        if len(email) == 0:
            body = {
                "Error": "Please provide a valid email address."
            }
        else:
            body = {
                "Error": "Please ensure that your password has at least 8 characters and contains a mix of uppercase letters, lowercase letters, special characters and numbers."
            }
        return {
        'statusCode': 400,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True,
            'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
        },
        'body': body
        } 

    except Exception as e:
        body = {
            "Error": "Something went wrong. Please check back at a later time."
        }
        print(str(e))
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True,
                'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
            },
            'body': body
        }    
    #Create registry in cognito

    body = {"Success": "All is good"}
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True,
            'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
        },
        'body': body

    }
    

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