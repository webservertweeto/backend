from flask import Flask, request
import boto3
from boto3.dynamodb.conditions import Key,Attr
import os
import botocore.exceptions
import botocore.errorfactory
import hmac
import hashlib
import base64
from os.path import join, dirname
from dotenv import load_dotenv
import json
import datetime

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
def authorizeuser(token):
    try:
        jsonData = request.json
        token = token
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)   
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an access token"
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
        resp = client.get_user(
            AccessToken = token
           )
        
        
        
        body = {
            "Success":"Your token is valid."
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

    except client.exceptions.NotAuthorizedException as e:
        errorMessage = str(e).lower()
        if "invalid" in errorMessage:
            body = {
                "Error": "You are not authorized to commit this action. Please log in to retrieve a valid access token."
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
        elif "expired" in errorMessage:
            body = {
                "Error": "Your session has expired. Please refresh your token."
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
        else:
            print(str(errorMessage))
            body = {
                "Error": "Something went wrong. We weren't able to validate your session. Please log in again."
            }
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
    except Exception as e:
            body = {
                "Error": "Something went wrong. We weren't able to validate your session. Please log in again."
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

def get_secret_hash(username,CLIENT_ID,CLIENT_SECRET):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


#----------------------------ROUTES----------------------------#
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
    
    #Verify input parameters
    try:
        jsonData = request.json
        username = str(jsonData["email"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email."
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
    
    #Resend confirmation code for signing up
    try:
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)  
        response = client.resend_confirmation_code(
        ClientId=CLIENT_ID,
        SecretHash=get_secret_hash(username,CLIENT_ID,CLIENT_SECRET),
        Username=username,
    )
        body = {
            "Success": "Done. If your account exists, you will be receiving a verification code via email shortly."
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
    
    except Exception as e:
        if len(username) == 0:
            body = {
                "Error": "Please provide a valid email."
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
        else:
            body = {
                "Error": "Something went wrong.Please check back at a later time."
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
    

#Cognito + DynamoDB
@app.route('/confirmsignup', methods = ["POST"])
def confirmsignup():
    
    #Verify input parameters
    try:
        jsonData = request.json
        username = str(jsonData["email"])
        code = str(jsonData["code"])
        consumerKey = str(jsonData["consumerKey"])
        consumerSecret = str(jsonData["consumerSecret"])
        accessTokenKey = str(jsonData["accessTokenKey"])
        accessTokenSecret = str(jsonData["accessTokenSecret"])
        twitterHandle = str(jsonData["twitterHandle"])
        twitterID = str(jsonData["twitterID"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email, verification code, consumer key, consumer secret, access token key, and access token secret."
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
        response = client.confirm_sign_up(
        ClientId=CLIENT_ID,
        SecretHash=get_secret_hash(username,CLIENT_ID,CLIENT_SECRET),
        Username=username,
        ConfirmationCode=code,
        ForceAliasCreation=False)
    
        body = {
            "Success": "Your account has been verified! Please log in."
        }
        
        tableName = "users"
        dynamoDB = boto3.resource('dynamodb',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        table = dynamoDB.Table(tableName)
        
        today = datetime.datetime.now()
        dateString = str(today.month) + "/" + str(today.day) + "/" + str(today.year) 
        
        table.put_item(
            Item = {
                'email': username,
                'twitterid':twitterID,
                'twitterHandle': twitterHandle,
                'consumerKey': consumerKey,
                'consumerSecret': consumerSecret,
                'accessTokenKey': accessTokenKey,
                'accessTokenSecret': accessTokenSecret,
                'dateJoined': dateString
            })
        
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
    except client.exceptions.ExpiredCodeException as e:
        print(str(e))
        body = {
            "Error": "This code has already expired. Please request for a new one."
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
    except client.exceptions.CodeMismatchException:
        body = {
            "Error": "You have provided an invalid code. Please double-check your email or request for a new code."
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
        
    except client.exceptions.NotAuthorizedException:
        body = {
            "Error": "This user has already been confirmed."
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
        print(str(e))
        body = {
            "Error": "Something went wrong. Please check back at a later time."
        }
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

#Cognito
@app.route('/login', methods = ["POST"])
def login():
    def awslogin(client, username, password,CLIENT_ID,CLIENT_SECRET):
        secret_hash = get_secret_hash(username,CLIENT_ID,CLIENT_SECRET)
        try:
            response = client.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'SECRET_HASH': secret_hash,
                    'PASSWORD': password,
                },
                ClientMetadata={
                'username': username,
                'password': password})
            
            return response,None
        except client.exceptions.NotAuthorizedException:
            return None, {
                "Error": "Invalid username/password combination."
            }
        except client.exceptions.UserNotConfirmedException:
            return None, {
                "Error": "Please ensure your account has been verfied via email first before signing in."
            }
        except Exception as e:
            print(str(e))
            return None,{
                "Error": "Something went wrong. Please check back at a later time."
            }
    
    #Verify input parameters
    try:
        jsonData = request.json
        username = str(jsonData["email"])
        password = str(jsonData["password"])
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)   
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email and password"
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

    response, errorMessage = awslogin(client, username, password,CLIENT_ID,CLIENT_SECRET)
    
    if errorMessage != None:
        if "Something" in errorMessage["Error"]:
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True,
                    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
                },
                'body': errorMessage
            }
        else:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Headers': 'Content-Type,Origin,X-Amz-Date,Authorization,X-Api-Key,x-requested-with,Access-Control-Allow-Origin,Access-Control-Request-Method,Access-Control-Request-Headers',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True,
                    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,PATCH,OPTIONS'
                },
                'body': errorMessage
            }
    if response.get("AuthenticationResult"):
        body = { 
               "id_token": response["AuthenticationResult"]["IdToken"],
               "refresh_token": response["AuthenticationResult"]["RefreshToken"],
               "access_token": response["AuthenticationResult"]["AccessToken"]
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
    else:
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

#Cognito + DynamoDB
@app.route('/getuser', methods = ["POST"])
def getuser():
    try:
        jsonData = request.json
        token = str(jsonData["token"])
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)   
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an access token"
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
        resp = client.get_user(
            AccessToken = token
           )
        
        userAttributes = resp["UserAttributes"]
        
        body = {}
        
        for attribute in userAttributes:
            if attribute["Name"] == "name":
                body["name"] = attribute["Value"]
            elif attribute["Name"] == "email":
                body["email"] = attribute["Value"]
            elif attribute["Name"] == "sub":
                body["AWSusername"] = attribute["Value"]
        
        tableName = "users"
        dynamoDB = boto3.resource('dynamodb',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        table = dynamoDB.Table(tableName)
        
        
        response = table.query(
            KeyConditionExpression = Key('email').eq(body["email"])
        )

        body["twitterAccounts"] = []
        items = response["Items"]

        for item in items:
            del item["email"]
            body["twitterAccounts"].append(item)
        
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

    except client.exceptions.NotAuthorizedException as e:
        errorMessage = str(e).lower()
        print(errorMessage)
        if "invalid" in errorMessage:
            body = {
                "Error": "You are not authorized to commit this action. Please log in to retrieve a valid access token."
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
        elif "expired" in errorMessage:
            body = {
                "Error": "Your session has expired."
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
        else:
            print(str(e))
            body = {
                "Error": "Something went wrong. We weren't able to validate your session. Please log in again."
            }
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
    except Exception as e:
            body = {
                "Error": "Something went wrong. We weren't able to validate your session. Please log in again."
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

#Cognito
@app.route('/forgotpassword', methods = ["POST"])
def forgotpassword():
    
    #Verify input parameters
    try:
        jsonData = request.json
        username = str(jsonData["email"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email."
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
        response = client.forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username,CLIENT_ID,CLIENT_SECRET),
            Username=username,
            
        )
        body = {
            "Success": "Done. If your account exists, you will be receiving an email to trigger your password reset."
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
    
    except Exception as e:
        body = {
            "Success": "Something went wrong. Please check back at a later time."
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

#Cognito
@app.route('/confirmpasswordreset', methods = ["POST"])
def confirmpasswordreset():
    
    #Verify input parameters
    try:
        jsonData = request.json
        username = str(jsonData["email"])
        password = str(jsonData["password"])
        code = str(jsonData["code"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide an email, password, and code"
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
        
        client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username,CLIENT_ID,CLIENT_SECRET),
            Username=username,
            ConfirmationCode=code,
            Password=password,
           )
        body = {
            "Success": "You have successfully changed your password. Please proceed to log in."
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
    except client.exceptions.CodeMismatchException as e:
        body = {
            "Error": "You have provided an invalid code."
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
        if len(username) == 0:
            body = {
                "Error": "Please provide a valid email address."
            }
        else:
            body = {
                "Error": "Please ensure that your new password has at least 8 characters and contains a mix of uppercase letters, lowercase letters, special characters and numbers."
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
    except client.exceptions.ExpiredCodeException as e:
        body = {
            "Success": "Your code has expired. Please request for a new one."
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
            "Success": "Something went wrong. Please check back at a later time."
        }
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


#Twitter
@app.route('/gettwitteraccountinformation', methods = ["POST"])
def gettwitteraccountinformation():
    
    #Verify input parameters
    try:
        jsonData = request.json
        consumerKey = str(jsonData["consumerKey"])
        consumerSecret = str(jsonData["consumerSecret"])
        accessTokenKey = str(jsonData["accessTokenKey"])
        accessTokenSecret = str(jsonData["accessTokenSecret"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide a consumer key, consumer secret, access token key, and access token secret."
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
        #JISEON CALL TWITTER API HERE

        #USE VARIABLES ABOVE TO RETRIEVE INFORMATION FOR VARIABLES BELOW, I PUT PLACE HOLDER "TBD"

        twitterID = "TBD"
        twitterHandle = "TBD"
        twitterPicture = "TBD"

        body = {
            "twitterID": twitterID,
            "twitterHandle": twitterHandle,
            "twitterPicture" : twitterPicture
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

    except Exception as e:
        print(str(e))

        body = {
            "Error": "Something went wrong. Please try again at a later time."
        }
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

#Cognito + Dynamo
@app.route('/addnewtwitteraccount', methods = ["POST"])
def addnewtwitteraccount():
    
    #Verify input parameters
    try:
        jsonData = request.json
        token = str(jsonData["token"])
        consumerKey = str(jsonData["consumerKey"])
        consumerSecret = str(jsonData["consumerSecret"])
        accessTokenKey = str(jsonData["accessTokenKey"])
        accessTokenSecret = str(jsonData["accessTokenSecret"])
        twitterHandle = str(jsonData["twitterHandle"])
        twitterID = str(jsonData["twitterID"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide a token, twitter handle, twitter id, consumer key, consumer secret, access token key, and access token secret."
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

    #Authenticate the user
    authResponse = authorizeuser(token = token)
    if "Error" in authResponse["body"]:
        return authResponse

    #Update database
    try:
        client = boto3.client('cognito-idp',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        
        resp = client.get_user(
            AccessToken = token
           )
        
        userAttributes = resp["UserAttributes"]
        
        userData = {}
        
        for attribute in userAttributes:
            if attribute["Name"] == "name":
                userData["name"] = attribute["Value"]
            elif attribute["Name"] == "email":
                userData["email"] = attribute["Value"]
            elif attribute["Name"] == "sub":
                userData["AWSusername"] = attribute["Value"]
        
        tableName = "users"
        dynamoDB = boto3.resource('dynamodb',
                                region_name=REGION_NAME,
                                aws_access_key_id=AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        table = dynamoDB.Table(tableName)

        response = table.query(
            KeyConditionExpression = Key('email').eq(userData["email"])
        )

        
        items = response["Items"]

        for item in items:
            if item["twitterid"] == twitterID:
                body = {
                    "Error": "You have already registered this account."
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

        
        today = datetime.datetime.now()
        dateString = str(today.month) + "/" + str(today.day) + "/" + str(today.year) 
        
        table.put_item(
            Item = {
                'email': userData["email"],
                'twitterid':twitterID,
                'twitterHandle': twitterHandle,
                'consumerKey': consumerKey,
                'consumerSecret': consumerSecret,
                'accessTokenKey': accessTokenKey,
                'accessTokenSecret': accessTokenSecret,
                'dateJoined': dateString
            })
        
        body = {
            "Success":"Your account has been registered."
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
    except Exception as e:
        print(str(e))
        body = {
            "Error": "Something went wrong. Please try again later."
        }
        
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
 

#Twitter
@app.route('/getlatesttweets', methods = ["POST"])
def getlatesttweets():
    
    #Verify input parameters
    try:
        jsonData = request.json
        consumerKey = str(jsonData["consumerKey"])
        consumerSecret = str(jsonData["consumerSecret"])
        accessTokenKey = str(jsonData["accessTokenKey"])
        accessTokenSecret = str(jsonData["accessTokenSecret"])
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide a consumer key, consumer secret, access token key, and access token secret."
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
    
    #Get latest tweets here
    try:
        #do twitter stuff here Jiseon, get 5 latest tweets
        #Make it a list of JSON objects
        #Each object should have: twitter handle, twitter post date, twitter profile picture, message, photo (if they uploaded a photo)
        latestTweets = []

        body = {
            "Data": latestTweets
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
    
    except Exception as e:
        print(str(e))
        body = {
            "Error" : "You must provide a consumer key, consumer secret, access token key, and access token secret."
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

#Cognito + Dynamo
@app.route('/getscheduledtweets', methods = ["POST"])
def getscheduledtweets():
    pass

#Cognito + Dynamo
@app.route('/scheduleatweet', methods = ["POST"])
def scheduleatweet():
    pass

#Delete a scheduled tweet
@app.route('/deleteascheduledtweet', methods = ["POST"])
def deleteascheduledtweet():
    pass

if __name__ == '__main__':


    app.run()