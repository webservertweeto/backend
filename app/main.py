from flask import Flask, request
import requests
import os
import tweepy
from dotenv import load_dotenv  # access to .evn file
load_dotenv()


app = Flask(__name__)

#----------------------------ENVIRONMENT VARIABLES----------------------------#
CONSUMER_KEY = os.environ['CONSUMER_KEY']
CONSUMER_SECRET = os.environ['CONSUMER_SECRET']
ACCESS_TOKEN = os.environ['ACCESS_TOKEN']
ACCESS_SECRET = os.environ['ACCESS_SECRET']
BEARER_TOKEN = os.environ['BEARER_TOKEN']
ID = os.environ['ID']

#------------------------------AUTH Tweepy KEYS-------------------------------#
# authentication of consumer key and secret
auth = tweepy.OAuthHandler(CONSUMER_KEY, CONSUMER_SECRET)
# authentication of access token and secret
auth.set_access_token(ACCESS_TOKEN, ACCESS_SECRET)
api = tweepy.API(auth)

#-----------------------------------------------------------------------------#


def auth():
    return os.environ.get("BEARER_TOKEN")


def create_url():
    id = os.environ.get("ID")
    user_fields = 'user.fields=created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url,protected,url,username,verified,withheld,public_metrics'
    url = "https://api.twitter.com/2/users/{}?{}".format(id, user_fields)
    return url
    # https://api.twitter.com/2/users/:id?user.fields=created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url,protected,url,username,verified,withheld


def create_headers(bearer_token):
    headers = {"Authorization": "Bearer {}".format(bearer_token)}
    return headers


def connect_to_endpoint(url, headers):
    response = requests.request("GET", url, headers=headers)
    print(response.status_code)
    if response.status_code != 200:
        raise Exception(
            "Request returned an error: {} {}".format(
                response.status_code, response.text
            )
        )
    return response.json()


@app.route('/getAccountInformation', methods=['POST'])
def getAccountInformation():
    #     ASSUME THE FRONT-END GIVES YOU THE FOLLOWING:
    # ⦁    consumer key
    # ⦁    consumer secret
    # ⦁    access token
    # ⦁    access secret
    bearer_token = auth()
    url = create_url()
    headers = create_headers(bearer_token)
    json_response = connect_to_endpoint(url, headers)

    data_dict = {}
    get_acc_info = []
    get_acc_info.append({
        'profile_image_url': json_response['data']['profile_image_url'],
        'username': json_response['data']['username'],
        'handle_id': json_response['data']['id'],
    })
    data_dict['data'] = get_acc_info
    # print(data_dict)
    return data_dict

    # OUTPUT:
    # {'data': [{'profile_image_url': 'https://pbs.twimg.com/profile_images/1335701436697604100/sVl6dNAO_normal.jpg',
    # 'username': 'jiseon_yu94',
    # 'handle_id': '1316875711249088513'}]}


#-----------------------------------------------------------------------------#


@app.route('/verifyAccount', methods=['POST'])
def verifyAccount():
    #     ASSUME THE FRONT-END GIVES YOU THE FOLLOWING:
    # ⦁    consumer key
    # ⦁    consumer secret
    # ⦁    access token
    # ⦁    access secret
    # ⦁    response ("yes","no")
    # ⦁    email
    # ⦁    verificationCode
    # ⦁    twitterHandleName
    # ⦁    twitterID

    # Return
    # Nothing

    #-----------------------------------------------------------------------------#


@app.route('/scheduleTweetToDatabase', methods=['POST'])
def scheduleTweetToDatabase():

    #     ASSUME THE FRONT-END GIVES YOU THE FOLLOWING:
    # ⦁    AWS_ACCESS_TOKEN
    # ⦁    Message (Tell Jorge to enforce 256 characters)
    # ⦁    Picture (BASE64 ENCODE)
    # ⦁    Picture extension (.png or .jpg)
    # ⦁    Time
    # Returns
    # Nothing

    #-----------------------------------------------------------------------------#


@app.route('/deleteScheduledTweetFromDatabase', methods=['POST'])
def deleteScheduledTweetFromDatabase():
    #     ASSUME THE FRONT-END GIVES YOU THE FOLLOWING:
    # ⦁    AWS_ACCESS_TOKEN
    # ⦁    TweetID (uuid that arun makes in database)

    # Returns
    # Nothing

    #-----------------------------------------------------------------------------#


def get_date_time(date_time_str):
    date_time_obj = None
    error_code = None
    try:
        date_time_obj = datetime.strptime(
            date_time_str, "%Y-%m-%dT%H:%M:%SZ")  # ISO time zone
    except ValueError as e:
        error_code = f'Error! {e}'
    if date_time_obj is not None:
        now_time_edt = datetime.utcnow() - timedelta(hours=5)
        if not date_time_obj > now_time_edt:
            error_code = "Error! time must be in the future"
    return date_time_obj, error_code

########CONVERT an image to BASE64 ENCODE for `sendTweet() function ############
# def get_base64_encoded_image(image_path):
#     with open(image_path, "rb") as img_file:
#         return base64.b64encode(img_file.read()).decode('utf-8')

# im = Image.open(image_path)  # JPEG
#######################################################


@app.route('/sendTweet', methods=['POST'])
def sendTweet():

    while True:
        # 1. GET DATA FROM DB
        # 2. GET CURRENT_TIME
        current_time = datetime.utcnow() - timedelta(hours=5)

    # 3. time.sleep(INTERVAL) INTERVAL = 2 seconds / refresh every 2 sec - I don't think we need it.
    # 4.
        #     ASSUME THE DATABASE GIVES YOU THE FOLLOWING:
        # ⦁    -> `msg`(STRING) = Message (Tell Jorge to enforce 256 characters)
        # ⦁    Picture (BASE64 ENCODE)
        # ⦁    Picture extension (.png or .jpg)
        #       -> `image_path`(STRING): ONLY url format
        # ⦁    CONSUMER_KEY
        # ⦁    CONSUMER_SECRET
        # ⦁    ACCESS_TOKEN
        # ⦁    ACCESS_SECRET
        # *   -> `date_time_obj`(STRING) = time when a user posts a message / HAS TO BE ISO-860 time zone format

        msg =  # FROM THE DB
        if not msg:
            return "Error! no message!"
        time =  # FROM THE DB
        if not time:
            return "ERROR! no time entered"

        if len(msg) > 280:
            return "ERROR! message too long"

        # Assume that date_time_obj is STRING
        date_time_obj, error_code = get_date_time(
            time)  # Convert time to ISO time zone
        if error_code is not None:
            return error_code

        if data_time_obj < str(current_time):
            try:
                # POST if only tweet message exists
                if not image_path:
                    api.update_status(status=msg)
                # POST if tweet + image_path both exist
                else:
                    api.update_with_media(image_path, msg)

                # 5. update database
            except Exception as e:
                print(str(e))


#-----------------------------------------------------------------------------#

@app.route('/showRecentTweets', methods=['POST'])
def showRecentTweets(screen_name)):
    #     ASSUME THE DATABASE GIVES YOU THE FOLLOWING:
    # ⦁    consumer key
    # ⦁    consumer secret
    # ⦁    access token
    # ⦁    access secret
    # Returns
    # A list of the last 5 or 10 tweets (list of json objects)
    # [
    # {
    # profile picture  - 'profile_image_url'
    # twitter ID - 'id'
    # twitter message + twitter attached picture(?) in message - 'text
    # time sent - 'created_at'
    # number of retweets,commetns,likes
      # 'retweet_count'
      # 
    # }
    # ]
    data_dict = {}
    arr_dict = []

    statuses = api.user_timeline(screen_name=screen_name, count=200)
    #s = statuses[0]
    # print(s._json['user']['profile_image_url'])
    # print(s._json['profile_image_url'])

    for status in statuses:
        s = statuses[0]
        arr_dict.append({
            'id': s._json['user']['id'],
            'profile_image_url': s._json['user']['profile_image_url'],
            'text': s._json['text'],
            'created_at': s._json['user']['created_at'],
            'retweet_count': s._json['retweet_count'],
            'followers_count': s._json['user']['followers_count'],
            'friends_count': s._json['user']['followers_count'],
        })
    data_dict['data'] = arr_dict
    return data_dict
    #print(data_dict)



if __name__ == "__main__":
    getAccountInformation()
