# Tweeto <img src = "/images/twitter_icon.png"/>

## Overview
<p>Our application intends to serve as a service that allows users to tweet at a later time. Users will have the capability of setting what day/time a tweet should be sent and they have the option 
to delete that queued tweet before the deadline.  In addition, they can send out multiple tweets at different times. </p>

## Getting Started
<p>Before you get started you need to have a valid <strong>Twitter API key</strong>(Consumer Key), <strong>API secret key</strong>(Consumer Secret key), <strong>Acceess token</strong>, <strong>Access token secret</strong>. These credentials are a requirement if you are going to access the Twitter API.
</p>

### Setup Twitter Developer Account and App (Requirements)
<ol>
  <li> Create a twitter account if you do not already have one. </li>
  <li> <a href="https://developer.twitter.com/en/apply/user"> Apply for a twitter developer account. </a> </li>
  <li> Enter phone number if you don't have one associated with your twitter.</li>
  <li> Add account details. Click on continue. </li>
  <li> Describe in your own words what you are building. Click on continue.</li>
  <li> Submit application. </li>
  <li> Check your email associated with your twitter and click Confirm your email. </li>
  <li> On the welcome screen, click on Create an app. </li>
  <li> First, click on your <strong>API key</strong> and <strong>API secret key</strong>. Second, click on create to get <strong>Access access token</strong> and <strong>access token secret</strong>. </li>
  <li> Click App permissions Edit button and enable <strong>Read, write and access Direct Messages<strong>. </li>
</ol>

## Requirements
- APScheduler==3.6.3
- boto3==1.16.30
- botocore==1.19.30
- certifi==2020.12.5
- chardet==3.0.4
- click==7.1.2
- Flask==1.1.2
- idna==2.10
- itsdangerous==1.1.0
- Jinja2==2.11.2
- jmespath==0.10.0
- MarkupSafe==1.1.1
- oauthlib==3.1.0
- PySocks==1.7.1
- python-dateutil==2.8.1
- python-dotenv==0.15.0
- pytz==2020.4
- requests==2.25.0
- requests-oauthlib==1.3.0
- s3transfer==0.3.3
- six==1.15.0
- tweepy==3.9.0
- tzlocal==2.1
- urllib3==1.26.2
- Werkzeug==1.0.1


## Flask Quickstart:

### Create virtual env

```console
python3 -m venv venv
Activate (on Mac):
. venv/bin/activate
```

```console
pip install -r requirements.txt
```

```console
pip install Flask
export FLASK_APP=app.py
flask run
```

## References Used
<p><a href="https://developer.twitter.com/en/portal/dashboard">Twitter Developers</a> - Twitter Developer Tool </p>
<p> <a href="http://docs.tweepy.org/en/latest/">Tweepy</a> - Tweepy Documentation </p>
<p> <a href="https://boto3.amazonaws.com/v1/documentation/api/latest/index.html">AWS</a> - Boto3 Documentation </p>

## Contributors

| Name          | Github        | 
| ------------- | ------------- | 
| Jorge Quiroz  | @JQuiroz728  | 
| Arun Ajay  | @arun-ajay  |
| Jiseon Yu | @JiseonYu  | 

