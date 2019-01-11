import flask_login
import sqlalchemy
from fitbit.exceptions import BadResponse
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import logout_user, login_required, login_user
from flask import abort, make_response

from app import db
from app.fitbit_client import fitbit_client, get_permission_screen_url, do_fitbit_auth, do_subscription
from app.main.forms import RegistrationForm, LoginForm
from app.models import User, get_user_fitbit_credentials
from . import main
from pprint import pprint
import pandas as pd
import json
from pandas.io.json import json_normalize
from datetime import date, timedelta
import pdb


@main.route('/get_activity_stats', methods=['GET'])
def get_activity_stats():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        data = ''
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    #ls  = client.time_series('activities/calories', period='1y')
                    #ls = client.activity_stats()
                    #ls = client.list_subscriptions()
                    #data = ls['activities-calories']
                    ls  = client.activity_stats(qualifier='favorite')
                    # r = json.dumps(ls)
                    # d = json.loads(r)
                    # data = json_normalize(d['activities-calories'])
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activity_stats.html',  data= ls)   

@main.route('/get_intraday_heart_rate', methods=['GET'])
def get_intraday_heart_rate():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        data = ''
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get('')
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    ls  = client.intraday_time_series('activities/heart')
                    ls  = client.time_series('activities/heart', period='1y')
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d['activities-heart'])
                    data = ls
                
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('intraday_heart_data.html',  activities= data)  

@main.route('/get_calerories', methods=['GET'])
def get_calerories():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        data = ''
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    #ls  = client.time_series('activities/calories', period='1y')
                    #ls = client.activity_stats()
                    #ls = client.list_subscriptions()
                    #data = ls['activities-calories']
                    ls  = client.time_series('activities/calories', period='1y')
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d['activities-calories'])
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activities.html',  data= data)   
        

@main.route('/get_steps', methods=['GET'])
def get_steps():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        data = ''
        file_path = '/export/sc-ehealth01/fitbit/fitbit-data-collection/data/'
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get()
                    user_profile = "{} UserId: {} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['encodedId'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    ls  = client.time_series('activities/steps', period='1y')
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d['activities-steps'])
                    
                    df = pd.DataFrame()
                    df = df.append({'fitbit_user_id': profile_response['user']['encodedId'] ,
                                    'full_name': profile_response['user']['fullName'],
                                    'json_value': d}, ignore_index=True)

                    #f = ls['activities-steps']
                    #df.to_csv('filename.csv', mode='a', header=False)
                    df.to_csv( file_path + 'activities_steps.csv', mode='a', header=False, sep=',', index=False, encoding='utf-8')

                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activities_steps.html', user_profile=user_profile, data=data, df=df)       
        
        
@main.route('/get_distance', methods=['GET'])
def get_distance():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        data = ''
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    ls  = client.time_series('activities/distance', period='1y')
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d['activities-distance'])
                    
                
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activities_distance.html',  data= data)      
        
        
@main.route('/get_sleep_data', methods=['GET'])
def get_sleepdata():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        data = ''
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )
                    
                    week_sleep_data = []
                    #week_date_range = (date.today() - timedelta(days=x) for x in xrange(30))
                    #week_data_range = ((date.today() - timedelta(days=240)) - (date.today() - timedelta(days=260))
                    
                    week_date_range = (date.today() - timedelta(days=240) - timedelta(days=x) for x in xrange(30))
                    for day in week_date_range:
                        day_sleep_data = client.sleep(date=day)
                        week_sleep_data.append(day_sleep_data)
                    
                    ls = week_sleep_data
                    
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d)
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activities_sleep.html',  data= data)              
        
        
@main.route('/get_heartrates', methods=['GET'])
def get_heartrates():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        data = ''
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    ls  = client.time_series('activities/heart', period='1y')
                    #ls = client.activity_stats()
                    #ls = client.list_subscriptions()
                    #data = ls['activities-heart']
                    r = json.dumps(ls)
                    d = json.loads(r)
                    data = json_normalize(d['activities-heart'])
                
                
                except BadResponse:
                    flash("Api Call Failed")
                    
        return render_template('activities_heartrate.html',  data= data)              
        
                        

@main.route('/fitbit/webhook', methods=['GET', 'POST'])
def get_updates():
    updates = request.args.get('updates')
    # resp = make_response('', 204)
    # resp.headers['Content-Length'] = 0
    return render_template('updates.html', updates= updates), 204

def verify_fitbit_subscription():
    code = request.args.get('verify')
    if code == 'a21fe8a950806b401db053a94a210dfcf8856527615288c370fd11929cadeb9d':
        resp = make_response('', 204)
        resp.headers['Content-Length'] = 0
        return resp
    else:
        resp = make_response('', 404)
        resp.headers['Content-Length'] = 0
        return resp

@main.route('/', methods=['GET', 'POST'])
def index():
    if not flask_login.current_user.is_authenticated:
        return redirect(url_for('main.login'))
    else:
        user_profile = "Could not access fitbit profile"
        ls = 'Subscription List is Empty!'
        data = ''
        fitbit_creds = get_user_fitbit_credentials(flask_login.current_user.id)
        if fitbit_creds:
            with fitbit_client(fitbit_creds) as client:
                try:
                    
                    profile_response = client.user_profile_get()
                    user_profile = "{} has been on fitbit since {}".format(
                        profile_response['user']['fullName'],
                        profile_response['user']['memberSince']
                    )

                    #client.subscription(flask_login.current_user.id, '100')
                    #ls  = client.time_series('activities/calories', period='1y')
                    #ls = client.activity_stats()
                    #ls = client.list_subscriptions()
                    #pprint(ls)
                    #data = ls['activities-calories']
                    
                except BadResponse:
                    
                    flash("Api Call Failed")
        return render_template('index.html', user_profile=user_profile, permission_url=get_permission_screen_url())


@main.route('/oauth-redirect', methods=['GET'])
@login_required
def handle_redirect():
    code = request.args.get('code')
    do_fitbit_auth(code, flask_login.current_user)
    return redirect(url_for('main.index'))


@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    status = 200
    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.validate(form.password.data):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid Credentials')
            status = 401
    return render_template('login.html', form=form), status


@main.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged Out')
    return redirect(url_for('main.login'))


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    status = 200
    if request.method == 'POST' and form.validate():
        user = User(
            form.username.data,
            form.password.data
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('Thanks for registering')
            return redirect(url_for('main.login'))
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()
            flash('Username {} already taken'.format(form.username.data))
            status = 400

    return render_template('register.html', form=form), status


@main.route('/api_subscriptions')
def api_subscription():
    return redirect(url_for('main.login'))
