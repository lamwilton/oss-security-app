from flask import Flask, render_template, session, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import NumberRange, DataRequired
import numpy as np
from tensorflow.keras.models import load_model
import joblib

global NUM_COLUMNS
NUM_COLUMNS = 81


def return_prediction(model, scaler, sample_json):
    THRESHOLD = 0.565554
    data = np.zeros(NUM_COLUMNS)

    data[0] = sample_json['f0']
    data[1] = sample_json['f1']
    data[2] = sample_json['f2']
    data[3] = sample_json['f3']
    data[4] = sample_json['f4']
    data[5] = sample_json['f5']
    data[6] = sample_json['f6']
    data[7] = sample_json['f7']
    data[8] = sample_json['f8']
    data[9] = sample_json['f9']
    data[10] = sample_json['f10']
    data[11] = sample_json['f11']
    data[12] = sample_json['f12']
    data[13] = sample_json['f13']
    data[14] = sample_json['f14']
    data[15] = sample_json['f15']

    data = scaler.transform([data])
    result = model.predict(data)
    if result[0][0] > THRESHOLD:
        return str(result[0][0]) + ", which is greater than the optimal threshold of 0.565554. It is likely to be security related."
    else:
        return str(result[0][0]) + ", which is less than the optimal threshold of 0.565554. It is unlikely to be security related."
    return result

app = Flask(__name__)
# Configure a secret SECRET_KEY
app.config['SECRET_KEY'] = '00000000'


# Load the model and scaler
model = load_model('model_security_mode_817')
scaler = joblib.load('my_scaler.pkl')


# Create WTForm class

class MyForm(FlaskForm):
    columns = ['file', 'auth', 'authorize', 'authenticate', 'AES', 'DES', 'Fish',
       'blowfish', 'Twofish', 'Kerberos', 'Ciph', 'CBC', 'credential', 'cert',
       'Crypt', 'encrypt', 'decrypt', 'Rijndael', 'Anubis', 'X.509', 'Khazad',
       'Escal of Privilege', 'Multi-Term', 'GRE', 'hash', 'key', 'publickey',
       'privatekey', 'Proxy', 'ELGamal', 'DSA', 'RSA', 'DSS', 'DER', 'BER',
       'code', 'encode', 'decode', 'ftp', 'sftp', 'pass', 'policy', 'PBE',
       'POP', 'http', 'https', 'UDP', 'TCP', 'MD', 'luks', 'protocol', 'RFC',
       'Hellman', 'secur', 'salt', 'Sandbox', 'VPN', 'VNC', 'SHA', 'SSH',
       'X11', 'SSL', 'SSO', 'Realm', 'TLS', 'token', 'utf', 'Session',
       'socket', 'port', 'connect', 'firewall', 'acl', 'secret', 'virus',
       'password', 'access', 'login', 'comments_whole', 'logical_SLOC',
       'physical_SLOC']
    field = []
    f0 = StringField(columns[0], default=0, validators=[DataRequired()])
    f1 = StringField(columns[1], default=0, validators=[DataRequired()])
    f2 = StringField(columns[2], default=0, validators=[DataRequired()])
    f3 = StringField(columns[3], default=0, validators=[DataRequired()])
    f4 = StringField(columns[4], default=0, validators=[DataRequired()])
    f5 = StringField(columns[5], default=0, validators=[DataRequired()])
    f6 = StringField(columns[6], default=0, validators=[DataRequired()])
    f7 = StringField(columns[7], default=0, validators=[DataRequired()])
    f8 = StringField(columns[8], default=0, validators=[DataRequired()])
    f9 = StringField(columns[9], default=0, validators=[DataRequired()])
    f10 = StringField(columns[10], default=0, validators=[DataRequired()])
    f11 = StringField(columns[11], default=0, validators=[DataRequired()])
    f12 = StringField(columns[12], default=0, validators=[DataRequired()])
    f13 = StringField(columns[13], default=0, validators=[DataRequired()])
    f14 = StringField(columns[14], default=0, validators=[DataRequired()])
    f15 = StringField(columns[15], default=0, validators=[DataRequired()])
    submit = SubmitField('Analyze')


@app.route('/', methods=['GET', 'POST'])
def index():
    # Create instance of form
    form = MyForm()
    # If the form is valid on submission
    if form.validate_on_submit():
        # Grab the data from the input on the form
        session['f0'] = form.f0.data
        session['f1'] = form.f1.data
        session['f2'] = form.f2.data
        session['f3'] = form.f3.data
        session['f4'] = form.f4.data
        session['f5'] = form.f5.data
        session['f6'] = form.f6.data
        session['f7'] = form.f7.data
        session['f8'] = form.f8.data
        session['f9'] = form.f9.data
        session['f10'] = form.f10.data
        session['f11'] = form.f11.data
        session['f12'] = form.f12.data
        session['f13'] = form.f13.data
        session['f14'] = form.f14.data
        session['f15'] = form.f15.data

        return redirect(url_for("prediction"))
    return render_template('home.html', form=form)


@app.route('/prediction')
def prediction():
    # Defining content dictionary
    try:
        content = {}
        content['f0'] = int(session['f0'])
        content['f1'] = int(session['f1'])
        content['f2'] = int(session['f2'])
        content['f3'] = int(session['f3'])
        content['f4'] = int(session['f4'])
        content['f5'] = int(session['f5'])
        content['f6'] = int(session['f6'])
        content['f7'] = int(session['f7'])
        content['f8'] = int(session['f8'])
        content['f9'] = int(session['f9'])
        content['f10'] = int(session['f10'])
        content['f11'] = int(session['f11'])
        content['f12'] = int(session['f12'])
        content['f13'] = int(session['f13'])
        content['f14'] = int(session['f14'])
        content['f15'] = int(session['f15'])
    
        results = return_prediction(model=model, scaler=scaler, sample_json=content)
    except:
        return "Somethings wrong with the input data. Please check again!"
    return render_template('prediction.html', results=results)
