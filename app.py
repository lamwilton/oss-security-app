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
    data[16] = sample_json['f16']
    data[17] = sample_json['f17']
    data[18] = sample_json['f18']
    data[19] = sample_json['f19']
    data[20] = sample_json['f20']
    data[21] = sample_json['f21']
    data[22] = sample_json['f22']
    data[23] = sample_json['f23']
    data[24] = sample_json['f24']
    data[25] = sample_json['f25']
    data[26] = sample_json['f26']
    data[27] = sample_json['f27']
    data[28] = sample_json['f28']
    data[29] = sample_json['f29']
    data[30] = sample_json['f30']
    data[31] = sample_json['f31']
    data[32] = sample_json['f32']
    data[33] = sample_json['f33']
    data[34] = sample_json['f34']
    data[35] = sample_json['f35']
    data[36] = sample_json['f36']
    data[37] = sample_json['f37']
    data[38] = sample_json['f38']
    data[39] = sample_json['f39']
    data[40] = sample_json['f40']
    data[41] = sample_json['f41']
    data[42] = sample_json['f42']
    data[43] = sample_json['f43']
    data[44] = sample_json['f44']
    data[45] = sample_json['f45']
    data[46] = sample_json['f46']
    data[47] = sample_json['f47']
    data[48] = sample_json['f48']
    data[49] = sample_json['f49']
    data[50] = sample_json['f50']
    data[51] = sample_json['f51']
    data[52] = sample_json['f52']
    data[53] = sample_json['f53']
    data[54] = sample_json['f54']
    data[55] = sample_json['f55']
    data[56] = sample_json['f56']
    data[57] = sample_json['f57']
    data[58] = sample_json['f58']
    data[59] = sample_json['f59']
    data[60] = sample_json['f60']
    data[61] = sample_json['f61']
    data[62] = sample_json['f62']
    data[63] = sample_json['f63']
    data[64] = sample_json['f64']
    data[65] = sample_json['f65']
    data[66] = sample_json['f66']
    data[67] = sample_json['f67']
    data[68] = sample_json['f68']
    data[69] = sample_json['f69']
    data[70] = sample_json['f70']
    data[71] = sample_json['f71']
    data[72] = sample_json['f72']
    data[73] = sample_json['f73']
    data[74] = sample_json['f74']
    data[75] = sample_json['f75']
    data[76] = sample_json['f76']
    data[77] = sample_json['f77']
    data[78] = sample_json['f78']
    data[79] = sample_json['f79']
    data[80] = sample_json['f80']

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
    f16 = StringField(columns[16], default=0, validators=[DataRequired()])
    f17 = StringField(columns[17], default=0, validators=[DataRequired()])
    f18 = StringField(columns[18], default=0, validators=[DataRequired()])
    f19 = StringField(columns[19], default=0, validators=[DataRequired()])
    f20 = StringField(columns[20], default=0, validators=[DataRequired()])
    f21 = StringField(columns[21], default=0, validators=[DataRequired()])
    f22 = StringField(columns[22], default=0, validators=[DataRequired()])
    f23 = StringField(columns[23], default=0, validators=[DataRequired()])
    f24 = StringField(columns[24], default=0, validators=[DataRequired()])
    f25 = StringField(columns[25], default=0, validators=[DataRequired()])
    f26 = StringField(columns[26], default=0, validators=[DataRequired()])
    f27 = StringField(columns[27], default=0, validators=[DataRequired()])
    f28 = StringField(columns[28], default=0, validators=[DataRequired()])
    f29 = StringField(columns[29], default=0, validators=[DataRequired()])
    f30 = StringField(columns[30], default=0, validators=[DataRequired()])
    f31 = StringField(columns[31], default=0, validators=[DataRequired()])
    f32 = StringField(columns[32], default=0, validators=[DataRequired()])
    f33 = StringField(columns[33], default=0, validators=[DataRequired()])
    f34 = StringField(columns[34], default=0, validators=[DataRequired()])
    f35 = StringField(columns[35], default=0, validators=[DataRequired()])
    f36 = StringField(columns[36], default=0, validators=[DataRequired()])
    f37 = StringField(columns[37], default=0, validators=[DataRequired()])
    f38 = StringField(columns[38], default=0, validators=[DataRequired()])
    f39 = StringField(columns[39], default=0, validators=[DataRequired()])
    f40 = StringField(columns[40], default=0, validators=[DataRequired()])
    f41 = StringField(columns[41], default=0, validators=[DataRequired()])
    f42 = StringField(columns[42], default=0, validators=[DataRequired()])
    f43 = StringField(columns[43], default=0, validators=[DataRequired()])
    f44 = StringField(columns[44], default=0, validators=[DataRequired()])
    f45 = StringField(columns[45], default=0, validators=[DataRequired()])
    f46 = StringField(columns[46], default=0, validators=[DataRequired()])
    f47 = StringField(columns[47], default=0, validators=[DataRequired()])
    f48 = StringField(columns[48], default=0, validators=[DataRequired()])
    f49 = StringField(columns[49], default=0, validators=[DataRequired()])
    f50 = StringField(columns[50], default=0, validators=[DataRequired()])
    f51 = StringField(columns[51], default=0, validators=[DataRequired()])
    f52 = StringField(columns[52], default=0, validators=[DataRequired()])
    f53 = StringField(columns[53], default=0, validators=[DataRequired()])
    f54 = StringField(columns[54], default=0, validators=[DataRequired()])
    f55 = StringField(columns[55], default=0, validators=[DataRequired()])
    f56 = StringField(columns[56], default=0, validators=[DataRequired()])
    f57 = StringField(columns[57], default=0, validators=[DataRequired()])
    f58 = StringField(columns[58], default=0, validators=[DataRequired()])
    f59 = StringField(columns[59], default=0, validators=[DataRequired()])
    f60 = StringField(columns[60], default=0, validators=[DataRequired()])
    f61 = StringField(columns[61], default=0, validators=[DataRequired()])
    f62 = StringField(columns[62], default=0, validators=[DataRequired()])
    f63 = StringField(columns[63], default=0, validators=[DataRequired()])
    f64 = StringField(columns[64], default=0, validators=[DataRequired()])
    f65 = StringField(columns[65], default=0, validators=[DataRequired()])
    f66 = StringField(columns[66], default=0, validators=[DataRequired()])
    f67 = StringField(columns[67], default=0, validators=[DataRequired()])
    f68 = StringField(columns[68], default=0, validators=[DataRequired()])
    f69 = StringField(columns[69], default=0, validators=[DataRequired()])
    f70 = StringField(columns[70], default=0, validators=[DataRequired()])
    f71 = StringField(columns[71], default=0, validators=[DataRequired()])
    f72 = StringField(columns[72], default=0, validators=[DataRequired()])
    f73 = StringField(columns[73], default=0, validators=[DataRequired()])
    f74 = StringField(columns[74], default=0, validators=[DataRequired()])
    f75 = StringField(columns[75], default=0, validators=[DataRequired()])
    f76 = StringField(columns[76], default=0, validators=[DataRequired()])
    f77 = StringField(columns[77], default=0, validators=[DataRequired()])
    f78 = StringField(columns[78], default=10, validators=[DataRequired()])
    f79 = StringField(columns[79], default=100, validators=[DataRequired()])
    f80 = StringField(columns[80], default=100, validators=[DataRequired()])
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
        session['f16'] = form.f16.data
        session['f17'] = form.f17.data
        session['f18'] = form.f18.data
        session['f19'] = form.f19.data
        session['f20'] = form.f20.data
        session['f21'] = form.f21.data
        session['f22'] = form.f22.data
        session['f23'] = form.f23.data
        session['f24'] = form.f24.data
        session['f25'] = form.f25.data
        session['f26'] = form.f26.data
        session['f27'] = form.f27.data
        session['f28'] = form.f28.data
        session['f29'] = form.f29.data
        session['f30'] = form.f30.data
        session['f31'] = form.f31.data
        session['f32'] = form.f32.data
        session['f33'] = form.f33.data
        session['f34'] = form.f34.data
        session['f35'] = form.f35.data
        session['f36'] = form.f36.data
        session['f37'] = form.f37.data
        session['f38'] = form.f38.data
        session['f39'] = form.f39.data
        session['f40'] = form.f40.data
        session['f41'] = form.f41.data
        session['f42'] = form.f42.data
        session['f43'] = form.f43.data
        session['f44'] = form.f44.data
        session['f45'] = form.f45.data
        session['f46'] = form.f46.data
        session['f47'] = form.f47.data
        session['f48'] = form.f48.data
        session['f49'] = form.f49.data
        session['f50'] = form.f50.data
        session['f51'] = form.f51.data
        session['f52'] = form.f52.data
        session['f53'] = form.f53.data
        session['f54'] = form.f54.data
        session['f55'] = form.f55.data
        session['f56'] = form.f56.data
        session['f57'] = form.f57.data
        session['f58'] = form.f58.data
        session['f59'] = form.f59.data
        session['f60'] = form.f60.data
        session['f61'] = form.f61.data
        session['f62'] = form.f62.data
        session['f63'] = form.f63.data
        session['f64'] = form.f64.data
        session['f65'] = form.f65.data
        session['f66'] = form.f66.data
        session['f67'] = form.f67.data
        session['f68'] = form.f68.data
        session['f69'] = form.f69.data
        session['f70'] = form.f70.data
        session['f71'] = form.f71.data
        session['f72'] = form.f72.data
        session['f73'] = form.f73.data
        session['f74'] = form.f74.data
        session['f75'] = form.f75.data
        session['f76'] = form.f76.data
        session['f77'] = form.f77.data
        session['f78'] = form.f78.data
        session['f79'] = form.f79.data
        session['f80'] = form.f80.data

        return redirect(url_for("prediction"))
    return render_template('home.html', form=form)


@app.route('/prediction')
def prediction():
    # Defining content dictionary
    content = {}

    try:
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
        content['f16'] = int(session['f16'])
        content['f17'] = int(session['f17'])
        content['f18'] = int(session['f18'])
        content['f19'] = int(session['f19'])
        content['f20'] = int(session['f20'])
        content['f21'] = int(session['f21'])
        content['f22'] = int(session['f22'])
        content['f23'] = int(session['f23'])
        content['f24'] = int(session['f24'])
        content['f25'] = int(session['f25'])
        content['f26'] = int(session['f26'])
        content['f27'] = int(session['f27'])
        content['f28'] = int(session['f28'])
        content['f29'] = int(session['f29'])
        content['f30'] = int(session['f30'])
        content['f31'] = int(session['f31'])
        content['f32'] = int(session['f32'])
        content['f33'] = int(session['f33'])
        content['f34'] = int(session['f34'])
        content['f35'] = int(session['f35'])
        content['f36'] = int(session['f36'])
        content['f37'] = int(session['f37'])
        content['f38'] = int(session['f38'])
        content['f39'] = int(session['f39'])
        content['f40'] = int(session['f40'])
        content['f41'] = int(session['f41'])
        content['f42'] = int(session['f42'])
        content['f43'] = int(session['f43'])
        content['f44'] = int(session['f44'])
        content['f45'] = int(session['f45'])
        content['f46'] = int(session['f46'])
        content['f47'] = int(session['f47'])
        content['f48'] = int(session['f48'])
        content['f49'] = int(session['f49'])
        content['f50'] = int(session['f50'])
        content['f51'] = int(session['f51'])
        content['f52'] = int(session['f52'])
        content['f53'] = int(session['f53'])
        content['f54'] = int(session['f54'])
        content['f55'] = int(session['f55'])
        content['f56'] = int(session['f56'])
        content['f57'] = int(session['f57'])
        content['f58'] = int(session['f58'])
        content['f59'] = int(session['f59'])
        content['f60'] = int(session['f60'])
        content['f61'] = int(session['f61'])
        content['f62'] = int(session['f62'])
        content['f63'] = int(session['f63'])
        content['f64'] = int(session['f64'])
        content['f65'] = int(session['f65'])
        content['f66'] = int(session['f66'])
        content['f67'] = int(session['f67'])
        content['f68'] = int(session['f68'])
        content['f69'] = int(session['f69'])
        content['f70'] = int(session['f70'])
        content['f71'] = int(session['f71'])
        content['f72'] = int(session['f72'])
        content['f73'] = int(session['f73'])
        content['f74'] = int(session['f74'])
        content['f75'] = int(session['f75'])
        content['f76'] = int(session['f76'])
        content['f77'] = int(session['f77'])
        content['f78'] = int(session['f78'])
        content['f79'] = int(session['f79'])
        content['f80'] = int(session['f80'])
    
        results = return_prediction(model=model, scaler=scaler, sample_json=content)
        
    except:
        return "Input data error. Please check your inputs!"

    return render_template('prediction.html', results=results)
