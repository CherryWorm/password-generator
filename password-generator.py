from flask import Flask
from flask import request
from flask import render_template
from flask import abort
from hashlib import *
from base64 import b64encode
import requests as r


app = Flask(__name__)
app.config.from_envvar("PASSWORD_GENERATOR_SETTINGS")

with open(app.config["SALT"], "rb") as f:
    salt = f.read(1024).replace(b'\n', bytes())


def gen_password(site, password, remove_special_chars, max_size):
    s = b64encode(pbkdf2_hmac('sha256', bytes(site + password, encoding="utf-8"), salt, 100000)).decode("utf-8")[:max_size]
    if remove_special_chars:
        s = s.replace("=", "").replace("/", "").replace("+", "")
    return s


def validate_captcha(captcha):
    return r.post("https://www.google.com/recaptcha/api/siteverify", data={"secret":app.config["GOOGLE_SECRET"], "response":captcha, "remoteip":request.remote_addr}).json()["success"]


@app.route('/', methods=['POST', 'GET'])
def hello_world():
    if request.method == 'POST':
        captcha = request.form["g-recaptcha-response"]
        website = request.form['website']
        password = request.form['password']
        rem = "rem" in request.form
        length = request.form["length"]

        if not validate_captcha(captcha):
            abort(403)
            return

        if len(website) < 1 or len(password) < 1:
            abort(400)
            return

        return render_template('index.html', key=app.config["GOOGLE_KEY"], password=gen_password(website, password, rem, int(length)))
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run()
