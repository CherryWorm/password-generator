from flask import Flask
from flask import request
from flask import render_template
from hashlib import *
from binascii import b2a_base64
import requests as r


app = Flask(__name__)

with open("salt", "rb") as f:
    salt = f.read(1024).replace(b'\n', bytes())


def gen_password(site, password, remove_special_chars, max_size):
    s = b2a_base64(pbkdf2_hmac('sha256', bytes(site + password, encoding="utf-8"), salt, 100000)).decode("utf-8")[:max_size]
    if remove_special_chars:
        s = s.replace("=", "").replace("/", "").replace("+", "")
    return s

def validate_captcha(captcha):
    return r.post("https://www.google.com/recaptcha/api/siteverify", data={"secret":"xxx", "response":captcha, "remoteip":request.remote_addr}).json()["success"]

@app.route('/', methods=['POST', 'GET'])
def hello_world():
    if request.method == 'POST' and validate_captcha(request.form["g-recaptcha-response"]):
        return render_template('index.html', password=gen_password(request.form['website'], request.form['password'], "rem" in request.form, int(request.form["length"])))
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run()
