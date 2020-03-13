from flask import Flask

app = Flask(__name__)

@app.route('/hello')
def hello_world():
    print('request log')
    import time
    time.sleep(10)
    return 'Hello World'
