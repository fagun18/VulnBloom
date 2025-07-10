from flask import Flask, request
from datetime import datetime

app = Flask(__name__)

@app.route('/callback', methods=['GET', 'POST'])
def callback():
    log_entry = f"[{datetime.now()}] IP: {request.remote_addr} | Path: {request.path} | Args: {dict(request.args)} | Data: {request.data.decode(errors='ignore')}\n"
    print(log_entry)
    with open('blind_xss_callbacks.log', 'a', encoding='utf-8') as f:
        f.write(log_entry)
    return 'Callback received', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 