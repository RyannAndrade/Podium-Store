from app import app
from flask import Flask, jsonify

@app.route('/.netlify/functions/api', methods=['GET'])
def netlify_handler():
    return jsonify({"message": "API is working!"})

if __name__ == '__main__':
    app.run() 