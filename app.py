from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from sqlalchemy import PickleType
import subprocess, tempfile, re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

def get_rank_from_xp(xp: int) -> str:
    if xp >= 200: return "Black Belt"
    if xp >= 130: return "Brown Belt"
    if xp >= 70:  return "Purple Belt"
    if xp >= 30:  return "Blue Belt"
    return "White Belt"

class User(db.Model):
    id   = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    xp       = db.Column(db.Integer, default=0, nullable=False)
    completed_challenges = db.Column(PickleType, default=list, nullable=False)

class Challenge(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(150), nullable=False)
    description     = db.Column(db.Text, nullable=False)
    sample_input    = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    difficulty      = db.Column(db.String(50), nullable=False)
    xp_reward       = db.Column(db.Integer, nullable=False)

with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message='Username already exists!'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Email already exists!'), 400
    pwd = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    u = User(username=data['username'], email=data['email'], password=pwd)
    db.session.add(u)
    db.session.commit()
    return jsonify(message='User registered successfully!'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    u = User.query.filter_by(username=data['username']).first()
    if u and bcrypt.check_password_hash(u.password, data['password']):
        token = create_access_token(identity=str(u.id))
        return jsonify(access_token=token), 200
    return jsonify(message='Invalid credentials!'), 401

@app.route('/api/challenges', methods=['GET'])
@jwt_required()
def list_challenges():
    user = User.query.get_or_404(int(get_jwt_identity()))
    out = []
    for c in Challenge.query.all():
        out.append({
            "id": c.id,
            "title": c.title,
            "difficulty": c.difficulty,
            "xp_reward": c.xp_reward,
            "completed": c.id in user.completed_challenges
        })
    return jsonify(out), 200

@app.route('/api/challenges/<int:challenge_id>', methods=['GET'])
@jwt_required()
def get_challenge(challenge_id):
    user = User.query.get_or_404(int(get_jwt_identity()))
    c = Challenge.query.get_or_404(challenge_id)
    return jsonify({
        "id": c.id,
        "title": c.title,
        "description": c.description,
        "sample_input": c.sample_input,
        "expected_output": c.expected_output,
        "difficulty": c.difficulty,
        "xp_reward": c.xp_reward,
        "completed": c.id in user.completed_challenges
    }), 200

@app.route('/api/run-challenge', methods=['POST'])
@jwt_required()
def run_challenge():
    data = request.get_json()
    c = Challenge.query.get_or_404(data['challenge_id'])
    # … your temp-file + subprocess logic …
    # return {'stdout':…, 'stderr':…}

@app.route('/api/submit-challenge', methods=['POST'])
@jwt_required()
def submit_challenge():
    data = request.get_json()
    c   = Challenge.query.get_or_404(data['challenge_id'])
    u   = User.query.get_or_404(int(get_jwt_identity()))
    out = data.get('user_output', '')
    exp = c.expected_output or ""

    # cheat-detector + normalize…
    def normalize(s): return "".join(s.lower().split())
    if normalize(out) != normalize(exp):
        return jsonify(message="Incorrect solution."), 400

    if c.id not in u.completed_challenges:
        u.xp += c.xp_reward
        u.completed_challenges.append(c.id)
        db.session.commit()
        return jsonify(
           message="Correct! XP awarded.",
           xp=u.xp,
           rank=get_rank_from_xp(u.xp)
        ), 200

    return jsonify(
       message="Already completed – no additional XP.",
       xp=u.xp,
       rank=get_rank_from_xp(u.xp)
    ), 200

if __name__ == '__main__':
    app.run(debug=True)
