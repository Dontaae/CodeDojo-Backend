import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError

# ─── App & extensions setup ───────────────────────────────────────────────────
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')
).replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'supersecretkey')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# ─── Helper: rank from XP ──────────────────────────────────────────────────────
def get_rank_from_xp(xp: int) -> str:
    ranks = [
        (0, "White Belt"),
        (20, "Yellow Belt"),
        (40, "Orange Belt"),
        (70, "Green Belt"),
        (100, "Blue Belt"),
        (140, "Purple Belt"),
        (190, "Brown Belt"),
        (250, "Black Belt")
    ]
    for threshold, rank in reversed(ranks):
        if xp >= threshold:
            return rank
    return "White Belt"

# ─── Models ────────────────────────────────────────────────────────────────────
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    xp       = db.Column(db.Integer, default=0, nullable=False)

class Challenge(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(150), nullable=False)
    description     = db.Column(db.Text, nullable=False)
    sample_input    = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    difficulty      = db.Column(db.String(50), nullable=False)
    xp_reward       = db.Column(db.Integer, nullable=False)

class PracticeLog(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id  = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    xp_awarded    = db.Column(db.Integer, nullable=False)
    attempted_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user      = db.relationship('User', backref='practice_logs')
    challenge = db.relationship('Challenge', backref='practice_logs')

# ─── Seed sample challenges ───────────────────────────────────────────────────
seed_data = [
    # Easy
    {"title":"Hello World","description":"Print 'Hello, World!' to the console.","sample_input":"","expected_output":"Hello, World!","difficulty":"easy","xp_reward":10},
    {"title":"Sum Two Numbers","description":"Read two integers and print their sum.","sample_input":"3 5","expected_output":"8","difficulty":"easy","xp_reward":15},
    {"title":"Even or Odd","description":"Determine if a number is even or odd.","sample_input":"7","expected_output":"odd","difficulty":"easy","xp_reward":15},
    {"title":"Factorial","description":"Calculate the factorial of a number.","sample_input":"5","expected_output":"120","difficulty":"easy","xp_reward":20},
    {"title":"FizzBuzz","description":"Implement FizzBuzz for numbers up to N.","sample_input":"15","expected_output":"1 2 Fizz 4 Buzz Fizz 7 8 Fizz Buzz 11 Fizz 13 14 FizzBuzz","difficulty":"easy","xp_reward":25},
    # Medium
    {"title":"Reverse String","description":"Given a string, output it reversed.","sample_input":"dojo","expected_output":"ojod","difficulty":"medium","xp_reward":30},
    {"title":"Palindrome Check","description":"Determine if a string is a palindrome.","sample_input":"racecar","expected_output":"true","difficulty":"medium","xp_reward":35},
    {"title":"Prime Check","description":"Check if a number is prime.","sample_input":"17","expected_output":"true","difficulty":"medium","xp_reward":40},
    {"title":"Fibonacci Sequence","description":"Generate the first N Fibonacci numbers.","sample_input":"8","expected_output":"0 1 1 2 3 5 8 13","difficulty":"medium","xp_reward":45},
    {"title":"Anagram Check","description":"Check if two strings are anagrams.","sample_input":"listen silent","expected_output":"true","difficulty":"medium","xp_reward":50},
    # Hard
    {"title":"Binary Search","description":"Implement binary search on a sorted array.","sample_input":"1 3 5 7 9 11\n7","expected_output":"3","difficulty":"hard","xp_reward":60},
    {"title":"Merge Sort","description":"Implement merge sort algorithm.","sample_input":"5 3 8 4 2 7 1 10","expected_output":"1 2 3 4 5 7 8 10","difficulty":"hard","xp_reward":70},
    {"title":"Dijkstra's Algorithm","description":"Find the shortest path in a graph.","sample_input":"5\n0 1 4\n0 2 1\n1 3 1\n2 1 2\n2 3 5\n3 4 3","expected_output":"0 2 1 3 4","difficulty":"hard","xp_reward":80},
    {"title":"N-Queens","description":"Solve the N-Queens problem for N=4.","sample_input":"4","expected_output":".Q..\n...Q\nQ...\n..Q.","difficulty":"hard","xp_reward":90},
    {"title":"Knapsack Problem","description":"Solve the 0/1 knapsack problem.","sample_input":"50\n3\n60 10\n100 20\n120 30","expected_output":"220","difficulty":"hard","xp_reward":100}
]

with app.app_context():
    db.create_all()
    if Challenge.query.count() == 0:
        for d in seed_data:
            db.session.add(Challenge(**d))
        db.session.commit()
        print("✅ Seeded sample challenges.")

# ─── Auth routes ──────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message='Username already exists!'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Email already exists!'), 400

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'], password=hashed)
    db.session.add(user); db.session.commit()
    return jsonify(message='User registered!'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    u = User.query.filter_by(username=data['username']).first()
    if u and bcrypt.check_password_hash(u.password, data['password']):
        token = create_access_token(identity=str(u.id))
        return jsonify(access_token=token), 200
    return jsonify(message='Invalid creds!'), 401

# ─── User profile with practice summary ───────────────────────────────────────
@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user_profile():
    uid = int(get_jwt_identity()); user = User.query.get_or_404(uid)
    rows = (
        db.session.query(
            Challenge.id, Challenge.title,
            db.func.count(PracticeLog.id).label('runs')
        )
        .join(PracticeLog, PracticeLog.challenge_id==Challenge.id)
        .filter(PracticeLog.user_id==uid)
        .group_by(Challenge.id)
        .all()
    )
    return jsonify({
        "username": user.username,
        "email": user.email,
        "xp": user.xp,
        "rank": get_rank_from_xp(user.xp),
        "practice_summary": [
            {"challenge_id": cid, "title": title, "runs": runs}
            for cid, title, runs in rows
        ]
    }), 200

# ─── List challenges with run_count ────────────────────────────────────────────
@app.route('/api/challenges', methods=['GET'])
@jwt_required()
def list_challenges():
    uid = int(get_jwt_identity())
    run_map = {
        r.challenge_id: r.count for r in
        db.session.query(
            PracticeLog.challenge_id,
            db.func.count(PracticeLog.id).label('count')
        )
        .filter(PracticeLog.user_id==uid)
        .group_by(PracticeLog.challenge_id)
        .all()
    }
    out = []
    for c in Challenge.query.order_by(Challenge.id):
        out.append({
            "id": c.id,
            "title": c.title,
            "difficulty": c.difficulty,
            "xp_reward": c.xp_reward,
            "run_count": run_map.get(c.id, 0)
        })
    return jsonify(out), 200

@app.route('/api/challenges/<int:challenge_id>', methods=['GET'])
@jwt_required()
def get_challenge(challenge_id):
    uid = int(get_jwt_identity()); c = Challenge.query.get_or_404(challenge_id)
    run_count = (
        db.session.query(db.func.count(PracticeLog.id))
        .filter_by(user_id=uid, challenge_id=challenge_id)
        .scalar()
    )
    return jsonify({
        "id": c.id, "title": c.title,
        "description": c.description,
        "sample_input": c.sample_input,
        "expected_output": c.expected_output,
        "difficulty": c.difficulty,
        "xp_reward": c.xp_reward,
        "run_count": run_count
    }), 200

# ─── Run code ─────────────────────────────────────────────────────────────────
@app.route('/api/run-challenge', methods=['POST'])
@jwt_required()
def run_challenge():
    data = request.get_json(); cid = data['challenge_id']; code = data['code']
    c = Challenge.query.get_or_404(cid); inp = c.sample_input or ''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code); fname = f.name
    try:
        proc = subprocess.run(
            ['python', fname],
            input=inp.encode(),
            capture_output=True,
            timeout=5
        )
        return jsonify(stdout=proc.stdout.decode(), stderr=proc.stderr.decode()), 200
    except subprocess.TimeoutExpired:
        return jsonify(stdout='', stderr='Error: execution timed out'), 400
    except Exception as e:
        return jsonify(stdout='', stderr=f'Error running code: {e}'), 500
    finally:
        try: os.unlink(fname)
        except: pass

# ─── Submit & log with cooldown + decaying XP ─────────────────────────────────
@app.route('/api/submit-challenge', methods=['POST'])
@jwt_required()
def submit_challenge():
    data         = request.get_json()
    cid          = data['challenge_id']
    user_output  = data['user_output']
    code         = data['code']

    c = Challenge.query.get_or_404(cid)
    u = User.query.get_or_404(int(get_jwt_identity()))

    # cheat detector
    lit = re.escape(c.expected_output.strip())
    if re.search(rf'print\(\s*{lit}\s*\)', code):
        return jsonify(message="Incorrect solution."), 400

    def normalize(s): return "".join(s.lower().split())
    if normalize(user_output) != normalize(c.expected_output):
        return jsonify(message="Incorrect solution."), 400

    # fetch previous logs descending by time
    logs = (PracticeLog.query
            .filter_by(user_id=u.id, challenge_id=cid)
            .order_by(PracticeLog.attempted_at.desc())
            .all())
    prev = len(logs)

    # 1st: 100%, 2nd: 50% after 24h, 3rd: 25% after 24h, 4th+: 0%
    now = datetime.utcnow()
    if prev == 0:
        factor = 1.0
    elif prev == 1:
        first_time = logs[-1].attempted_at
        factor = 0.5 if now - first_time >= timedelta(hours=24) else 0.0
    elif prev == 2:
        second_time = logs[-2].attempted_at
        factor = 0.25 if now - second_time >= timedelta(hours=24) else 0.0
    else:
        factor = 0.0

    awarded = int(c.xp_reward * factor)

    # record this practice
    pl = PracticeLog(user_id=u.id, challenge_id=cid, xp_awarded=awarded)
    u.xp += awarded
    db.session.add(pl)
    db.session.commit()

    new_count = PracticeLog.query.filter_by(
        user_id=u.id, challenge_id=cid
    ).count()

    return jsonify({
        "message":      f"Correct! You earned {awarded} XP.",
        "xp_awarded":   awarded,
        "total_xp":     u.xp,
        "rank":         get_rank_from_xp(u.xp),
        "new_run_count": new_count
    }), 200

# ─── Leaderboard ───────────────────────────────────────────────────────────────
@app.route('/api/leaderboard', methods=['GET'])
@jwt_required()
def leaderboard():
    top = User.query.order_by(User.xp.desc()).limit(10).all()
    return jsonify([
        {"username": u.username, "xp": u.xp}
        for u in top
    ]), 200

# ─── Run server ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug)
