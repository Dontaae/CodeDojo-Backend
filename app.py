from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from flask_cors import CORS
from sqlalchemy import PickleType
import subprocess
import tempfile
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY']                 = 'supersecretkey'  # Change in prod

db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt    = JWTManager(app)
CORS(app)

def get_rank_from_xp(xp: int) -> str:
    if xp >= 200: return "Black Belt"
    if xp >= 130: return "Brown Belt"
    if xp >= 70:  return "Purple Belt"
    if xp >= 30:  return "Blue Belt"
    return "White Belt"

class User(db.Model):
    id                   = db.Column(db.Integer, primary_key=True)
    username             = db.Column(db.String(80), unique=True, nullable=False)
    email                = db.Column(db.String(120), unique=True, nullable=False)
    password             = db.Column(db.String(120), nullable=False)
    xp                   = db.Column(db.Integer, default=0, nullable=False)
    completed_challenges = db.Column(PickleType, default=list, nullable=False)

class Challenge(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(150), nullable=False)
    description     = db.Column(db.Text, nullable=False)
    sample_input    = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    difficulty      = db.Column(db.String(50), nullable=False)  # easy/medium/hard
    xp_reward       = db.Column(db.Integer, nullable=False)

# ────────────────────────────────────────────────────────────────────
# TEMP DEV RESET + SEED:
# on each startup drop & recreate tables, then seed if empty.
with app.app_context():
    db.drop_all()
    db.create_all()

    if Challenge.query.count() == 0:
        seeds = [
            {
                "title": "Hello World",
                "description": "Print \"Hello World\"",
                "sample_input": "",
                "expected_output": "Hello World",
                "difficulty": "easy",
                "xp_reward": 10
            },
            {
                "title": "Two Sum",
                "description": "Read two ints from input, output their sum",
                "sample_input": "3 5",
                "expected_output": "8",
                "difficulty": "easy",
                "xp_reward": 15
            },
            # ... add more here as needed ...
        ]
        for s in seeds:
            db.session.add(Challenge(
                title           = s["title"],
                description     = s["description"],
                sample_input    = s["sample_input"],
                expected_output = s["expected_output"],
                difficulty      = s["difficulty"],
                xp_reward       = s["xp_reward"]
            ))
        db.session.commit()
# ────────────────────────────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message='Username already exists!'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Email already exists!'), 400

    pwd = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    u   = User(username=data['username'], email=data['email'], password=pwd)
    db.session.add(u)
    db.session.commit()
    return jsonify(message='User registered successfully!'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    u    = User.query.filter_by(username=data['username']).first()
    if u and bcrypt.check_password_hash(u.password, data['password']):
        token = create_access_token(identity=str(u.id))
        return jsonify(access_token=token), 200
    return jsonify(message='Invalid credentials!'), 401

@app.route('/api/challenges', methods=['GET'])
@jwt_required()
def list_challenges():
    user = User.query.get_or_404(int(get_jwt_identity()))
    out  = []
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
    c    = Challenge.query.get_or_404(challenge_id)
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
    cid  = data.get('challenge_id')
    code = data.get('code', '')
    c    = Challenge.query.get_or_404(cid)
    inp  = c.sample_input or ''

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        fname = f.name

    try:
        proc = subprocess.run(
            ['python', fname],
            input=inp.encode(),
            capture_output=True,
            timeout=5
        )
        return jsonify({
            'stdout': proc.stdout.decode(),
            'stderr': proc.stderr.decode()
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({'stderr': 'Error: execution timed out'}), 400

@app.route('/api/submit-challenge', methods=['POST'])
@jwt_required()
def submit_challenge():
    data        = request.get_json()
    cid         = data.get("challenge_id")
    code        = data.get("code", "")
    user_output = data.get("user_output", "")

    c   = Challenge.query.get_or_404(cid)
    exp = c.expected_output or ""

    # cheat-detect literal prints
    lit = re.escape(exp.strip())
    if re.search(rf'print\(\s*{lit}\s*\)', code):
        return jsonify({"message": "Incorrect solution."}), 400

    # normalize for comparison
    def normalize(txt: str) -> str:
        return "".join(txt.lower().split())

    if normalize(user_output) != normalize(exp):
        return jsonify({"message": "Incorrect solution."}), 400

    u = User.query.get_or_404(int(get_jwt_identity()))
    if cid not in u.completed_challenges:
        u.xp += c.xp_reward
        u.completed_challenges.append(cid)
        db.session.commit()
        return jsonify({
            "message": "Correct! XP awarded.",
            "xp": u.xp,
            "rank": get_rank_from_xp(u.xp)
        }), 200

    return jsonify({
        "message": "Already completed – no additional XP.",
        "xp": u.xp,
        "rank": get_rank_from_xp(u.xp)
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
