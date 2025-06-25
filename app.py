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

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change in production

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

def get_rank_from_xp(xp: int) -> str:
    """Return the belt rank for a given XP total."""
    if xp >= 200:
        return "Black Belt"
    if xp >= 130:
        return "Brown Belt"
    if xp >= 70:
        return "Purple Belt"
    if xp >= 30:
        return "Blue Belt"
    return "White Belt"

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    xp = db.Column(db.Integer, default=0, nullable=False)
    completed_challenges = db.Column(PickleType, default=list, nullable=False)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    sample_input = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)  # easy, medium, hard
    xp_reward = db.Column(db.Integer, nullable=False)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Auth routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message='Username already exists!'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Email already exists!'), 400
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message='User registered successfully!'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200
    return jsonify(message='Invalid credentials!'), 401

# Challenge list & detail
@app.route('/api/challenges', methods=['GET'])
@jwt_required()
def list_challenges():
    user = User.query.get_or_404(int(get_jwt_identity()))
    data = [
        {
            "id": c.id,
            "title": c.title,
            "difficulty": c.difficulty,
            "xp_reward": c.xp_reward,
            "completed": c.id in user.completed_challenges
        }
        for c in Challenge.query.all()
    ]
    return jsonify(data), 200

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

# Submit solution & award XP (with normalization)
@app.route('/api/submit-challenge', methods=['POST'])
@jwt_required()
def submit_challenge():
    data = request.get_json()
    cid = data.get("challenge_id")
    user_output = data.get("user_output", "")

    challenge = Challenge.query.get_or_404(cid)
    expected = challenge.expected_output or ""

    # normalize: lowercase + remove all whitespace
    def normalize(text: str) -> str:
        return "".join(text.lower().split())

    if normalize(user_output) != normalize(expected):
        return jsonify({"message": "Incorrect solution."}), 400

    user_id = int(get_jwt_identity())
    user = User.query.get_or_404(user_id)

    if cid not in user.completed_challenges:
        user.xp += challenge.xp_reward
        user.completed_challenges.append(cid)
        new_rank = get_rank_from_xp(user.xp)
        db.session.commit()
        return jsonify({
            "message": "Correct! XP awarded.",
            "xp": user.xp,
            "rank": new_rank
        }), 200

    return jsonify({
        "message": "Already completed – no additional XP.",
        "xp": user.xp,
        "rank": get_rank_from_xp(user.xp)
    }), 200

# Run user code against sample input
@app.route('/api/run-challenge', methods=['POST'])
@jwt_required()
def run_challenge():
    data = request.get_json()
    cid = data.get('challenge_id')
    code = data.get('code', '')
    challenge = Challenge.query.get_or_404(cid)
    sample_input = challenge.sample_input or ''

    # Write code to a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        fname = f.name

    try:
        proc = subprocess.run(
            ['python', fname],
            input=sample_input.encode(),
            capture_output=True,
            timeout=5
        )
        return jsonify({
            'stdout': proc.stdout.decode(),
            'stderr': proc.stderr.decode()
        }), 200
    except subprocess.TimeoutExpired:
        return jsonify({'stderr': 'Error: execution timed out'}), 400

if __name__ == '__main__':
    app.run(debug=True)