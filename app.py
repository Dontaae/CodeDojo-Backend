from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS

app = Flask(__name__)

# Allow CORS
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change this in production

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ✅ Define the User model BEFORE using it in routes
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# ✅ Ensure database tables exist
with app.app_context():
    db.create_all()

# ✅ Fixing the register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify(message='Username already exists!'), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Email already exists!'), 400

    # Hash password and create new user
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message='User registered successfully!'), 201

@app.route('/')
def home():
    return "Backend is running!"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
