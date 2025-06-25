from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import PickleType

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    xp = db.Column(db.Integer, default=0, nullable=False)
    completed_challenges = db.Column(PickleType, default=list, nullable=False)

    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    sample_input = db.Column(db.Text, nullable=False)
    expected_output = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)  # e.g., 'easy', 'medium', 'hard'
    xp_reward = db.Column(db.Integer, nullable=False)
