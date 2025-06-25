from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Challenge
from utils import get_rank_from_xp

bp = Blueprint('api', __name__)

@bp.route('/challenges', methods=['GET'])
@jwt_required()
def list_challenges():
    """Return all challenges (id, title, difficulty, xp_reward)."""
    data = [
        {
            "id": c.id,
            "title": c.title,
            "difficulty": c.difficulty,
            "xp_reward": c.xp_reward
        }
        for c in Challenge.query.all()
    ]
    return jsonify(data), 200

@bp.route('/challenges/<int:challenge_id>', methods=['GET'])
@jwt_required()
def get_challenge(challenge_id):
    """Return full details for one challenge."""
    c = Challenge.query.get_or_404(challenge_id)
    return jsonify({
        "id": c.id,
        "title": c.title,
        "description": c.description,
        "sample_input": c.sample_input,
        "expected_output": c.expected_output,
        "difficulty": c.difficulty,
        "xp_reward": c.xp_reward
    }), 200

@bp.route('/submit-challenge', methods=['POST'])
@jwt_required()
def submit_challenge():
    """
    Expect JSON:
      { "challenge_id": int, "user_output": str }
    Compare user_output to expected_output; award XP if first-time correct.
    """
    data = request.get_json()
    cid = data.get("challenge_id")
    user_output = data.get("user_output", "").strip()

    challenge = Challenge.query.get_or_404(cid)
    # simple exact-match; you can extend this later
    if user_output != challenge.expected_output.strip():
        return jsonify({"message": "Incorrect solution."}), 400

    user = User.query.get(get_jwt_identity())
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

    # Already done
    return jsonify({
        "message": "Already completed – no additional XP.",
        "xp": user.xp,
        "rank": get_rank_from_xp(user.xp)
    }), 200
