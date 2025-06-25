# seed.py
from app import app, db, Challenge

with app.app_context():
    # Remove any old challenges
    Challenge.query.delete()
    db.session.commit()

    # Create three sample challenges
    challenges = [
        Challenge(
            title="Hello World",
            description="Print “Hello, World!” to the console.",
            sample_input="",
            expected_output="Hello, World!",
            difficulty="easy",
            xp_reward=10
        ),
        Challenge(
            title="Sum Two Numbers",
            description="Read two integers and print their sum.",
            sample_input="3 5",
            expected_output="8",
            difficulty="easy",
            xp_reward=15
        ),
        Challenge(
            title="Reverse String",
            description="Given a string, output it reversed.",
            sample_input="dojo",
            expected_output="ojod",
            difficulty="medium",
            xp_reward=30
        )
    ]

    for c in challenges:
        db.session.add(c)
    db.session.commit()
    print("✅ Seeded challenges.")
