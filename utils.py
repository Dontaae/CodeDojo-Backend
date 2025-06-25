# utils.py

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
