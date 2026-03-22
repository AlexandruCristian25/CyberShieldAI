from flask import request, g
from auth_utils import decode_jwt  # asigură-te că ai funcția decode_jwt(token)

def attach_user_from_token():
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        try:
            data = decode_jwt(token.replace("Bearer ", ""))
            g.user_id = data.get("id")
            g.user_role = data.get("role", "guest")
        except Exception as e:
            g.user_role = "guest"
            g.user_id = None
    else:
        g.user_role = "guest"
        g.user_id = None
