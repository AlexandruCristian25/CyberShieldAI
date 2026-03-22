from fastapi import FastAPI, Query, Form, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from secure_utils import Session, LoginAudit, logger
from jinja2 import Template
from datetime import datetime
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
import os, csv, io

# Load environment variables
load_dotenv()

# FastAPI setup
app = FastAPI()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# Load admin token
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN")
if not ADMIN_API_TOKEN:
    raise RuntimeError("❌ ADMIN_API_TOKEN not set in .env!")

# Secure Headers Middleware
class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://unpkg.com;"
        return response

app.add_middleware(SecureHeadersMiddleware)

# Templates
AUDIT_TEMPLATE = Template("""
<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>📋 Istoric Login</title>
  <script src="https://unpkg.com/htmx.org@1.9.2"></script>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50 p-6">
  <div class="max-w-4xl mx-auto">
    <h1 class="text-2xl font-bold mb-4">📋 Istoric autentificări</h1>
    <form method="get" class="mb-4 flex gap-4">
      <input name="token" type="hidden" value="{{ token }}">
      <input name="filter" value="{{ filter }}" placeholder="Filtru IP sau token" class="p-2 border w-1/2">
      <button class="px-4 py-2 bg-blue-500 text-white rounded">Filtrează</button>
      <button formaction="/audit-ui/delete" formmethod="post" name="token" value="{{ token }}" class="ml-auto px-4 py-2 bg-red-500 text-white rounded">🗑️ Șterge tot</button>
      <a href="/audit-ui/export?token={{ token }}" class="ml-2 px-4 py-2 bg-green-500 text-white rounded">⬇️ Export CSV</a>
    </form>

    <table class="w-full text-left border">
      <thead>
        <tr class="bg-gray-100">
          <th class="p-2 border">Token</th>
          <th class="p-2 border">IP</th>
          <th class="p-2 border">Timp</th>
          <th class="p-2 border">Succes</th>
        </tr>
      </thead>
      <tbody>
        {% for row in rows %}
        <tr class="hover:bg-gray-200">
          <td class="p-2 border text-sm">{{ row.token }}</td>
          <td class="p-2 border">{{ row.ip_address }}</td>
          <td class="p-2 border">{{ row.timestamp | datetime }}</td>
          <td class="p-2 border">{{ '✔️' if row.success else '❌' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <p class="mt-2 text-sm text-gray-500">Afișare maxim 50 rezultate sortate descrescător</p>
  </div>
</body>
</html>
""")  # Păstrăm template-ul exact cum era, vezi explicația mai jos

# Helper: Validate Admin Token
def validate_admin_token(token: str = Query(...)):
    if token != ADMIN_API_TOKEN:
        logger.warning("⛔ Tentativă acces interzis - token invalid: %s", token)
        raise HTTPException(status_code=401, detail="⛔ Access Denied")
    return token

@app.get("/audit-ui", response_class=HTMLResponse)
@limiter.limit("5/minute")
def audit_ui(request: Request, token: str = Depends(validate_admin_token), filter: str = Query("")):
    session = Session()
    query = session.query(LoginAudit).order_by(LoginAudit.timestamp.desc())
    if filter:
        query = query.filter(
            LoginAudit.token.contains(filter) | LoginAudit.ip_address.contains(filter)
        )
    logs = query.limit(50).all()
    session.close()
    return AUDIT_TEMPLATE.render(
        rows=logs,
        datetime=lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
        token=token,
        filter=filter
    )

@app.post("/audit-ui/delete")
@limiter.limit("2/minute")
def audit_ui_delete(token: str = Form(...)):
    if token != ADMIN_API_TOKEN:
        logger.warning("⛔ Tentativă ștergere audit cu token invalid: %s", token)
        raise HTTPException(status_code=401, detail="⛔ Access Denied")
    session = Session()
    session.query(LoginAudit).delete()
    session.commit()
    session.close()
    logger.warning("🗑️ Toate înregistrările audit au fost șterse prin UI.")
    return RedirectResponse(url=f"/audit-ui?token={token}", status_code=303)

@app.get("/audit-ui/export")
@limiter.limit("2/minute")
def export_audit_csv(token: str = Depends(validate_admin_token)):
    session = Session()
    data = session.query(LoginAudit).order_by(LoginAudit.timestamp.desc()).all()
    session.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Token", "IP", "Timestamp", "Success"])
    for row in data:
        writer.writerow([
            row.token,
            row.ip_address,
            datetime.fromtimestamp(row.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "Yes" if row.success else "No"
        ])
    output.seek(0)

    logger.info("📤 Export audit generat in-memory.")

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_export.csv"}
    )
