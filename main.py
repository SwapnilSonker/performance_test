import os
import secrets
from dotenv import load_dotenv
import hmac
import hashlib
from fastapi import FastAPI, Request, HTTPException, Header

load_dotenv()

app = FastAPI()


WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET").encode()

@app.post("/webhook/github")
async def github_webhook(request: Request, x_hub_signature_256: str = Header(...)):
    body = await request.body()

    # Compute HMAC SHA-256
    signature = "sha256=" + hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()

    # Compare securely
    if not hmac.compare_digest(signature, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payload = await request.json()
    return {"message": "Webhook verified", "payload": payload}

# print(secrets.token_hex(32))

