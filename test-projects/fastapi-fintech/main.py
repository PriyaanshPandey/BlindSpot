from fastapi import FastAPI
import httpx
import os
import razorpay

app = FastAPI(title="Fintech Payment Core")

client = razorpay.Client(auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")))

@app.post("/verify-kyc")
async def verify_kyc(user_id: str):
    async with httpx.AsyncClient() as http_client:
        resp = await http_client.post("https://api.veriff.com/v1/sessions", json={"user_id": user_id})
    return resp.json()

@app.post("/fraud-check")
async def fraud_check(ip_address: str):
    async with httpx.AsyncClient() as http_client:
        resp = await http_client.get(f"https://api.sift.com/v205/score/{ip_address}")
    return resp.json()

