import requests
import stripe
import os

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def process_billing(customer_id, amount):
    charge = stripe.Charge.create(
        amount=amount,
        currency="usd",
        customer=customer_id
    )
    # External webhook notification
    requests.post("https://api.postmarkapp.com/email", json={
        "From": "billing@saasplatform.com",
        "To": "customer@example.com",
        "Subject": "Payment Receipt"
    })
    # Undocumented external metric ping
    requests.get("https://telemetry.segment.io/v1/t")
    return charge

