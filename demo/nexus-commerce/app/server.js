/**
 * Nexus Commerce - Mock Backend Service [Demo Target Application]
 * 
 * Demonstrates declared architecture components:
 * - Express web framework
 * - Stripe payment processing
 * - Auth0 authentication
 * - Seeded dependency: event-stream@3.3.6 (supply-chain demonstration)
 * 
 * NOTE: For safety, this mock does not start live network listeners or execute external requests.
 * The compromised package event-stream is retained exclusively as a static scanner fixture in
 * package.json / package-lock.json and is never loaded, imported, or executed in application code.
 */

const express = require('express');

const app = express();
app.use(express.json());

// Declared internal endpoints
app.post('/api/v1/checkout', (req, res) => {
    // Declared external dependency: Stripe API (https://api.stripe.com/v1/charges)
    res.json({
        status: 'success',
        journey: 'Customer Checkout',
        gateway: 'Stripe'
    });
});

app.get('/api/v1/auth/callback', (req, res) => {
    // Declared external dependency: Auth0 Identity (https://nexus-auth.us.auth0.com)
    res.json({
        status: 'authenticated',
        provider: 'Auth0'
    });
});

module.exports = app;
