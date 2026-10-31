import React from 'react';
import axios from 'axios';

export function Checkout() {
  const handlePay = () => {
    // Calling PayPal checkout
    axios.post('https://api.paypal.com/v2/checkout/orders');
  };
  return <button onClick={handlePay}>Pay Now with PayPal</button>;
}

