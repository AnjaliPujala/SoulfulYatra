import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

export default function VerifyOTP() {
  const location = useLocation();
  const navigate = useNavigate();

  // Get passed data from navigate state
  const { otp, name, email, phone, password } = location.state || {};
  const [enteredOtp, setEnteredOtp] = useState('');
  const [error, setError] = useState('');

  const handleVerify = async (e) => {
    e.preventDefault(); // Prevent form reload
    console.log("Entered OTP:", enteredOtp);
    console.log("Expected OTP:", otp);
   if (parseInt(enteredOtp) !== parseInt(otp)) {
      setError('OTP is incorrect');
      return;
    }

    try {
      // Send registration request to backend
      
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, phone}),
      });

      const data = await response.json();

      if (response.ok) {


        // Optionally call onSuccess callback (e.g. redirect user)
        navigate('/login', { state: { message: 'Registration successful! Please log in.' } });
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Server error');
    }
  };

  return (
    <div>
      <h2>Verify OTP</h2>
      <input
        type="text"
        placeholder="Enter OTP"
        value={enteredOtp}
        onChange={(e) => setEnteredOtp(e.target.value)}
      />
      <button onClick={handleVerify}>Verify & Register</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
}
