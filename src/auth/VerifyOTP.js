import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import '../styles/VerifyOTP.css';

export default function VerifyOTP() {
  const location = useLocation();
  const navigate = useNavigate();

  const { otp, name, email, phone, password } = location.state || {};
  const [enteredOtp, setEnteredOtp] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('OTP sent to your email');

  const handleVerify = async (e) => {
    e.preventDefault();
    if (parseInt(enteredOtp) !== parseInt(otp)) {
      setError('OTP is incorrect');
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, phone }),
      });

      const data = await response.json();

      if (response.ok) {
        navigate('/login', { state: { message: 'Registration successful! Please log in.' } });
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Server error');
    }
  };

  const handleResendOTP = () => {
    setInfo('A new OTP has been sent to your email.');
    setError('');
    console.log('Resend OTP clicked for:', email);
  };

  return (
    <div className="verify-otp-container">
      <h2>Verify OTP</h2>
      <p className="info-message">{info}</p>

      <input
        type="text"
        placeholder="Enter OTP"
        value={enteredOtp}
        onChange={(e) => setEnteredOtp(e.target.value)}
      />

      <button onClick={handleVerify}>Verify & Register</button>

      <p className="resend-otp">
        OTP not received?{' '}
        <span onClick={handleResendOTP}>Resend OTP</span>
      </p>

      {error && <p className="error-message">{error}</p>}
    </div>
  );
}
