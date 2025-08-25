import React, { useEffect, useState } from 'react';
import '../styles/Login.css';
import appLogo from '../assets/app-icon.jpg';
import { useNavigate } from 'react-router-dom';
import emailjs from '@emailjs/browser';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [forgotPassword, setForgotPassword] = useState(false);
  const [otpSent, setOtpSent] = useState(false);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [successMessage,setSuccessMessage]=useState('');
  const navigate = useNavigate();

  // Initialize EmailJS
  useEffect(()=>{
      emailjs.init('SV0XPhI3tDyRALbSk');
    },[]);

  // Login function
  const validLogin = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!email || !password) {
      setErrorMessage('Email and password are required');
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/valid-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (data.error) setErrorMessage(data.error);
      else if (data.message === 'Login successful') navigate('/home');
      else setErrorMessage(data.message || 'Unknown error');
    } catch (err) {
      console.error(err);
      setErrorMessage('An error occurred. Please try again later.');
    }
  };

  // Send OTP via EmailJS
  const sendOtp = async () => {
    setErrorMessage('');
    if (!email) {
      setErrorMessage('Please enter your email');
      return;
    }

    // Generate 6-digit OTP
    const generatedOtp = Math.floor(100000 + Math.random() * 900000);

    try {
      // Send email
      await emailjs.send('service_npgj14s', 'template_5671qrw', {
        email,
        subject: 'SoulfulYatra Password Reset OTP',
        message: `Your OTP is ${generatedOtp}. It expires in 10 minutes.`
      });

      // Store OTP in backend
      const res = await fetch('http://localhost:5000/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp: generatedOtp })
      });

      const data = await res.json();
      if (data.error) setErrorMessage(data.error);
      else setOtpSent(true);
    } catch (err) {
      console.error('EmailJS error:', err);
      setErrorMessage('Failed to send OTP. Please try again later.');
    }
  };

  // Reset password
  const resetPassword = async () => {
    setErrorMessage('');

    if (!otp || !newPassword || !confirmPassword) {
      setErrorMessage('All fields are required');
      return;
    }

    if (newPassword !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }

    try {
      const res = await fetch('http://localhost:5000/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp, newPassword })
      });

      const data = await res.json();

      if (data.error) setErrorMessage(data.error);
      else {
        setSuccessMessage('Password reset successful! Please log in.');
        setForgotPassword(false);
        setOtpSent(false);
        setEmail('');
        setPassword('');
        setOtp('');
        setNewPassword('');
        setConfirmPassword('');
      }
    } catch (err) {
      console.error(err);
      setErrorMessage('Error resetting password. Try again.');
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <img src={appLogo} alt="SoulfulYatra Logo" className="login-logo" />
        <h1 className="login-title">Welcome Back</h1>
        <p className="login-subtitle">Log in to continue your adventures with SoulfulYatra</p>

        {errorMessage && <p className="error-message">{errorMessage}</p>}
        {successMessage && <p className='success-message'>{successMessage}</p>}
        {/* Normal login form */}
        {!forgotPassword && (
          <form className="login-form" onSubmit={validLogin}>
            <label>Email</label>
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
            <label>Password</label>
            <input
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
            <button type="submit" className="login-btn">Log In</button>
          </form>
        )}

        {/* Forgot password: send OTP */}
        {forgotPassword && !otpSent && (
          <div className="login-form">
            <label>Email</label>
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
            <button onClick={sendOtp} className="login-btn">Send OTP</button>
          </div>
        )}

        {/* Reset password form */}
        {forgotPassword && otpSent && (
          <div className="login-form">
            <label>OTP</label>
            <input
              type="text"
              placeholder="Enter OTP"
              value={otp}
              onChange={e => setOtp(e.target.value)}
            />
            <label>New Password</label>
            <input
              type="password"
              placeholder="New password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
            />
            <label>Confirm Password</label>
            <input
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
            />
            <button onClick={resetPassword} className="login-btn">Reset Password</button>
          </div>
        )}

        {/* Footer links */}
        {!forgotPassword && (
          <p className="login-footer">
            <a href="#!" onClick={() => setForgotPassword(true)}>Forgot Password?</a><br/>
            Don’t have an account? <a href="/signup">Sign up</a>
          </p>
        )}
      </div>
    </div>
  );
}
