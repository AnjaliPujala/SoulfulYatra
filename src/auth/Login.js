import React, { useEffect, useState } from 'react';
import '../styles/Login.css';
import appLogo from '../assets/app-icon.jpg'; // Adjust the path as necessary
import { useNavigate } from 'react-router-dom';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const navigate = useNavigate();
  useEffect(() => {
    
    const token = localStorage.getItem('token');
    if (token) {
      navigate('/home'); 
    }
  }, [navigate]);
  const validLogin = (e) => {
    e.preventDefault();
    setErrorMessage(''); // Reset errors

    if (!email || !password) {
      setErrorMessage('Email and password are required');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErrorMessage('Please enter a valid email address');
      return;
    }

    fetch('http://localhost:5000/valid-login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          setErrorMessage(data.error);
        } else if (data.message) {
          if (data.message === 'Login successful') {
            // Save token and user details to localStorage
            localStorage.setItem('token', data.token);
            localStorage.setItem('email', data.user.email);
            localStorage.setItem('name', data.user.name);
            localStorage.setItem('phone', data.user.phone);
            navigate('/home');
          } else {
            // Handle other messages, e.g. user not found
            setErrorMessage(data.message);
            if (data.message === 'User not found') {
              navigate('/signup', { state: { message: 'You are not registered. Please sign up.' } });
            }
          }
        }
      })
      .catch((error) => {
        console.error('Error:', error);
        setErrorMessage('An error occurred. Please try again later.');
      });
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <img
          src={appLogo}
          alt="SoulfulYatra Logo"
          className="login-logo"
        />
        <h1 className="login-title">Welcome Back</h1>
        <p className="login-subtitle">
          Log in to continue your adventures with SoulfulYatra
        </p>

        {errorMessage && <p className="error-message">{errorMessage}</p>}

        <form className="login-form" onSubmit={validLogin}>
          <label>Email</label>
          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <label>Password</label>
          <input
            type="password"
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          <button type="submit" className="login-btn">
            Log In
          </button>
        </form>

        <p className="login-footer">
          Don’t have an account? <a href="/signup">Sign up</a>
        </p>
      </div>
    </div>
  );
}
