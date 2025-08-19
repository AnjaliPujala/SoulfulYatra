import React, { useEffect, useState } from 'react';
import '../styles/Signup.css';
import appLogo from '../assets/app-icon.jpg';
import emailjs from '@emailjs/browser';
import { useNavigate } from 'react-router-dom';
export default function Signup() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const navigate = useNavigate();
  useEffect(()=>{
      emailjs.init('SV0XPhI3tDyRALbSk');
    },[]);
  const validateForm = (e) => {
    e.preventDefault(); // Prevent form reload
    setErrorMessage(''); // Reset errors

    if (!name || !email || !phone || !password || !confirmPassword) {
      setErrorMessage('All fields are required');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setErrorMessage('Please enter a valid email address');
      return;
    }
    if (!/^\d{10}$/.test(phone)) {
      setErrorMessage('Please enter a valid 10-digit phone number');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }

    if (password.length < 6) {
      setErrorMessage('Password must be at least 6 characters long');
      return;
    }
    const otp= Math.floor(100000 + Math.random() * 900000);
    fetch(`http://localhost:5000/get-user?email=${email}&phone=${phone}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          setErrorMessage(data.error);
        } else if (data.message) {
          setErrorMessage(data.message);
          if(data.message === "User already exists") {
            
          }else{
            sendEmail(email,name,"Your OTP for SoulfulYatra Signup",`Dear ${name},\nYour OTP is ${otp}\nPlease use this OTP to complete your registration.\nThank you for choosing SoulfulYatra!`);
            navigate('/verify-otp', {
              state: { otp, name, email, phone, password }
            });
          }
        }
      })
      .catch((error) => {
        console.error('Error fetching user:', error);
        setErrorMessage('Server error. Please try again later.');
      });
    
  };
  const sendEmail = (email, name, subject, message) => {
    
    emailjs.send('service_npgj14s', 'template_5671qrw', {
      email: email,
      message: message,
      subject: subject,
  }).then((response) => {
      console.log('Email sent successfully:', response.status, response.text);
     
  }).catch((error) => {
      console.error('Error sending email:', error);
      setErrorMessage('Failed to send OTP. Please try again later.');
    });
  }
  return (
    <div className="signup-container">
      <div className="signup-card">
        {/* Logo and Title */}
        <img src={appLogo} alt="SoulfulYatra Logo" className="signup-logo" />
        <h1 className="signup-title">Create Your Account</h1>
        <p className="signup-subtitle">
          Plan, explore, and enjoy your journey across India with SoulfulYatra
        </p>

        {/* Form */}
        <form className="signup-form" onSubmit={validateForm}>
          {errorMessage && <p className="error-message">{errorMessage}</p>}

          <input
            type="text"
            placeholder="Enter your name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />

          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <input
            type="tel"
            placeholder="Enter your phone number"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
          />

          <input
            type="password"
            placeholder="Create a password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          <input
            type="password"
            placeholder="Confirm your password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />

          <button type="submit" className="signup-btn">
            Sign Up
          </button>
        </form>

        {/* Footer */}
        <p className="signup-footer">
          Already have an account? <a href="/login">Log in</a>
        </p>
      </div>
    </div>
  );
}
