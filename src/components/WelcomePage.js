import React from 'react';
import { Link } from 'react-router-dom';
import WalkingPerson from './WalkingPerson';
import '../styles/WelcomePage.css';
import appIcon from '../assets/app-icon.jpg';

const WelcomePage = () => {
  return (
    <div className="welcome-container">
      {/* Header */}
      <header className="top-bar">
        <div className="app-icon-container">
          <img src={appIcon} alt="SoulfulYatra Logo" className="app-icon" />
          <WalkingPerson />
        </div>
        <nav className="auth-buttons">
          <Link to="/login" className="btn login-btn-home" aria-label="Login">
            Login
          </Link>
          <Link to="/signup" className="btn signup-btn-home" aria-label="Signup">
            Signup
          </Link>
        </nav>
      </header>

      {/* Main Content */}
      <main className="welcome-main">
        <h1 className="animated-text">Welcome to <span className="highlight">SoulfulYatra</span></h1>
        <p className="intro-text">Your perfect companion for exploring all tourist places across India.</p>
        <p className="tagline">Discover. Plan. Travel. Experience.</p>

        {/* CTA Button */}
        <Link to="/signup" className="explore-btn">
          Start Your Journey
        </Link>
      </main>

      {/* Footer */}
      <footer className="footer">
        © {new Date().getFullYear()} SoulfulYatra. All rights reserved.
      </footer>
    </div>
  );
};

export default WelcomePage;
