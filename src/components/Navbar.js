import React, { useState, useEffect } from 'react';
import '../styles/Navbar.css';
import appLogo from '../assets/app-icon.jpg';
import {Link, useNavigate } from 'react-router-dom';

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const navigate = useNavigate();

  const toggleMenu = () => setMenuOpen(prev => !prev);

  // Check login status on mount
  useEffect(() => {
    fetch('http://localhost:5000/check-auth', {
      method: 'GET',
      credentials: 'include', // send cookies
    })
      .then(res => res.json())
      .then(data => setLoggedIn(data.loggedIn))
      .catch(err => console.error(err));
  }, []);

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:5000/logout', {
        method: 'POST',
        credentials: 'include',
      });
      setLoggedIn(false);
      
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  return (
    <nav className='nav'>
      <div className='logo-container'>
        <img src={appLogo} alt="App Logo" className="app-logo" />
        <span>SoulfulYatra</span>
      </div>

      <div className="menu-toggle" onClick={toggleMenu}>
        &#9776;
      </div>

      <ul className={menuOpen ? 'show' : ''}>
        <li><Link to='/home'>Home</Link></li>
        <li><Link to='/explore-places'>Explore Places</Link></li>
        <li><Link to='/plan-trip'>Plan a Trip</Link></li>
        <li><Link to='/hotel-rooms'>Hotel Rooms</Link></li>
        <li><Link to='/restaurants'>Restaurants</Link></li>
        <li><Link to='/profile'>Profile</Link></li>
        
        <li>
          {loggedIn 
            ? <a href='/login' onClick={handleLogout} className="logout-btn">Logout</a>
            : <Link to='/login'>Login</Link>
          }
        </li>
      </ul>

    </nav>
  );
}
