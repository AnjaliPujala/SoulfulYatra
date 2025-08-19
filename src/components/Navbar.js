import React,{useState} from 'react'
import '../styles/Navbar.css';
import appLogo from '../assets/app-icon.jpg';
export default function Navbar() {
    const [menuOpen, setMenuOpen] = useState(false);
    const toggleMenu = () => {
    setMenuOpen(prev => !prev);
  };
  return (
    
    <div>
      <nav className='nav'>
        <div className='logo-container'>
          <img src={appLogo} alt="App Logo" className="app-logo" />
          <span>SoulfulYatra</span>
        </div>

        <div className="menu-toggle" onClick={toggleMenu}>
          &#9776;
        </div>

        <ul className={menuOpen ? 'show' : ''}>
          <li><a href='/explore-places'>Explore Places</a></li>
          <li><a href='/plan-trip'>Plan a Trip</a></li>
          <li><a href='/hotel-rooms'>Hotel Rooms</a></li>
          <li><a href='/famous-foods'>Famous Foods</a></li>
          <li><a href='/contact-us'>Contact us</a></li>
          <li><a href='/about-us'>About us</a></li>
          <li>
            {localStorage.getItem('email') 
              ? <a href='/logout'>Logout</a> 
              : <a href='/login'>Login</a>
            }
          </li>
        </ul>
      </nav>
    </div>
  )
}
