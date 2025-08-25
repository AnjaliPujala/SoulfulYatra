import React from "react";
import "../styles/Footer.css";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-container">
        <h3>Soulful Yatra</h3>
        <ul className="quick-links">
          <li><a href="/home">Home</a></li>
          <li><a href="/explore">Explore Places</a></li>
          <li><a href="/plan-trip">Plan Trip</a></li>
          <li><a href="/about">About Us</a></li>
          <li><a href="/contact">Contact</a></li>
        </ul>
        <p className="copyright">© 2025 Soulful Yatra. All rights reserved.</p>
      </div>
    </footer>
  );
}
