import React from 'react';
import walkingAnimation from '../assets/walking-animation.mp4'
import '../styles/WelcomePage.css';
const WalkingPerson = () => {
  return (
    <div className="walking-animation">
      <video
        src= {walkingAnimation} // Update with your actual mp4 path
        autoPlay
        loop
        muted
        playsInline
        style={{ width: '50px', maxWidth: '80vw', borderRadius: '12px', margin: '10px', display: 'block' }}
      />
    </div>
  );
};

export default WalkingPerson;
