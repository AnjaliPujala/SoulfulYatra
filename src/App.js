import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import WelcomePage from './components/WelcomePage';
import Login from './auth/Login';
import Signup from './auth/Signup';
import VerifyOTP from './auth/VerifyOTP';
import HomePage from './components/HomePage'; 
const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/verify-otp" element={<VerifyOTP />} />
        <Route path='/home' element={<HomePage/>} />
      </Routes>
    </Router>
  );
};

export default App;
