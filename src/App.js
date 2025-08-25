import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Login from './auth/Login';
import Signup from './auth/Signup';
import VerifyOTP from './auth/VerifyOTP';
import ExplorePlaces from './components/ExplorePlaces';
import PlanTrip from './components/PlanTrip';
import HotelRooms from './components/HotelRooms';
import FamousFoods from './components/FamousFoods';
import ContactUs from './components/ContactUs';
import AboutUs from './components/AboutUs';
import Logout from './components/Logout';
import HomePage from './components/HomePage'; 
import Profile from './components/Profile.js'
const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/verify-otp" element={<VerifyOTP />} />
        <Route path='/home' element={<HomePage/>} />
        <Route path="/logout" element={<Logout />} />
        <Route path="/explore-places" element={<ExplorePlaces />} />
        <Route path="/plan-trip" element={<PlanTrip />} />
        <Route path="/hotel-rooms" element={<HotelRooms />} />
        <Route path="/restaurants" element={<FamousFoods />} />
        <Route path="/contact-us" element={<ContactUs />} />
        <Route path="/about-us" element={<AboutUs />} />
        <Route path="/profile" element={<Profile/>}/>
      </Routes>
    </Router>
  );
};

export default App;
