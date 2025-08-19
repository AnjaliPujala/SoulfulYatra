import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/PlanTrip.css'; // import CSS file
import Navbar from './Navbar'; 
import WalkingPerson from './WalkingPerson'; 

export default function PlanTrip() {
  const [destination, setDestination] = useState('');
  const [days, setDays] = useState(1);
  const [interests, setInterests] = useState('');
  const [itinerary, setItinerary] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      setError('You must be logged in to plan a trip.');
      navigate('/login');
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('token');
    if (!token) {
      setError('No authorization token found. Please login.');
      return;
    }

    try {
      setLoading(true);
      const response = await fetch('http://localhost:5000/generate-itinerary', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ destination, days, interests }),
      });

      if (response.status === 401) {
        setError('Unauthorized. Please login again.');
        return;
      }

      const data = await response.json();
      setItinerary(data.itinerary);
      setError('');
    } catch (err) {
      setError('Failed to generate itinerary. Try again.');
      console.error(err);
    }finally {
      setLoading(false);
    }
  };

  return (
    <div className="plan-trip-container">
      <Navbar />
      <div className='plan-trip'>
        <h2>Plan Your Soulful Yatra Trip</h2>
        {error && <p className="plan-trip-error">{error}</p>}

        <form className="plan-trip-form" onSubmit={handleSubmit}>
          <label>
            Destination:
            <input
              type="text"
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              required
              placeholder="Enter city or place"
            />
          </label>

          <label>
            Number of Days:
            <input
              type="number"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              min="1"
              required
            />
          </label>

          <label>
            Interests (optional, comma-separated):
            <input
              type="text"
              value={interests}
              onChange={(e) => setInterests(e.target.value)}
              placeholder="e.g., spiritual, nature, adventure"
            />
          </label>

          <button type="submit">Generate Itinerary</button>
        </form>
        {loading && (
          <div className="plan-trip-loading-container">
            <p className="plan-trip-loading">Generating itinerary...</p>
            <WalkingPerson /> 
          </div>
        )}

        {itinerary && (
          <div className="itinerary-container">
            <h3>Your Trip Itinerary:</h3>
            <pre className="itinerary-pre">{itinerary}</pre>
          </div>
        )}
      </div>
      
    </div>
  );
}
