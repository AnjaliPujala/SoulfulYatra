import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import '../styles/PlanTrip.css';
import Navbar from './Navbar'; 
import WalkingPerson from './WalkingPerson'; 
import Footer from './Footer';

export default function PlanTrip() {
  const [destination, setDestination] = useState('');
  const [days, setDays] = useState(1);
  const [interests, setInterests] = useState('');
  const [itinerary, setItinerary] = useState([]); // structured data
  const [activeDay, setActiveDay] = useState(0);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [message,setMessage]=useState('');
  const navigate = useNavigate();

  // ------------------ useEffect for auth check ------------------
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await fetch('http://localhost:5000/check-auth', {
          method: 'GET',
          credentials: 'include', // important to send cookies
        });
        const data = await res.json();
        if (!data.loggedIn) {
          setError('You must be logged in to plan a trip.');
          navigate('/login');
        }
      } catch (err) {
        console.error(err);
        setError('Error checking login status.');
        navigate('/login');
      }
    };

    checkAuth();
  }, [navigate]);


  // ------------------ Function to parse plain text itinerary ------------------
  function parseItinerary(text) {
  
    const cleanedText = text.replace(/(Morning|Afternoon|Evening|Lunch|Dinner):\s*\1:/gi, '$1:');

  
    const daysArray = cleanedText.split(/Day \d+: /).filter(Boolean);

    return daysArray.map((dayText, index) => {
  
      const lines = dayText.split('\n').filter(line => line.trim() !== '');
      const dayTitleLine = lines.shift(); 
      const day = `Day ${index + 1}: ${dayTitleLine.trim()}`;

      const activities = lines.map(line => {
        
        const cleanLine = line.replace(/^- /, '').trim();

       
        const [timePart, ...activityParts] = cleanLine.split(':');
        if (activityParts.length > 0) {
          return {
            time: timePart.trim(),
            activity: activityParts.join('').trim(),
          };
        } else {
          return { time: '', activity: cleanLine }; 
        }
      });

      return { day, activities };
    });
  }


  // ------------------ Form submit handler ------------------
  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);
      const response = await fetch('http://localhost:5000/generate-itinerary', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ destination, days, interests }),
        credentials:'include',
      });

      if (response.status === 401) {
        setError('Token expired. Please login again.');
        return;
      }

      const data = await response.json();

      
      const structuredItinerary = parseItinerary(data.itinerary);
      setItinerary(structuredItinerary);
      setActiveDay(0); 
      setError('');
    } catch (err) {
      setError('Failed to generate itinerary. Try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
const handleSaveTrip=async ()=>{
  try {
      const response = await fetch('http://localhost:5000/save-trip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // send cookies
        body: JSON.stringify({ 
          destination,
          interests,
          tripData: itinerary,
          days:Number(days) })
      });

      const data = await response.json();
      if (response.ok) {
        setMessage('Trip saved successfully');
        setError(''); 
        setTimeout(()=>setMessage(''),5000);
      } else {
        setError('Trip already saved');
        setMessage(''); 
        setTimeout(()=>setError(''),5000);
      }

    } catch (err) {
      console.error(err);
      setError('Error in saving trip.');
    }
  }

  // ------------------ JSX ------------------
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

        
        {itinerary.length > 0 && (
          <div className="itinerary-container">
            <h2 className='itinerary-header'> Here is the detailed Plan we made for YOU</h2>
            <div className="timeline">
              
              <div className="timeline-days">
                {itinerary.map((day, index) => (
                  <div
                    key={index}
                    className={`timeline-day ${activeDay === index ? "active" : ""}`}
                    onClick={() => setActiveDay(index)}
                  >
                    {index + 1}
                  </div>
                ))}
              </div>

              <div className="timeline-plan">
                <h3>{itinerary[activeDay].day}</h3>
                <ul>
                  {itinerary[activeDay].activities.map((act, idx) => (
                    <li key={idx}>
                      <strong>{act.time}:</strong> {act.activity}
                    </li>
                  ))}
                </ul>
              </div>

            </div>
          </div>
        )}
        {itinerary.length > 0 && (
          <div className="save-trip-container">
            {message && <p className="success-message">{message}</p>}
            {error && <p className="plan-trip-error">{error}</p>}
            <button
              className="save-trip-button"
              onClick={handleSaveTrip}>
              Save Trip
            </button>
          </div>

        )}

      </div>
      <Footer/>
    </div>
  );
}
