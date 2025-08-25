import React, { useState, useEffect } from 'react';
import Navbar from './Navbar';
import '../styles/HomePage.css';
import Footer from './Footer';

export default function HomePage() {
  
  const [statesData, setStatesData] = useState([]); // grouped by state
  const [placeIndexes, setPlaceIndexes] = useState({}); // track current place per state
  const [error, setError] = useState('');

  

  useEffect(() => {
    const fetchPlaces = async () => {
      try {
        const response = await fetch('http://localhost:5000/get-places');
        if (!response.ok) {
          throw new Error('Failed to fetch places');
        }
        const data = await response.json();

        // Group places by state
        const grouped = data.places.reduce((acc, place) => {
          if (!acc[place.state]) {
            acc[place.state] = [];
          }
          acc[place.state].push(place);
          return acc;
        }, {});

        // Convert object to array
        const groupedArray = Object.keys(grouped).map(state => ({
          state,
          places: grouped[state],
        }));

        // Initialize each state's place index to 0
        const indexes = {};
        groupedArray.forEach(s => {
          indexes[s.state] = 0;
        });

        setStatesData(groupedArray);
        setPlaceIndexes(indexes);
      } catch (err) {
        console.error('Error fetching places:', err);
        setError('Failed to load places. Please try again later.');
      }
    };
    fetchPlaces();
  }, []);

  const handleNextPlace = (state) => {
    setPlaceIndexes(prev => ({
      ...prev,
      [state]: (prev[state] + 1) % statesData.find(s => s.state === state).places.length
    }));
  };

  const handlePrevPlace = (state) => {
    setPlaceIndexes(prev => ({
      ...prev,
      [state]: (prev[state] - 1 + statesData.find(s => s.state === state).places.length) %
               statesData.find(s => s.state === state).places.length
    }));
  };

  return (
    <div className='home-container'>
      <Navbar/>
      <div className='home-content'>
        <h1>Welcome to SoulfulYatra</h1>
        <p>Your journey to explore the world's most soulful places begins here.</p>

        {error && <p className='error-message'>{error}</p>}

        {statesData.length > 0 ? (
          <div className="states-grid">
            {statesData.map((stateObj) => {
              const place = stateObj.places[placeIndexes[stateObj.state]];
              return (
                <div key={stateObj.state} className="state-card">
                  <h2>{stateObj.state}</h2>
                  <div className='place-card'>
                    <img src={place.image_url} alt={place.name} className='place-image' />
                    <h3 className='place-name'>{place.place_name}</h3>
                    <p className='place-description' style={{color:'#222'}}>{place.description}</p>
                    <div className="nav-buttons">
                      <button onClick={() => handlePrevPlace(stateObj.state)}>Prev Place</button>
                      <button onClick={() => handleNextPlace(stateObj.state)}>Next Place</button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p>Loading places...</p>
        )}
      </div>
      <Footer/>
    </div>
  );
}
