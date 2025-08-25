import React, { useEffect, useState } from 'react';
import Navbar from './Navbar.js';
import '../styles/HotelRooms.css';
import WalkingPerson from './WalkingPerson.js';
import Footer from './Footer.js';

export default function HotelRooms() {
  const [hotels, setHotels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [city, setCity] = useState(''); // new state for city

  // Utility to format address
  const formatAddress = (address) => {
    if (!address) return 'Address not available';
    const { house_number, road, suburb, city, state, country } = address;
    return [house_number, road, suburb, city, state, country].filter(Boolean).join(', ');
  };

  // Reverse geocoding to get city name
  const getCityFromCoords = async (lat, lon) => {
    try {
      const res = await fetch(
        `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json`
      );
      const data = await res.json();
      return data.address.city || data.address.town || data.address.village || data.address.county || '';
    } catch (err) {
      console.error('Reverse geocoding error:', err);
      return '';
    }
  };

  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const { latitude, longitude } = position.coords;

          // Get city name for Justdial redirect
          const cityName = await getCityFromCoords(latitude, longitude);
          setCity(cityName);

          try {
            const response = await fetch(
              `http://localhost:5000/get-hotels?lat=${latitude}&lon=${longitude}&radius=10000`,
              {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
              }
            );
            if (response.status === 401) {
              setError('Token expired. Please login again.');
              return;
            }

            const data = await response.json();
            const nearbyHotels = data.hotels || [];

            const detailedHotels = [];
            for (let i = 0; i < nearbyHotels.length; i++) {
              const hotel = nearbyHotels[i];
              try {
                const res = await fetch(`http://localhost:5000/get-place-image?xid=${hotel.properties.xid}`);
                const json = await res.json();
                const placeData = json.data || {};
                detailedHotels.push({
                  name: placeData.name || hotel.properties.name,
                  address: formatAddress(placeData.address),
                  rating: placeData.rate || hotel.properties.rate || 'N/A',
                  image: placeData.preview?.source || null,
                  description: placeData.wikipedia_extracts?.text || 'No description available',
                  xid: placeData.xid,
                });
              } catch (err) {
                console.error('Error fetching hotel details for', hotel.properties.name, err);
                detailedHotels.push({
                  name: hotel.properties.name,
                  address: 'Address not available',
                  rating: hotel.properties.rate || 'N/A',
                  image: null,
                  description: 'No description available',
                  xid: hotel.properties.xid,
                });
              }
              await new Promise((resolve) => setTimeout(resolve, 300));
            }
            setHotels(detailedHotels);
          } catch (err) {
            setError('Failed to fetch nearby hotels.');
          } finally {
            setLoading(false);
          }
        },
        (err) => {
          setError('Failed to get your location.');
          setLoading(false);
        }
      );
    } else {
      setError('Geolocation is not supported by this browser.');
      setLoading(false);
    }
  }, []);

  // Handle Justdial redirect
  const handleBookHotel = () => {
    if (!city) return alert('Fetching your location...');
    const url = `https://www.justdial.com/${city}/Hotels`;
    window.open(url, '_blank');
  };

  return (
    <div className='hotel-rooms-container'>
      <Navbar />

      {/* Book a Hotel button top-right */}
      

      <div className='hotels-container'>
        
        <h2>Hotels Near To YOU!</h2>
        <div >
        <button
          onClick={handleBookHotel}
          style={{
            padding: '10px 20px',
            backgroundColor: '#009dffff',
            color: '#fff',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer',
          }}
        >
          Book a Hotel
        </button>
      </div>
        {loading && (
          <div className="hotel-rooms-loading-container">
            <p className="hotel-rooms-loading">Finding best places for you..🥰</p>
            <WalkingPerson /> 
          </div>
        )}
        {error && <p className='error'>{error}</p>}
        {!loading && hotels.length === 0 && <p>No hotels found nearby.</p>}

        <div className='hotel-cards'>
          {hotels.map((hotel) => (
            <div className='hotel-card' key={hotel.xid}>
              {hotel.image && <img src={hotel.image} alt={hotel.name} className='hotel-image' />}
              <h3>{hotel.name}</h3>
              <p><strong>Address:</strong> {hotel.address}</p>
              <p><strong>Rating:</strong> {hotel.rating}/3⭐</p>
            </div>
          ))}
        </div>
      </div>
      <Footer />
    </div>
  );
}
