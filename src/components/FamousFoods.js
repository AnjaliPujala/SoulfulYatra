import React, { useEffect, useState } from 'react';
import Navbar from './Navbar.js';
import '../styles/FamousFoods.css';
import WalkingPerson from './WalkingPerson.js';
import Footer from './Footer.js';
export default function FamousFoods() {
  const [restaurants, setRestaurants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const formatAddress = (address) => {
    if (!address) return 'Address not available';
    const { house_number, road, suburb, city, state, country } = address;
    return [house_number, road, suburb, city, state, country].filter(Boolean).join(', ');
  };

  useEffect(() => {
    if (!navigator.geolocation) {
      setError('Geolocation is not supported by this browser.');
      setLoading(false);
      return;
    }

    navigator.geolocation.getCurrentPosition(async (position) => {
      const { latitude, longitude } = position.coords;

      try {
        const response = await fetch(
          `http://localhost:5000/famous-restaurants?lat=${latitude}&lon=${longitude}&radius=10000`,{
            method: 'GET',
            headers:{
              'Content-Type':'application/json',
              
            },
            credentials:'include',
          });
          if (response.status === 401) {
            setError('Token expired. Please login again.');
            return;
          }
        const data = await response.json();

        const nearbyRestaurants = Array.isArray(data.restaurants) ? data.restaurants : [];

        const detailedRestaurants = [];
        for (let restaurant of nearbyRestaurants) {
          try {
            const res = await fetch(`http://localhost:5000/get-place-image?xid=${restaurant.properties.xid}`);
            const json = await res.json();
            const restaurantData = json.data || {};
            detailedRestaurants.push({
              name: restaurantData.name || restaurant.properties.name,
              address: formatAddress(restaurantData.address),
              rating: restaurantData.rate || restaurant.properties.rate || 'N/A',
              image: restaurantData.preview?.source || null,
              xid: restaurantData.xid || restaurant.properties.xid,
            });
          } catch (err) {
            console.error('Error fetching restaurant details for', restaurant.properties.name, err);
            detailedRestaurants.push({
              name: restaurant.properties.name,
              address: 'Address not available',
              rating: restaurant.properties.rate || 'N/A',
              image: null,
              description: 'No description available',
              xid: restaurant.properties.xid,
            });
          }
          await new Promise((resolve) => setTimeout(resolve, 300));
        }

        setRestaurants(detailedRestaurants);
      } catch (err) {
        console.error(err);
        setError('Failed to fetch famous restaurants.');
      } finally {
        setLoading(false);
      }
    }, (err) => {
      setError('Failed to get your location.');
      setLoading(false);
    });
  }, []);

  return (
    <div className="famous-foods-container">
      <Navbar />
      <div className="famous-foods-content">
        <h2>Famous Restaurants Near You ❤️</h2>
        
        {loading && (
          <div className='restaurants-loading-container'>
          <p>Finding famous restaurants for you...</p>
          <WalkingPerson/>
        </div>)}
        {error && <p className="error">{error}</p>}
        {!loading && !error && restaurants.length === 0 && <p>No famous restaurants found nearby.</p>}

        <div className="food-cards">
          {restaurants.map((restaurant) => (
            <div className="food-card" key={restaurant.xid}>
              {restaurant.image && <img src={restaurant.image} alt={restaurant.name} className="food-image" />}
              <h3>{restaurant.name}</h3>
              <p><strong>Address:</strong> {restaurant.address}</p>
              <p><strong>Rating:</strong> {restaurant.rating}/3⭐</p>
            </div>
          ))}
        </div>
      </div>
      <Footer/>
    </div>
  );
}
