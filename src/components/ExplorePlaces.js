import React, { useState } from "react";
import "../styles/ExplorePlaces.css";
import Navbar from "./Navbar";
import WalkingPerson from "./WalkingPerson"; // Assuming this is a loading animation component
import Footer from './Footer.js';
export default function ExplorePlaces() {

  const [placeQuery, setPlaceQuery] = useState("");
  const [matchedPlaces, setMatchedPlaces] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [loading, setLoading] = useState(false);

  
  const formatAddress = (addr) => {
    if (!addr) return "No address available";
    const { city, state, suburb, country, postcode } = addr;
    return [suburb, city, state, country, postcode].filter(Boolean).join(", ");
  };

  const handleSearch = async () => {
    setLoading(true);
    

    try {
      const response = await fetch(`http://localhost:5000/get-places-by-name?name=${encodeURIComponent(placeQuery)}`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      if (data.error) {
        console.log(data.error);
      } else {
        
        fetchPlaces(data.places);
      }

    } catch (err) {
      console.error('Error fetching place:', err);
      
    } finally {
      setLoading(false);
    }
};


const fetchPlaces = async (places) => {
  const results = await Promise.all(
    places.map(async (place) => {
      try {
        const res = await fetch(`http://localhost:5000/get-place-image?xid=${place.properties.xid}`);
        const json = await res.json();
        const placeData = json.data || {};        

        return {
          name: placeData.name,
          description: placeData.wikipedia_extracts?.text,
          kinds: placeData.kinds,
          address: formatAddress(placeData.address),
          image: placeData.preview?.source,
          xid: placeData.xid
        };

      } catch (err) {
        console.error("Error fetching:", place.properties.name, err);
        return null; 
      }
    })
  );

  setIsSearching(true);
  setMatchedPlaces(results.filter(place => place !== null));
};




  

  return (
    <div className="explore-container">
      <Navbar />
      <div className="explorer">
        <h1 className="explore-title">Explore Places</h1>

        <div className="search-bar">
          <div className="input-group">
            <input
              type="text"
              placeholder="Search by place..."
              value={placeQuery}
              onChange={(e) => setPlaceQuery(e.target.value)}
            />
          </div>
        
          <button onClick={handleSearch}>Search</button>
        </div>

        {loading && <WalkingPerson/>}
        {matchedPlaces.length > 0 ? (
          <div className="places-container">
            {matchedPlaces.map((place, index) => 
              place?.name && (
                <div className="card" key={index} style={{ margin: "1rem auto", maxWidth: "300px" }}>

                  <div className="card-content">
                    {place.image && <img src={place.image} alt={place.name} style={{ width: '100%', borderRadius: '8px' }} />}
                    <h3>{place.name}</h3>
                    <p>{place.kinds}</p>
                    <p>{place.address}</p>
                    <p>{place.description}</p>
                    
                    {/*<button className="see-more-btn">See More</button>*/}
                  </div>
                </div>
              )
            )}
          </div>
        ) : (
          isSearching && <p>No places found</p>
        )}



      </div>
      <Footer/>
    </div>
  );
}
