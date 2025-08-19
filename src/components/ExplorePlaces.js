import React, { useState } from "react";
import "../styles/ExplorePlaces.css";
import Navbar from "./Navbar";
import WalkingPerson from "./WalkingPerson"; // Assuming this is a loading animation component

export default function ExplorePlaces() {
  const [stateQuery, setStateQuery] = useState("");
  const [placeQuery, setPlaceQuery] = useState("");
  const [matchedPlaces, setMatchedPlaces] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [loading, setLoading] = useState(false);
 const [error, setError] = useState("");
  const [apiResult, setApiResult] = useState(null);
  const indianStates = [
    "Andhra Pradesh",
    "Arunachal Pradesh",
    "Assam",
    "Bihar",
    "Chhattisgarh",
    "Goa",
    "Gujarat",
    "Haryana",
    "Himachal Pradesh",
    "Jharkhand",
    "Karnataka",
    "Kerala",
    "Madhya Pradesh",
    "Maharashtra",
    "Manipur",
    "Meghalaya",
    "Mizoram",
    "Nagaland",
    "Odisha",
    "Punjab",
    "Rajasthan",
    "Sikkim",
    "Tamil Nadu",
    "Telangana",
    "Tripura",
    "Uttar Pradesh",
    "Uttarakhand",
    "West Bengal",
    "Delhi",
    "Jammu & Kashmir",
    "Ladakh",
    "Puducherry",
    "Chandigarh",
    "Daman & Diu",
    "Dadra & Nagar Haveli",
    "Lakshadweep",
    "Andaman & Nicobar Islands"
  ];
  const formatAddress = (addr) => {
    if (!addr) return "No address available";
    const { city, state, suburb, country, postcode } = addr;
    return [suburb, city, state, country, postcode].filter(Boolean).join(", ");
  };

  const handleSearch = async () => {
    setLoading(true);
    setError("");
    setApiResult(null);

    try {
      const response = await fetch(`http://localhost:5000/get-places-by-name?name=${encodeURIComponent(placeQuery)}`);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      if (data.error) {
        setError(data.error);
      } else {
        console.log("API Result:", data.places[0].properties.name);
        setApiResult(data); 
        fetchPlaces(data.places);
      }

    } catch (err) {
      console.error('Error fetching place:', err);
      setError('Failed to fetch place. Please try again.');
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
                    
                    <button className="see-more-btn">See More</button>
                  </div>
                </div>
              )
            )}
          </div>
        ) : (
          isSearching && <p>No places found</p>
        )}



      </div>
      
    </div>
  );
}
