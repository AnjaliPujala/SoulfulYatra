import { useEffect, useState } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import "../styles/Profile.css";  
import { useNavigate } from "react-router-dom";
function Profile() {
  const [profile, setProfile] = useState(null);
  const [trips, setTrips] = useState([]);
  const [expandedTrip, setExpandedTrip] = useState(null);
  const navigate=useNavigate();
  useEffect(() => {
   
    fetch("http://localhost:5000/profile", {
      method: "GET",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
    })
      .then((res) => {
        if(res.status===401) {
            navigate('/login');
        }
        if (!res.ok) throw new Error("Failed to fetch profile");
        return res.json();
      })
      .then((data) => setProfile(data.user))
      .catch((err) => console.error("Error fetching profile:", err));

    
    fetch("http://localhost:5000/get-saved-trips", {
      method: "GET",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch trips");
        return res.json();
      })
      .then((data) => setTrips(data.trips))
      .catch((err) => console.error("Error fetching trips:", err));
  }, []);

  if (!profile) return <p>Loading profile...</p>;

  return (
    <div className="profile-main-container">
      <Navbar />
      <div className="profile-container">
        <h2 className="profile-heading">Welcome, {profile.name}</h2>

        <h3 className="profile-subheading">Your Saved Trips</h3>
        {trips.length === 0 ? (
          <p>No saved trips yet.</p>
        ) : (
          <div className="saved-trips-grid">
            {trips.map((trip, idx) => (
              <div key={idx} style={{ width: "100%" }}>
                {/* Card */}
                <div className="saved-trip-card">
                  <h4>{trip.destination}</h4>
                  <p>{trip.days} days</p>
                  <button
                    className="view-btn"
                    onClick={() =>
                      setExpandedTrip(expandedTrip === idx ? null : idx)
                    }
                  >
                    {expandedTrip === idx ? "Hide Plan" : "View More"}
                  </button>
                </div>

               
                {expandedTrip === idx && (
                  <div className="trip-details">
                    {trip.tripData.map((day, dIdx) => (
                      <div key={dIdx} className="trip-day">
                        <h5>{day.day}</h5>
                        <ul>
                          {day.activities.map((act, aIdx) => (
                            <li key={aIdx}>
                              <strong>{act.time}:</strong> {act.activity}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      <Footer />
    </div>
  );
}

export default Profile;
