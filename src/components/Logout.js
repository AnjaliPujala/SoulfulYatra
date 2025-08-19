import React, { useEffect } from 'react'
import { useNavigate} from 'react-router-dom';
export default function Logout() {
    localStorage.removeItem('email');
    localStorage.removeItem('token');
    localStorage.removeItem('name');
    localStorage.removeItem('phone');
    const navigate = useNavigate();
    useEffect(() => {
        // Redirect to home page after logout
        navigate('/home');
    }, [navigate]);
  return (
    <div>
      
    </div>
  )
}
