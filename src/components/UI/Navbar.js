import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FaHome, FaTools, FaBook, FaInfoCircle } from 'react-icons/fa';
import { useContext } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';

const Navbar = () => {
  const { theme } = useContext(ThemeContext);

  const navItems = [
    { path: '/', name: 'Home', icon: <FaHome /> },
    { path: '/tools', name: 'Tools', icon: <FaTools /> },
    { path: '/cheatsheets', name: 'Cheat Sheets', icon: <FaBook /> },
    { path: '/about', name: 'About', icon: <FaInfoCircle /> }
  ];

  return (
    <nav className={`navbar ${theme}`}>
      <div className="nav-container">
        <div className="nav-logo">
          <span>CyberCheat</span>
        </div>
        <ul className="nav-links">
          {navItems.map((item, index) => (
            <motion.li
              key={item.path}
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <NavLink
                to={item.path}
                className={({ isActive }) => isActive ? 'active' : ''}
              >
                {item.icon}
                <span>{item.name}</span>
              </NavLink>
            </motion.li>
          ))}
        </ul>
      </div>
    </nav>
  );
};

export default Navbar;