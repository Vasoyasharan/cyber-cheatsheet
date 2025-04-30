import { useState, useEffect } from 'react';
import { FaSearch, FaTimes } from 'react-icons/fa';
import { motion } from 'framer-motion';

const Search = ({ onSearch, placeholder = 'Search...', className = '' }) => {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => {
      onSearch(query);
    }, 300);

    return () => clearTimeout(timer);
  }, [query, onSearch]);

  const clearSearch = () => {
    setQuery('');
    onSearch('');
  };

  return (
    <div className={`search-container ${className}`}>
      <div className="search-input-wrapper">
        <FaSearch className="search-icon" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={placeholder}
          className="search-input"
          aria-label="Search"
        />
        {query && (
          <motion.button
            className="clear-button"
            onClick={clearSearch}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            whileHover={{ scale: 1.1 }}
            whileTap={{ scale: 0.9 }}
            aria-label="Clear search"
          >
            <FaTimes />
          </motion.button>
        )}
      </div>
    </div>
  );
};

export default Search;