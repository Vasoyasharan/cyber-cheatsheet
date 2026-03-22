import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaTimes, FaFilter, FaCheck } from 'react-icons/fa';
import { searchIndex, categories, difficulties, types } from '../../data/searchIndex';
import AnimatedCard from './AnimatedCard';
import DifficultyBadge from './DifficultyBadge';
import { useNavigate } from 'react-router-dom';
import './AdvancedSearch.css';

const AdvancedSearch = ({ onClose, isOpen }) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [selectedType, setSelectedType] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const navigate = useNavigate();

  // Fuzzy search implementation
  const fuzzyMatch = (query, text) => {
    const queryLower = query.toLowerCase();
    const textLower = text.toLowerCase();
    
    let queryIdx = 0;
    let textIdx = 0;
    let score = 0;

    while (queryIdx < query.length && textIdx < text.length) {
      if (queryLower[queryIdx] === textLower[textIdx]) {
        score += 1;
        queryIdx++;
      }
      textIdx++;
    }

    return queryIdx === query.length ? score : 0;
  };

  // Perform search
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    let filtered = searchIndex.filter(item => {
      if (selectedCategory !== 'all' && item.category !== selectedCategory) return false;
      if (selectedDifficulty !== 'all' && item.difficulty !== selectedDifficulty) return false;
      if (selectedType !== 'all' && item.type !== selectedType) return false;
      return true;
    });

    const scored = filtered.map(item => {
      const titleScore = fuzzyMatch(query, item.name || item.title || '');
      const descScore = fuzzyMatch(query, item.description || '');
      const tagScore = (item.tags || []).some(tag => 
        tag.toLowerCase().includes(query.toLowerCase())
      ) ? 50 : 0;

      const totalScore = titleScore * 2 + descScore + tagScore;
      return { ...item, score: totalScore };
    });

    const sorted = scored
      .filter(item => item.score > 0)
      .sort((a, b) => b.score - a.score);

    setResults(sorted);
  }, [query, selectedCategory, selectedDifficulty, selectedType]);

  const handleResultClick = (item) => {
    navigate(item.path);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <motion.div 
      className="advanced-search-overlay"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div 
        className="advanced-search-modal"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="search-header">
          <div className="search-input-group">
            <FaSearch className="search-icon" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search cheat sheets, tools, utilities..."
              className="search-input-large"
              autoFocus
            />
            {query && (
              <button onClick={() => setQuery('')} className="clear-btn">
                <FaTimes />
              </button>
            )}
          </div>
          <button onClick={onClose} className="close-btn">
            <FaTimes />
          </button>
        </div>

        {/* Filter Toggle */}
        <div className="filter-toggle">
          <button 
            onClick={() => setShowFilters(!showFilters)}
            className="toggle-btn"
          >
            <FaFilter /> Filters
          </button>
        </div>

        {/* Filters */}
        {showFilters && (
          <motion.div 
            className="filters-section"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
          >
            {/* Category Filter */}
            <div className="filter-group">
              <h4>Category</h4>
              <div className="filter-options">
                <button
                  className={`filter-option ${selectedCategory === 'all' ? 'active' : ''}`}
                  onClick={() => setSelectedCategory('all')}
                >
                  All Categories
                </button>
                {categories.map(cat => (
                  <button
                    key={cat}
                    className={`filter-option ${selectedCategory === cat ? 'active' : ''}`}
                    onClick={() => setSelectedCategory(cat)}
                  >
                    {selectedCategory === cat && <FaCheck className="check-icon" />}
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Difficulty Filter */}
            <div className="filter-group">
              <h4>Difficulty</h4>
              <div className="filter-options">
                <button
                  className={`filter-option ${selectedDifficulty === 'all' ? 'active' : ''}`}
                  onClick={() => setSelectedDifficulty('all')}
                >
                  All Levels
                </button>
                {difficulties.map(diff => (
                  <button
                    key={diff}
                    className={`filter-option ${selectedDifficulty === diff ? 'active' : ''}`}
                    onClick={() => setSelectedDifficulty(diff)}
                  >
                    {selectedDifficulty === diff && <FaCheck className="check-icon" />}
                    {diff.charAt(0).toUpperCase() + diff.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* Type Filter */}
            <div className="filter-group">
              <h4>Type</h4>
              <div className="filter-options">
                <button
                  className={`filter-option ${selectedType === 'all' ? 'active' : ''}`}
                  onClick={() => setSelectedType('all')}
                >
                  All Types
                </button>
                {types.map(type => (
                  <button
                    key={type.value}
                    className={`filter-option ${selectedType === type.value ? 'active' : ''}`}
                    onClick={() => setSelectedType(type.value)}
                  >
                    {selectedType === type.value && <FaCheck className="check-icon" />}
                    {type.label}
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* Results */}
        <div className="search-results">
          {query.trim() === '' ? (
            <div className="no-query">
              <p>Start typing to search across all tools, cheat sheets, and utilities</p>
            </div>
          ) : results.length === 0 ? (
            <div className="no-results">
              <p>No results found for "{query}"</p>
              <small>Try adjusting your search query or filters</small>
            </div>
          ) : (
            <>
              <p className="results-count">Found {results.length} result{results.length !== 1 ? 's' : ''}</p>
              <motion.div 
                className="results-list"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
              >
                {results.map((item, idx) => (
                  <motion.div
                    key={`${item.id}-${idx}`}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    onClick={() => handleResultClick(item)}
                    className="result-item"
                  >
                    <div className="result-header">
                      <div>
                        <h3>{item.name}</h3>
                        <p className="result-description">{item.description}</p>
                      </div>
                      <DifficultyBadge difficulty={item.difficulty} />
                    </div>
                    <div className="result-meta">
                      <span className="result-type">{item.type}</span>
                      <span className="result-category">{item.category}</span>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            </>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
};

export default AdvancedSearch;
