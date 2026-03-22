import { createContext, useState, useCallback, useContext } from 'react';

const SearchContext = createContext();

// Fuzzy search algorithm
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

  // Must match all characters to return score
  return queryIdx === query.length ? score : 0;
};

export const SearchProvider = ({ children }) => {
  const [searchResults, setSearchResults] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    category: 'all',
    difficulty: 'all',
    type: 'all' // 'command', 'cheatsheet', 'utility'
  });

  const search = useCallback((query, allItems, appliedFilters = filters) => {
    setSearchQuery(query);

    if (!query.trim()) {
      setSearchResults([]);
      return;
    }

    let filtered = allItems.filter(item => {
      // Apply category filter
      if (appliedFilters.category !== 'all' && item.category !== appliedFilters.category) {
        return false;
      }

      // Apply difficulty filter
      if (appliedFilters.difficulty !== 'all' && item.difficulty !== appliedFilters.difficulty) {
        return false;
      }

      // Apply type filter
      if (appliedFilters.type !== 'all' && item.type !== appliedFilters.type) {
        return false;
      }

      return true;
    });

    // Score and sort results
    const scored = filtered.map(item => {
      const titleScore = fuzzyMatch(query, item.name || item.title || '');
      const descScore = fuzzyMatch(query, item.description || '');
      const tagScore = (item.tags || []).some(tag => 
        tag.toLowerCase().includes(query.toLowerCase())
      ) ? 50 : 0;

      const totalScore = titleScore * 2 + descScore + tagScore;

      return {
        ...item,
        score: totalScore
      };
    });

    const results = scored
      .filter(item => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 50); // Limit to 50 results

    setSearchResults(results);
  }, [filters]);

  const updateFilters = (newFilters) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  };

  return (
    <SearchContext.Provider value={{
      searchResults,
      searchQuery,
      filters,
      search,
      updateFilters
    }}>
      {children}
    </SearchContext.Provider>
  );
};

export const useSearch = () => {
  const context = useContext(SearchContext);
  if (!context) {
    throw new Error('useSearch must be used within SearchProvider');
  }
  return context;
};

export default SearchContext;
