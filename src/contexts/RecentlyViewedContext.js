import { createContext, useContext, useState, useEffect } from 'react';

const RecentlyViewedContext = createContext();

export const RecentlyViewedProvider = ({ children }) => {
  const [recentTools, setRecentTools] = useState(() => {
    try { return JSON.parse(localStorage.getItem('recentTools') || '[]'); } catch { return []; }
  });
  const [recentSheets, setRecentSheets] = useState(() => {
    try { return JSON.parse(localStorage.getItem('recentSheets') || '[]'); } catch { return []; }
  });

  useEffect(() => { localStorage.setItem('recentTools', JSON.stringify(recentTools)); }, [recentTools]);
  useEffect(() => { localStorage.setItem('recentSheets', JSON.stringify(recentSheets)); }, [recentSheets]);

  const addRecentTool = (tool) => {
    setRecentTools(prev => {
      const filtered = prev.filter(t => t.id !== tool.id);
      return [tool, ...filtered].slice(0, 5);
    });
  };

  const addRecentSheet = (sheet) => {
    setRecentSheets(prev => {
      const filtered = prev.filter(s => s.id !== sheet.id);
      return [sheet, ...filtered].slice(0, 5);
    });
  };

  return (
    <RecentlyViewedContext.Provider value={{ recentTools, recentSheets, addRecentTool, addRecentSheet }}>
      {children}
    </RecentlyViewedContext.Provider>
  );
};

export const useRecentlyViewed = () => useContext(RecentlyViewedContext);
