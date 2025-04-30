import { createContext, useState, useContext, useEffect } from 'react';

const CommandHistoryContext = createContext();

export const CommandHistoryProvider = ({ children }) => {
  const [history, setHistory] = useState(() => {
    // Load from localStorage if available
    const savedHistory = localStorage.getItem('commandHistory');
    return savedHistory ? JSON.parse(savedHistory) : [];
  });

  // Save to localStorage whenever history changes
  useEffect(() => {
    localStorage.setItem('commandHistory', JSON.stringify(history));
  }, [history]);

  const addToHistory = (command) => {
    setHistory(prev => {
      // Avoid duplicates and keep only the last 10 commands
      const newHistory = [command, ...prev.filter(cmd => cmd !== command)].slice(0, 10);
      return newHistory;
    });
  };

  const clearHistory = () => {
    setHistory([]);
  };

  return (
    <CommandHistoryContext.Provider value={{ history, addToHistory, clearHistory }}>
      {children}
    </CommandHistoryContext.Provider>
  );
};

export const useCommandHistory = () => {
  const context = useContext(CommandHistoryContext);
  if (!context) {
    throw new Error('useCommandHistory must be used within a CommandHistoryProvider');
  }
  return context;
};