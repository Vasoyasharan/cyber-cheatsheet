import { createContext, useContext, useState, useEffect } from 'react';

const SidebarContext = createContext();

export const SidebarProvider = ({ children }) => {
  const [expanded, setExpanded] = useState(() => {
    try { return localStorage.getItem('sidebarExpanded') !== 'false'; } catch { return true; }
  });

  const toggle = () => setExpanded(prev => {
    localStorage.setItem('sidebarExpanded', String(!prev));
    return !prev;
  });

  const close = () => { setExpanded(false); localStorage.setItem('sidebarExpanded', 'false'); };

  return (
    <SidebarContext.Provider value={{ expanded, toggle, close }}>
      {children}
    </SidebarContext.Provider>
  );
};

export const useSidebar = () => useContext(SidebarContext);
