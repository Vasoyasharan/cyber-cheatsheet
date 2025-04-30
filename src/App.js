import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { CommandHistoryProvider } from './contexts/CommandHistoryContext';
import Layout from './components/Layout';
import Home from './pages/Home';
import Tools from './pages/Tools';
import CheatSheets from './pages/CheatSheets';
import About from './pages/About';
import './styles/global.css';
import './styles/animations.css';
import './styles/themes.css';

function App() {
  return (
    <ThemeProvider>
      <CommandHistoryProvider>
        <Router>
          <Layout>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/tools" element={<Tools />} />
              <Route path="/cheatsheets" element={<CheatSheets />} />
              <Route path="/about" element={<About />} />
            </Routes>
          </Layout>
        </Router>
      </CommandHistoryProvider>
    </ThemeProvider>
  );
}

export default App;