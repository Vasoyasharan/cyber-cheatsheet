import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { CommandHistoryProvider } from './contexts/CommandHistoryContext';
import { RecentlyViewedProvider } from './contexts/RecentlyViewedContext';
import Layout from './components/Layout';
import Home from './pages/Home';
import Tools from './pages/Tools';
import CheatSheets from './pages/CheatSheets';
import About from './pages/About';
import Utilities from './pages/Utilities';
import LearningPaths from './pages/LearningPaths';
import CommandExplainer from './pages/CommandExplainer';
import Glossary from './pages/Glossary';
import PayloadLibrary from './pages/PayloadLibrary';
import PortReference from './pages/PortReference';
import CVELookup from './pages/CVELookup';
import './styles/global.css';
import './styles/animations.css';
import './styles/themes.css';

function App() {
  return (
    <ThemeProvider>
      <CommandHistoryProvider>
        <RecentlyViewedProvider>
          <Router>
            <Layout>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/tools" element={<Tools />} />
                <Route path="/cheatsheets" element={<CheatSheets />} />
                <Route path="/utilities" element={<Utilities />} />
                <Route path="/about" element={<About />} />
                <Route path="/learning" element={<LearningPaths />} />
                <Route path="/explainer" element={<CommandExplainer />} />
                <Route path="/glossary" element={<Glossary />} />
                <Route path="/payloads" element={<PayloadLibrary />} />
                <Route path="/ports" element={<PortReference />} />
                <Route path="/cve" element={<CVELookup />} />
              </Routes>
            </Layout>
          </Router>
        </RecentlyViewedProvider>
      </CommandHistoryProvider>
    </ThemeProvider>
  );
}

export default App;