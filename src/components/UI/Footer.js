import { motion } from 'framer-motion';
import { FaGithub, FaLinkedin, FaShieldAlt } from 'react-icons/fa';
import { useContext } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';

const Footer = () => {
  const { theme } = useContext(ThemeContext);

  return (
    <motion.footer
      className={`footer ${theme}`}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.5 }}
    >
      <div className="footer-content">
        <div className="footer-brand">
          <FaShieldAlt className="brand-icon" />
          <span>CyberCheat</span>
        </div>
        
        <div className="footer-links">
          <a href="https://github.com/Vasoyasharan" target="_blank" rel="noopener noreferrer">
            <FaGithub /> GitHub
          </a>
          <a href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a" target="_blank" rel="noopener noreferrer">
            <FaLinkedin /> LinkedIn
          </a>
        </div>
        
        <div className="footer-disclaimer">
          <p>
            For educational and authorized security testing purposes only.
            Always obtain proper authorization before testing systems.
          </p>
        </div>
        
        <div className="footer-copyright">
          <p>&copy; {new Date().getFullYear()} CyberCheat. All rights reserved.</p>
        </div>
      </div>
    </motion.footer>
  );
};

export default Footer;