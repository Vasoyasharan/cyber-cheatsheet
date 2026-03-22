import { motion } from 'framer-motion';
import { FaGithub, FaLinkedin, FaShieldAlt, FaEnvelope, FaHome, FaTools, FaBook, FaHeart, FaExternalLinkAlt, FaArrowUp } from 'react-icons/fa';
import { useContext } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';

const Footer = () => {
  const { theme } = useContext(ThemeContext);

  const footerLinks = {
    'Quick Links': [
      { icon: <FaHome />, label: 'Home', href: '/' },
      { icon: <FaTools />, label: 'Tools', href: '/tools' },
      { icon: <FaBook />, label: 'Cheat Sheets', href: '/cheatsheets' },
    ],
    'Resources': [
      { label: 'GitHub Repository', href: 'https://github.com/Vasoyasharan/cyber-cheatsheet', external: true },
      { label: 'Security Tools Database', href: '#', external: true },
      { label: 'Penetration Testing Guide', href: '#', external: true },
    ],
    'Legal': [
      { label: 'Terms of Service', href: '#' },
      { label: 'Privacy Policy', href: '#' },
      { label: 'Disclaimer', href: '/about' },
    ]
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.3 } }
  };

  return (
    <motion.footer
      className={`footer ${theme}`}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.5, duration: 0.6 }}
    >
      <div className="footer-content">
        {/* Brand Section */}
        <motion.div 
          className="footer-section footer-brand-section"
          variants={itemVariants}
        >
          <div className="footer-brand">
            <motion.div 
              className="brand-icon-wrapper"
              animate={{ rotate: 360 }}
              transition={{ duration: 20, repeat: Infinity }}
            >
              <FaShieldAlt className="brand-icon" />
            </motion.div>
            <div>
              <h3>CyberCheat</h3>
              <p className="brand-tagline">Professional Security Reference Tool</p>
            </div>
          </div>
          <p className="brand-description">
            Your one-stop destination for cybersecurity tools, command builders, and comprehensive cheat sheets.
            Built to help security professionals work efficiently.
          </p>
          
          {/* Social Links */}
          <div className="social-links">
            <motion.a 
              href="https://github.com/Vasoyasharan" 
              target="_blank" 
              rel="noopener noreferrer"
              className="social-btn github"
              whileHover={{ scale: 1.15, y: -5 }}
              whileTap={{ scale: 0.95 }}
              title="GitHub"
            >
              <FaGithub />
            </motion.a>
            <motion.a 
              href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a" 
              target="_blank" 
              rel="noopener noreferrer"
              className="social-btn linkedin"
              whileHover={{ scale: 1.15, y: -5 }}
              whileTap={{ scale: 0.95 }}
              title="LinkedIn"
            >
              <FaLinkedin />
            </motion.a>
            <motion.a 
              href="mailto:sharan@example.com"
              className="social-btn email"
              whileHover={{ scale: 1.15, y: -5 }}
              whileTap={{ scale: 0.95 }}
              title="Email"
            >
              <FaEnvelope />
            </motion.a>
          </div>
        </motion.div>

        {/* Links Sections */}
        {Object.entries(footerLinks).map(([title, links]) => (
          <motion.div 
            key={title}
            className="footer-section footer-links-section"
            variants={itemVariants}
          >
            <h4>{title}</h4>
            <ul>
              {links.map((link, idx) => (
                <motion.li 
                  key={idx}
                  whileHover={{ x: 5 }}
                >
                  <a 
                    href={link.href} 
                    target={link.external ? '_blank' : undefined}
                    rel={link.external ? 'noopener noreferrer' : undefined}
                    className="footer-link"
                  >
                    {link.icon && <span className="link-icon">{link.icon}</span>}
                    <span>{link.label}</span>
                    {link.external && <FaExternalLinkAlt className="external-icon" />}
                  </a>
                </motion.li>
              ))}
            </ul>
          </motion.div>
        ))}

        {/* Features Highlights */}
        <motion.div 
          className="footer-section footer-features"
          variants={itemVariants}
        >
          <h4>Why CyberCheat?</h4>
          <div className="features-list">
            <motion.div 
              className="feature-item"
              whileHover={{ x: 5 }}
            >
              <span className="feature-check">✓</span>
              <span>14+ Interactive Tools</span>
            </motion.div>
            <motion.div 
              className="feature-item"
              whileHover={{ x: 5 }}
            >
              <span className="feature-check">✓</span>
              <span>15+ Cheat Sheets</span>
            </motion.div>
            <motion.div 
              className="feature-item"
              whileHover={{ x: 5 }}
            >
              <span className="feature-check">✓</span>
              <span>Dark/Light Mode</span>
            </motion.div>
            <motion.div 
              className="feature-item"
              whileHover={{ x: 5 }}
            >
              <span className="feature-check">✓</span>
              <span>Mobile Responsive</span>
            </motion.div>
          </div>
        </motion.div>
      </div>

      {/* Bottom Bar */}
      <motion.div 
        className="footer-bottom"
        variants={itemVariants}
      >
        <div className="footer-disclaimer">
          <p>
            ⚠️ For educational and authorized security testing only. Always obtain proper authorization before testing systems.
          </p>
        </div>

        <div className="footer-copyright">
          <p>
            <FaHeart className="heart-icon" /> Made with passion by 
            <motion.a 
              href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a"
              target="_blank"
              rel="noopener noreferrer"
              whileHover={{ color: 'var(--primary)' }}
            >
              {' '}Sharan Vasoya
            </motion.a>
            {' '} | &copy; {new Date().getFullYear()} CyberCheat. All rights reserved.
          </p>
        </div>

        {/* Back to Top Button */}
        <motion.button 
          className="back-to-top"
          onClick={scrollToTop}
          whileHover={{ scale: 1.1, y: -5 }}
          whileTap={{ scale: 0.95 }}
          title="Back to top"
          animate={{ y: [0, 5, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          <FaArrowUp />
        </motion.button>
      </motion.div>
    </motion.footer>
  );
};

export default Footer;