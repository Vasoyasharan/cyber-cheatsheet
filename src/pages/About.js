import { motion } from 'framer-motion';
import { FaGithub, FaLinkedin, FaShieldAlt } from 'react-icons/fa';
import GradientHeader from '../components/UI/GradientHeader';

const About = () => {
  return (
    <div className="about-page">
      <GradientHeader 
        title="About This Project" 
        subtitle="Interactive Cybersecurity Cheat Sheet"
        icon={<FaShieldAlt />}
      />
      
      <motion.div 
        className="about-content"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <div className="about-section">
          <h2>Project Purpose</h2>
          <p>
            This application was created to serve as an interactive reference for cybersecurity professionals,
            penetration testers, and ethical hackers. It provides command builders for common security tools
            and cheat sheets for various security testing scenarios.
          </p>
        </div>
        
        <div className="about-section">
          <h2>Features</h2>
          <ul>
            <li>Interactive command builders for tools like Nmap, Metasploit, and SQLmap</li>
            <li>Comprehensive cheat sheets for privilege escalation and web app testing</li>
            <li>Copy-to-clipboard functionality for quick command usage</li>
            <li>Responsive design that works on desktop and mobile</li>
            <li>Dark/light mode toggle</li>
          </ul>
        </div>
        
        <div className="about-section">
          <h2>Technology Stack</h2>
          <p>
            This project was built with React.js and utilizes various modern web technologies:
          </p>
          <ul>
            <li>React Hooks for state management</li>
            <li>Framer Motion for animations</li>
            <li>React Icons for scalable vector icons</li>
            <li>CSS custom properties for theming</li>
          </ul>
        </div>
        
        <div className="about-section">
          <h2>Disclaimer</h2>
          <p className="disclaimer">
            This tool is provided for educational and legitimate security testing purposes only.
            Unauthorized scanning or exploitation of systems you don't own or have explicit permission
            to test is illegal. Always obtain proper authorization before performing any security testing.
          </p>
        </div>
        
        <div className="about-links">
          <a href="https://github.com/Vasoyasharan/cyber-cheatsheet" target="_blank" rel="noopener noreferrer">
            <FaGithub /> GitHub Repository
          </a>
          <a href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a/" target="_blank" rel="noopener noreferrer">
            <FaLinkedin /> Developer LinkedIn
          </a>
        </div>
      </motion.div>
    </div>
  );
};

export default About;