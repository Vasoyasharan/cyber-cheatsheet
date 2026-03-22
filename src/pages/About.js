import { motion } from 'framer-motion';
import { FaGithub, FaLinkedin, FaShieldAlt, FaCode, FaRocket, FaUsers, FaMobileAlt, FaPalette, FaCheck, FaLightbulb } from 'react-icons/fa';
import GradientHeader from '../components/UI/GradientHeader';

const About = () => {
  const stats = [
    { icon: <FaShieldAlt />, label: 'Security Tools', value: '14+' },
    { icon: <FaCode />, label: 'Cheat Sheets', value: '15+' },
    { icon: <FaUsers />, label: 'For Everyone', value: 'Beginners → Pros' },
    { icon: <FaMobileAlt />, label: 'Platforms', value: 'Desktop & Mobile' },
  ];

  const features = [
    {
      icon: <FaCode />,
      title: 'Interactive Builders',
      description: 'Command builders for Nmap, Metasploit, SQLmap, and 11+ other tools'
    },
    {
      icon: <FaLightbulb />,
      title: 'Smart Cheat Sheets',
      description: 'Comprehensive guides for privilege escalation, web apps, and more'
    },
    {
      icon: <FaRocket />,
      title: 'Lightning Fast',
      description: 'Instant command generation with copy-to-clipboard functionality'
    },
    {
      icon: <FaPalette />,
      title: 'Modern Design',
      description: 'Responsive UI with dark/light mode support and smooth animations'
    },
    {
      icon: <FaCheck />,
      title: 'Offline Ready',
      description: 'Command history persists with localStorage, work anywhere anytime'
    },
    {
      icon: <FaMobileAlt />,
      title: 'Mobile Optimized',
      description: 'Perfect for pentesters on-the-go with touch-friendly interface'
    }
  ];

  const techStack = [
    { category: 'Frontend', items: ['React 19.1', 'Framer Motion 12.9.2', 'React Router', 'React Icons 5.5.0'] },
    { category: 'Styling', items: ['CSS Custom Properties', 'Responsive Design', 'Dark/Light Themes', 'Animation Library'] },
    { category: 'State Management', items: ['React Hooks', 'Context API', 'localStorage Persistence'] },
    { category: 'Tools & Libraries', items: ['React Toastify', 'Clipboard API', 'Modern Browser APIs'] },
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1, delayChildren: 0.2 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5 } }
  };

  return (
    <div className="about-page">
      <GradientHeader 
        title="About CyberCheat" 
        subtitle="Professional Cybersecurity Reference Tool for All Skill Levels"
        icon={<FaShieldAlt />}
      />
      
      <motion.div 
        className="about-wrapper"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6 }}
      >
        {/* Stats Section */}
        <motion.section 
          className="about-stats"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
        >
          {stats.map((stat, index) => (
            <motion.div 
              key={index}
              className="stat-card"
              variants={itemVariants}
              whileHover={{ scale: 1.05 }}
            >
              <motion.div 
                className="stat-icon"
                animate={{ y: [0, -5, 0] }}
                transition={{ duration: 3, repeat: Infinity, delay: index * 0.2 }}
              >
                {stat.icon}
              </motion.div>
              <div className="stat-value">{stat.value}</div>
              <div className="stat-label">{stat.label}</div>
            </motion.div>
          ))}
        </motion.section>

        <motion.div 
          className="about-content"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          {/* Purpose Section */}
          <motion.section 
            className="about-section"
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2>🎯 Mission</h2>
            <p>
              CyberCheat is your trusted companion for cybersecurity learning and professional penetration testing. 
              Whether you're a beginner exploring security fundamentals or a seasoned professional conducting authorized 
              security assessments, our tool provides instant access to 14+ command builders and 15+ comprehensive cheat sheets 
              covering every aspect of cybersecurity.
            </p>
          </motion.section>

          {/* Features Grid */}
          <motion.section 
            className="about-features-section"
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2>✨ Key Features</h2>
            <div className="features-grid">
              {features.map((feature, index) => (
                <motion.div 
                  key={index}
                  className="feature-card"
                  variants={itemVariants}
                  whileHover={{ y: -8, boxShadow: '0 12px 24px rgba(0,0,0,0.15)' }}
                >
                  <div className="feature-icon">{feature.icon}</div>
                  <h3>{feature.title}</h3>
                  <p>{feature.description}</p>
                </motion.div>
              ))}
            </div>
          </motion.section>

          {/* Tech Stack Section */}
          <motion.section 
            className="about-tech-section"
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2>⚙️ Technology Stack</h2>
            <div className="tech-grid">
              {techStack.map((tech, index) => (
                <motion.div 
                  key={index}
                  className="tech-category"
                  variants={itemVariants}
                  whileHover={{ backgroundColor: 'var(--primary)', color: 'white' }}
                >
                  <h3>{tech.category}</h3>
                  <ul>
                    {tech.items.map((item, idx) => (
                      <li key={idx}>
                        <span className="tech-dot">●</span> {item}
                      </li>
                    ))}
                  </ul>
                </motion.div>
              ))}
            </div>
          </motion.section>

          {/* Disclaimer Section */}
          <motion.section 
            className="about-disclaimer-section"
            variants={itemVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2>⚠️ Important Disclaimer</h2>
            <div className="disclaimer-box">
              <p>
                <strong>Educational & Authorized Use Only:</strong> This tool is provided for educational purposes and 
                authorized security testing only. Unauthorized scanning, exploitation, or any malicious use of systems you 
                don't own or have explicit written permission to test is <strong>illegal</strong> and punishable by law.
              </p>
              <ul>
                <li>✓ Always obtain documented authorization before testing</li>
                <li>✓ Use in controlled lab environments when learning</li>
                <li>✓ Follow all applicable laws and regulations</li>
                <li>✗ Never test production systems without permission</li>
                <li>✗ Never use for malicious purposes</li>
              </ul>
            </div>
          </motion.section>

          {/* About Developer */}
          <motion.section 
            className="about-developer-section"
            variants={itemVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <h2>👨‍💻 Developer</h2>
            <p>
              Created by <strong>Sharan Vasoya</strong>, a cybersecurity enthusiast passionate about building tools 
              that make security testing accessible and efficient for everyone. Connect to discuss cybersecurity, 
              open-source contributions, or collaborations.
            </p>
          </motion.section>

          {/* Social Links */}
          <motion.div 
            className="about-links"
            variants={containerVariants}
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
          >
            <motion.a 
              href="https://github.com/Vasoyasharan/cyber-cheatsheet" 
              target="_blank" 
              rel="noopener noreferrer"
              className="link-btn github-btn"
              variants={itemVariants}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <FaGithub /> GitHub Repository
            </motion.a>
            <motion.a 
              href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a/" 
              target="_blank" 
              rel="noopener noreferrer"
              className="link-btn linkedin-btn"
              variants={itemVariants}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <FaLinkedin /> Connect on LinkedIn
            </motion.a>
          </motion.div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default About;