import { motion } from 'framer-motion';
import { FaShieldAlt, FaTerminal, FaBook, FaTools } from 'react-icons/fa';
import AnimatedCard from '../components/UI/AnimatedCard';
import GradientHeader from '../components/UI/GradientHeader';

const Home = () => {
  const features = [
    {
      icon: <FaTerminal />,
      title: 'Interactive Command Builders',
      description: 'Generate commands for popular security tools with easy-to-use interfaces'
    },
    {
      icon: <FaBook />,
      title: 'Comprehensive Cheat Sheets',
      description: 'Quick reference for common techniques and commands'
    },
    {
      icon: <FaTools />,
      title: 'Multiple Tools Supported',
      description: 'Nmap, Metasploit, SQLmap, Hydra, Burp Suite, and more'
    },
    {
      icon: <FaShieldAlt />,
      title: 'Ethical Focus',
      description: 'Emphasis on proper authorization and legal considerations'
    }
  ];

  return (
    <div className="home-page">
      <GradientHeader 
        title="Cybersecurity Cheat Sheet" 
        subtitle="Interactive reference for security professionals"
        icon={<FaShieldAlt />}
      />
      
      <div className="features-grid">
        {features.map((feature, index) => (
          <AnimatedCard key={index} delay={index}>
            <div className="feature-card">
              <div className="feature-icon">{feature.icon}</div>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
            </div>
          </AnimatedCard>
        ))}
      </div>
      
      <motion.div 
        className="getting-started"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <h2>Getting Started</h2>
        <p>
          Use the navigation menu to explore the available tools and cheat sheets.
          Each command builder provides options to customize your commands and copy them
          to your clipboard for immediate use.
        </p>
      </motion.div>
    </div>
  );
};

export default Home;