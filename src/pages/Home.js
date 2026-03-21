import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { FaShieldAlt, FaTerminal, FaBook, FaTools, FaArrowRight, FaRocket, FaCheckCircle, FaLightbulb, FaCode, FaNetworkWired, FaStar, FaGem } from 'react-icons/fa';
import AnimatedCard from '../components/UI/AnimatedCard';
import GradientHeader from '../components/UI/GradientHeader';
import DifficultyBadge from '../components/UI/DifficultyBadge';
import AnimatedCounter from '../components/UI/AnimatedCounter';

const Home = () => {
  const navigate = useNavigate();

  // Floating element animation
  const floatingVariants = {
    animate: {
      y: [0, -20, 0],
      rotate: [0, 5, -5, 0],
      transition: {
        duration: 6,
        repeat: Infinity,
        ease: "easeInOut"
      }
    }
  };

  // Pulse animation
  const pulseVariants = {
    animate: {
      scale: [1, 1.05, 1],
      opacity: [0.7, 1, 0.7],
      transition: {
        duration: 2,
        repeat: Infinity
      }
    }
  };

  // Bounce animation
  const bounceVariants = {
    animate: {
      y: [0, -10, 0],
      transition: {
        duration: 1.5,
        repeat: Infinity,
        repeatDelay: 0.5
      }
    }
  };

  // Main features
  const features = [
    {
      icon: <FaTerminal />,
      title: 'Interactive Command Builders',
      description: 'Generate commands for 14+ security tools with step-by-step guidance',
      tools: 14,
      color: '#6e48aa'
    },
    {
      icon: <FaBook />,
      title: 'Comprehensive Cheat Sheets',
      description: 'Quick reference for 9 domains with real-world attack chains',
      tools: 9,
      color: '#9d50bb'
    },
    {
      icon: <FaTools />,
      title: 'Advanced & Beginner Content',
      description: 'Learn at your own pace with difficulty-tagged resources',
      tools: 100,
      color: '#4776e6'
    },
    {
      icon: <FaShieldAlt />,
      title: 'Ethical & Legal',
      description: 'Always emphasize authorization and responsible disclosure',
      tools: '∞',
      color: '#ff6b6b'
    }
  ];

  // Learning paths
  const learningPaths = [
    {
      title: '🌱 Beginner Track',
      description: 'Start here if you\'re new to cybersecurity',
      difficulty: 'beginner',
      topics: ['Basics', 'Network fundamentals', 'General enumeration'],
      action: 'Learn Basics',
      tools: ['OSINT Quick Ref', 'Nmap', 'Netcat'],
      color: '#4CAF50'
    },
    {
      title: '📈 Intermediate Track',
      description: 'Build your practical skills',
      difficulty: 'intermediate',
      topics: ['Web App Testing', 'Privilege Escalation', 'Post-Exploitation'],
      action: 'Explore Tools',
      tools: ['Burp Suite', 'SQLmap', 'Hydra'],
      color: '#FF9800'
    },
    {
      title: '⚡ Advanced Track',
      description: 'Master advanced techniques',
      difficulty: 'advanced',
      topics: ['Red Teaming', 'Cloud Security', 'C2 Operations'],
      action: 'Advanced Content',
      tools: ['Metasploit', 'Payload Gen', 'C2 Frameworks'],
      color: '#F44336'
    }
  ];

  // Stats with counters
  const stats = [
    { label: 'Tools', value: 14, icon: <FaTerminal /> },
    { label: 'Cheat Sheets', value: 9, icon: <FaBook /> },
    { label: 'Difficulty Levels', value: 3, icon: <FaLightbulb /> },
    { label: 'Resources', value: 100, icon: <FaCheckCircle /> }
  ];

  // Container variants
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5 } }
  };

  return (
    <div className="home-page">
      <GradientHeader 
        title="Cybersecurity Cheat Sheet" 
        subtitle="Master security tools from beginner to advanced level"
        icon={<FaShieldAlt />}
      />

      {/* Hero Animation Section */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1 }}
        style={{
          position: 'relative',
          background: 'linear-gradient(135deg, rgba(110, 72, 170, 0.1) 0%, rgba(71, 118, 230, 0.05) 100%)',
          padding: '60px 20px',
          borderRadius: '20px',
          margin: '30px 20px',
          overflow: 'hidden'
        }}
      >
        {/* Animated background elements */}
        <motion.div
          style={{
            position: 'absolute',
            top: '10%',
            right: '10%',
            width: '300px',
            height: '300px',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(110, 72, 170, 0.3) 0%, transparent 70%)',
            filter: 'blur(40px)'
          }}
          animate={{
            x: [0, 50, -50, 0],
            y: [0, -50, 50, 0]
          }}
          transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
        />
        <motion.div
          style={{
            position: 'absolute',
            bottom: '10%',
            left: '10%',
            width: '250px',
            height: '250px',
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(71, 118, 230, 0.3) 0%, transparent 70%)',
            filter: 'blur(40px)'
          }}
          animate={{
            x: [0, -50, 50, 0],
            y: [0, 50, -50, 0]
          }}
          transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut' }}
        />

        {/* Hero Content */}
        <motion.div
          className="hero-content"
          style={{ position: 'relative', zIndex: 1, textAlign: 'center' }}
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          <motion.div variants={itemVariants}>
            <motion.h2
              style={{
                fontSize: '48px',
                fontWeight: 'bold',
                background: 'linear-gradient(135deg, #6e48aa, #4776e6)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                color: 'transparent',
                marginBottom: '12px'
              }}
              animate={{
                backgroundPosition: ['0% 50%', '100% 50%', '0% 50%']
              }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              Welcome to Your Security Journey
            </motion.h2>
          </motion.div>

          <motion.div variants={itemVariants}>
            <p style={{
              fontSize: '18px',
              opacity: 0.8,
              maxWidth: '600px',
              margin: '0 auto 30px',
              lineHeight: 1.6
            }}>
              Learn cybersecurity from the ground up with interactive tools, comprehensive guides, and real-world examples
            </p>
          </motion.div>

          <motion.div
            variants={itemVariants}
            style={{ display: 'flex', gap: '15px', justifyContent: 'center', flexWrap: 'wrap' }}
          >
            <motion.button
              onClick={() => navigate('/tools')}
              style={{
                background: 'linear-gradient(135deg, #6e48aa, #9d50bb)',
                color: 'white',
                border: 'none',
                borderRadius: '50px',
                padding: '15px 40px',
                cursor: 'pointer',
                fontSize: '16px',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '10px'
              }}
              whileHover={{ scale: 1.1, boxShadow: '0 20px 40px rgba(110, 72, 170, 0.4)' }}
              whileTap={{ scale: 0.95 }}
            >
              <FaRocket /> Quick Start
            </motion.button>
            <motion.button
              onClick={() => navigate('/cheatsheets')}
              style={{
                background: 'transparent',
                color: 'var(--primary)',
                border: '2px solid var(--primary)',
                borderRadius: '50px',
                padding: '13px 40px',
                cursor: 'pointer',
                fontSize: '16px',
                fontWeight: '600',
                display: 'flex',
                alignItems: 'center',
                gap: '10px'
              }}
              whileHover={{ scale: 1.1, background: 'var(--primary)', color: 'white' }}
              whileTap={{ scale: 0.95 }}
            >
              <FaBook /> Explore Guides
            </motion.button>
          </motion.div>
        </motion.div>
      </motion.div>

      {/* Animated Stats Section */}
      <motion.div 
        className="stats-section"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.8 }}
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '20px',
          padding: '40px 20px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}
      >
        {stats.map((stat, index) => (
          <motion.div
            key={index}
            className="stat-card"
            variants={floatingVariants}
            animate="animate"
            style={{
              background: 'var(--card-bg)',
              border: '2px solid var(--primary)',
              borderRadius: '16px',
              padding: '20px',
              textAlign: 'center',
              cursor: 'pointer',
              position: 'relative',
              overflow: 'hidden'
            }}
            whileHover={{
              scale: 1.08,
              boxShadow: '0 10px 30px rgba(110, 72, 170, 0.3)'
            }}
          >
            {/* Glow effect on hover */}
            <motion.div
              style={{
                position: 'absolute',
                inset: 0,
                background: 'radial-gradient(circle, rgba(110, 72, 170, 0.2) 0%, transparent 70%)',
                opacity: 0
              }}
              whileHover={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
            />
            
            <motion.div
              style={{
                fontSize: '28px',
                color: 'var(--primary)',
                marginBottom: '8px',
                display: 'flex',
                justifyContent: 'center'
              }}
              animate={{ rotate: [0, 5, -5, 0] }}
              transition={{ duration: 2, repeat: Infinity, delay: index * 0.2 }}
            >
              {stat.icon}
            </motion.div>
            <motion.div
              style={{
                fontSize: '28px',
                fontWeight: 'bold',
                color: 'var(--text)',
                position: 'relative',
                zIndex: 1
              }}
            >
              <AnimatedCounter to={stat.value} duration={2} label={stat.label} />
            </motion.div>
          </motion.div>
        ))}
      </motion.div>

      {/* Features Grid with Enhanced Animations */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.8 }}
        style={{ padding: '40px 20px' }}
      >
        <motion.h2
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          style={{
            textAlign: 'center',
            marginBottom: '40px',
            color: 'var(--text)',
            fontSize: '36px',
            fontWeight: 'bold'
          }}
        >
          What You Get
        </motion.h2>
        <div className="features-grid" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '25px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}>
          {features.map((feature, index) => (
            <AnimatedCard key={index} delay={index * 0.15}>
              <motion.div
                className="feature-card"
                style={{
                  padding: '30px',
                  borderLeft: `4px solid ${feature.color}`,
                  position: 'relative',
                  overflow: 'hidden'
                }}
                whileHover={{ y: -10 }}
              >
                {/* Animated background */}
                <motion.div
                  style={{
                    position: 'absolute',
                    top: 0,
                    right: 0,
                    width: '100px',
                    height: '100px',
                    borderRadius: '50%',
                    background: `radial-gradient(circle, ${feature.color}22 0%, transparent 70%)`,
                    opacity: 0
                  }}
                  whileHover={{ opacity: 1 }}
                  transition={{ duration: 0.3 }}
                />

                <motion.div
                  className="feature-icon"
                  style={{
                    fontSize: '48px',
                    marginBottom: '15px',
                    color: feature.color,
                    position: 'relative',
                    zIndex: 1
                  }}
                  animate={{ y: [0, -5, 0] }}
                  transition={{ duration: 1.5, repeat: Infinity, delay: index * 0.2 }}
                >
                  {feature.icon}
                </motion.div>
                <h3 style={{ marginBottom: '12px', position: 'relative', zIndex: 1 }}>{feature.title}</h3>
                <p style={{ fontSize: '14px', opacity: 0.8, marginBottom: '15px', position: 'relative', zIndex: 1 }}>
                  {feature.description}
                </p>
                <motion.div
                  style={{
                    marginTop: '15px',
                    fontSize: '13px',
                    opacity: 0.7,
                    position: 'relative',
                    zIndex: 1,
                    display: 'inline-block'
                  }}
                  animate={{ scale: [1, 1.1, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  📊 {feature.tools}+ resources available
                </motion.div>
              </motion.div>
            </AnimatedCard>
          ))}
        </div>
      </motion.div>

      {/* Learning Paths with Enhanced Animations */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7, duration: 0.8 }}
        style={{ padding: '60px 20px', maxWidth: '1200px', margin: '0 auto' }}
      >
        <motion.h2
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          style={{
            textAlign: 'center',
            marginBottom: '40px',
            color: 'var(--text)',
            fontSize: '36px',
            fontWeight: 'bold'
          }}
        >
          Choose Your Path
        </motion.h2>
        <div className="learning-paths" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '25px'
        }}>
          {learningPaths.map((path, index) => (
            <AnimatedCard key={index} delay={index * 0.2}>
              <motion.div
                className="learning-path-card"
                style={{
                  padding: '28px',
                  borderLeft: `5px solid ${path.color}`,
                  cursor: 'pointer',
                  position: 'relative',
                  overflow: 'hidden'
                }}
                whileHover={{ translateX: 8, boxShadow: `0 15px 40px ${path.color}33` }}
              >
                {/* Animated gradient background */}
                <motion.div
                  style={{
                    position: 'absolute',
                    inset: 0,
                    background: `linear-gradient(135deg, ${path.color}11 0%, transparent 100%)`,
                    opacity: 0
                  }}
                  whileHover={{ opacity: 1 }}
                  transition={{ duration: 0.3 }}
                />

                <motion.div style={{ marginBottom: '15px', position: 'relative', zIndex: 1 }}>
                  <motion.h3
                    style={{ marginBottom: '8px', color: 'var(--text)', fontSize: '22px' }}
                    animate={{ color: [path.color, 'var(--text)', path.color] }}
                    transition={{ duration: 3, repeat: Infinity }}
                  >
                    {path.title}
                  </motion.h3>
                  <p style={{ opacity: 0.8, marginBottom: '12px' }}>{path.description}</p>
                </motion.div>

                <motion.div
                  style={{ marginBottom: '15px', position: 'relative', zIndex: 1 }}
                  animate={{ scale: [1, 1.02, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <DifficultyBadge level={path.difficulty} size="sm" />
                </motion.div>

                <div style={{ marginBottom: '15px', position: 'relative', zIndex: 1 }}>
                  <p style={{ fontSize: '12px', opacity: 0.6, marginBottom: '8px', fontWeight: '600' }}>Key Topics:</p>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {path.topics.map((topic, i) => (
                      <motion.span
                        key={i}
                        style={{
                          background: `${path.color}22`,
                          padding: '6px 12px',
                          borderRadius: '12px',
                          fontSize: '11px',
                          color: path.color,
                          fontWeight: '600',
                          border: `1px solid ${path.color}44`
                        }}
                        whileHover={{ scale: 1.1, boxShadow: `0 0 20px ${path.color}77` }}
                      >
                        {topic}
                      </motion.span>
                    ))}
                  </div>
                </div>

                <div style={{ marginBottom: '15px', position: 'relative', zIndex: 1 }}>
                  <p style={{ fontSize: '12px', opacity: 0.6, marginBottom: '8px', fontWeight: '600' }}>Recommended Tools:</p>
                  <div style={{ fontSize: '12px', opacity: 0.85, fontWeight: '500' }}>
                    {path.tools.join(' • ')}
                  </div>
                </div>

                <motion.button
                  onClick={() => navigate(path.title.includes('Beginner') ? '/tools' : path.title.includes('Intermediate') ? '/tools' : '/cheatsheets')}
                  style={{
                    background: path.color,
                    color: 'white',
                    border: 'none',
                    borderRadius: '10px',
                    padding: '12px 20px',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: '600',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    width: '100%',
                    justifyContent: 'center',
                    marginTop: '15px',
                    position: 'relative',
                    zIndex: 1,
                    overflow: 'hidden'
                  }}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {path.action}
                  <motion.span animate={{ x: [0, 5, 0] }} transition={{ duration: 1, repeat: Infinity }}>
                    <FaArrowRight style={{ fontSize: '12px' }} />
                  </motion.span>
                </motion.button>
              </motion.div>
            </AnimatedCard>
          ))}
        </div>
      </motion.div>

      {/* Quick Navigation with Stunning Animations */}
      <motion.div 
        className="quick-nav"
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9, duration: 0.8 }}
        style={{
          padding: '50px 20px',
          background: 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)',
          textAlign: 'center',
          borderRadius: '20px',
          margin: '60px 20px',
          maxWidth: '1200px',
          marginLeft: 'auto',
          marginRight: 'auto',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        {/* Animated background circles */}
        <motion.div
          style={{
            position: 'absolute',
            top: '-50%',
            right: '-10%',
            width: '400px',
            height: '400px',
            borderRadius: '50%',
            background: 'rgba(255, 255, 255, 0.1)',
            filter: 'blur(40px)'
          }}
          animate={{ y: [0, 50, 0], x: [0, 30, 0] }}
          transition={{ duration: 8, repeat: Infinity }}
        />
        <motion.div
          style={{
            position: 'absolute',
            bottom: '-30%',
            left: '-10%',
            width: '300px',
            height: '300px',
            borderRadius: '50%',
            background: 'rgba(255, 255, 255, 0.1)',
            filter: 'blur(40px)'
          }}
          animate={{ y: [0, -50, 0], x: [0, -30, 0] }}
          transition={{ duration: 10, repeat: Infinity }}
        />

        <motion.h2
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          style={{ color: 'white', marginBottom: '25px', position: 'relative', zIndex: 1, fontSize: '32px', fontWeight: 'bold' }}
        >
          🚀 Ready to Get Started?
        </motion.h2>
        <motion.div
          style={{
            display: 'flex',
            gap: '15px',
            justifyContent: 'center',
            flexWrap: 'wrap',
            position: 'relative',
            zIndex: 1
          }}
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          <motion.button
            onClick={() => navigate('/tools')}
            variants={itemVariants}
            style={{
              background: 'white',
              color: 'var(--primary)',
              border: 'none',
              borderRadius: '50px',
              padding: '14px 32px',
              cursor: 'pointer',
              fontSize: '15px',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
            whileHover={{ 
              scale: 1.1, 
              boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
              y: -3
            }}
            whileTap={{ scale: 0.95 }}
          >
            <FaTerminal /> Explore Tools
          </motion.button>
          <motion.button
            onClick={() => navigate('/cheatsheets')}
            variants={itemVariants}
            style={{
              background: 'transparent',
              color: 'white',
              border: '2px solid white',
              borderRadius: '50px',
              padding: '12px 32px',
              cursor: 'pointer',
              fontSize: '15px',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
            whileHover={{
              scale: 1.1,
              background: 'rgba(255, 255, 255, 0.2)',
              backdropFilter: 'blur(10px)',
              y: -3
            }}
            whileTap={{ scale: 0.95 }}
          >
            <FaBook /> Learn Techniques
          </motion.button>
        </motion.div>
      </motion.div>

      {/* Pro Tips with Smooth Animations */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.1, duration: 0.8 }}
        style={{ padding: '60px 20px', maxWidth: '1200px', margin: '0 auto' }}
      >
        <motion.h2
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.2 }}
          style={{ textAlign: 'center', marginBottom: '40px', color: 'var(--text)', fontSize: '36px', fontWeight: 'bold' }}
        >
          💡 Pro Tips
        </motion.h2>
        <div className="tips-grid" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '20px'
        }}>
          {[
            { icon: <FaCheckCircle />, title: 'Use Command History', desc: 'Access your last 10 commands via the history panel', color: '#4CAF50' },
            { icon: <FaCode />, title: 'Copy One-Click', desc: 'Copy commands directly - they\'re already validated', color: '#FF9800' },
            { icon: <FaNetworkWired />, title: 'Dark Mode', desc: 'Toggle dark mode anytime with the button in navbar', color: '#4776e6' },
            { icon: <FaGem />, title: 'Difficulty Badges', desc: 'Filter by skill level to find content right for you', color: '#F44336' }
          ].map((tip, i) => (
            <AnimatedCard key={i} delay={(i + 1) * 0.1}>
              <motion.div
                style={{
                  padding: '25px',
                  borderLeft: `4px solid ${tip.color}`,
                  position: 'relative',
                  overflow: 'hidden',
                  background: 'var(--card-bg)',
                  borderRadius: '8px',
                  cursor: 'pointer'
                }}
                whileHover={{ 
                  y: -8,
                  boxShadow: `0 15px 40px ${tip.color}33`
                }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                {/* Animated gradient background on hover */}
                <motion.div
                  style={{
                    position: 'absolute',
                    inset: 0,
                    background: `linear-gradient(135deg, ${tip.color}11 0%, transparent 100%)`,
                    opacity: 0,
                    borderRadius: '8px'
                  }}
                  whileHover={{ opacity: 1 }}
                  transition={{ duration: 0.3 }}
                />

                <motion.div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '15px',
                    marginBottom: '15px',
                    position: 'relative',
                    zIndex: 1
                  }}
                >
                  {/* Icon with floating animation */}
                  <motion.div
                    style={{
                      color: tip.color,
                      fontSize: '28px',
                      fontWeight: 'bold',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}
                    animate={{ y: [0, -3, 0] }}
                    transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut', delay: i * 0.4 }}
                    whileHover={{
                      y: [0, -8, 0],
                      transition: { duration: 0.6, times: [0, 0.5, 1] }
                    }}
                  >
                    {tip.icon}
                  </motion.div>
                  <h4 style={{ margin: 0, color: 'var(--text)', fontWeight: '700' }}>
                    {tip.title}
                  </h4>
                </motion.div>
                <p style={{ fontSize: '14px', opacity: 0.7, margin: 0, position: 'relative', zIndex: 1, lineHeight: '1.5' }}>
                  {tip.desc}
                </p>
              </motion.div>
            </AnimatedCard>
          ))}
        </div>
      </motion.div>

      {/* Disclaimer with Animated Warning */}
      <motion.div 
        className="disclaimer"
        initial={{ opacity: 0, x: -50 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 1.3, duration: 0.8 }}
        style={{
          padding: '25px 20px',
          background: 'linear-gradient(135deg, #F4433411 0%, transparent 100%)',
          borderLeft: '5px solid #F44336',
          borderRadius: '12px',
          margin: '60px 20px',
          maxWidth: '1200px',
          marginLeft: 'auto',
          marginRight: 'auto',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        <motion.div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '2px',
            background: 'linear-gradient(90deg, transparent, #F44336, transparent)',
            opacity: 0.5
          }}
          animate={{ x: ['-100%', '100%'] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
        <motion.div
          style={{
            display: 'flex',
            alignItems: 'start',
            gap: '15px'
          }}
          animate={{ scale: [1, 1.02, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
        >
          <motion.span
            style={{ fontSize: '24px', marginTop: '2px' }}
            animate={{ rotate: [0, 10, -10, 0] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            ⚠️
          </motion.span>
          <div>
            <strong style={{ color: '#F44336', display: 'block', marginBottom: '6px' }}>Important Legal Notice</strong>
            <p style={{ margin: '0', fontSize: '14px', opacity: 0.9 }}>
              Only use these techniques in authorized testing environments. Always ensure you have proper authorization before conducting security assessments. Unauthorized access to computer systems is illegal. We promote ethical hacking and responsible disclosure.
            </p>
          </div>
        </motion.div>
      </motion.div>

      {/* Footer decorative element */}
      <motion.div
        style={{
          textAlign: 'center',
          padding: '40px 20px',
          opacity: 0.3
        }}
        animate={{ y: [0, -10, 0] }}
        transition={{ duration: 3, repeat: Infinity }}
      >
        <FaStar size={20} style={{ color: 'var(--primary)' }} />
      </motion.div>
    </div>
  );
};

export default Home;