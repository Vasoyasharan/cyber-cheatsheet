import { motion } from 'framer-motion';
import { FaGithub, FaLinkedin, FaShieldAlt, FaEnvelope, FaHome, FaTools, FaBook, FaHeart, FaExternalLinkAlt, FaArrowUp, FaGraduationCap, FaCode } from 'react-icons/fa';
import { useContext } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';

const Footer = () => {
  const { theme } = useContext(ThemeContext);

  const footerLinks = {
    'Quick Links': [
      { icon: <FaHome />, label: 'Home', href: '/' },
      { icon: <FaTools />, label: 'Tools', href: '/tools' },
      { icon: <FaBook />, label: 'Cheat Sheets', href: '/cheatsheets' },
      { icon: <FaCode />, label: 'Utilities', href: '/utilities' },
      { icon: <FaShieldAlt />, label: 'CVE Lookup', href: '/cve-lookup' },
    ],
    'Security Resources': [
      { label: 'OWASP Top 10', href: 'https://owasp.org/www-project-top-ten/', external: true },
      { label: 'HackTricks Book', href: 'https://book.hacktricks.xyz/', external: true },
      { label: 'GTFOBins', href: 'https://gtfobins.github.io/', external: true },
      { label: 'Exploit-DB', href: 'https://www.exploit-db.com/', external: true },
      { label: 'CVE Details', href: 'https://www.cvedetails.com/', external: true },
      { label: 'LOLBAS Project', href: 'https://lolbas-project.github.io/', external: true },
    ],
    'Practice Platforms': [
      { icon: <FaGraduationCap />, label: 'TryHackMe', href: 'https://tryhackme.com', external: true },
      { icon: <FaGraduationCap />, label: 'HackTheBox', href: 'https://hackthebox.com', external: true },
      { icon: <FaGraduationCap />, label: 'PortSwigger Academy', href: 'https://portswigger.net/web-security', external: true },
      { icon: <FaGraduationCap />, label: 'PentesterLab', href: 'https://pentesterlab.com', external: true },
      { icon: <FaGraduationCap />, label: 'PicoCTF', href: 'https://picoctf.org', external: true },
    ],
  };

  const stats = [
    { value: '21+', label: 'Tools' },
    { value: '15+', label: 'Cheat Sheets' },
    { value: '10+', label: 'Utilities' },
    { value: '100+', label: 'Payloads' },
  ];

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: 'smooth' });

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
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
        <motion.div className="footer-section footer-brand-section" variants={itemVariants}>
          <div className="footer-brand">
            <motion.div className="brand-icon-wrapper" animate={{ rotate: 360 }} transition={{ duration: 20, repeat: Infinity }}>
              <FaShieldAlt className="brand-icon" />
            </motion.div>
            <div>
              <h3>CyberCheat</h3>
              <p className="brand-tagline">Professional Security Reference Tool</p>
            </div>
          </div>
          <p className="brand-description">
            Your one-stop destination for cybersecurity tools, command builders, CVE lookup, and comprehensive cheat sheets. Built for security professionals and learners.
          </p>

          {/* Live stats */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', margin: '14px 0' }}>
            {stats.map(s => (
              <div key={s.label} style={{ padding: '8px 12px', borderRadius: '10px', background: 'rgba(124,58,237,0.1)', border: '1px solid rgba(124,58,237,0.2)', textAlign: 'center' }}>
                <div style={{ fontSize: '18px', fontWeight: 800, color: 'var(--primary)' }}>{s.value}</div>
                <div style={{ fontSize: '10px', color: 'var(--text-lighter)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Social Links */}
          <div className="social-links">
            <motion.a href="https://github.com/Vasoyasharan" target="_blank" rel="noopener noreferrer"
              className="social-btn github" whileHover={{ scale: 1.15, y: -5 }} whileTap={{ scale: 0.95 }} title="GitHub">
              <FaGithub />
            </motion.a>
            <motion.a href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a" target="_blank" rel="noopener noreferrer"
              className="social-btn linkedin" whileHover={{ scale: 1.15, y: -5 }} whileTap={{ scale: 0.95 }} title="LinkedIn">
              <FaLinkedin />
            </motion.a>
            <motion.a href="mailto:sharanvasoya@gmail.com"
              className="social-btn email" whileHover={{ scale: 1.15, y: -5 }} whileTap={{ scale: 0.95 }} title="Email">
              <FaEnvelope />
            </motion.a>
          </div>
        </motion.div>

        {/* Links Sections */}
        {Object.entries(footerLinks).map(([title, links]) => (
          <motion.div key={title} className="footer-section footer-links-section" variants={itemVariants}>
            <h4>{title}</h4>
            <ul>
              {links.map((link, idx) => (
                <motion.li key={idx} whileHover={{ x: 5 }}>
                  <a href={link.href} target={link.external ? '_blank' : undefined}
                    rel={link.external ? 'noopener noreferrer' : undefined} className="footer-link">
                    {link.icon && <span className="link-icon">{link.icon}</span>}
                    <span>{link.label}</span>
                    {link.external && <FaExternalLinkAlt className="external-icon" />}
                  </a>
                </motion.li>
              ))}
            </ul>
          </motion.div>
        ))}
      </div>

      {/* Bottom Bar */}
      <motion.div className="footer-bottom" variants={itemVariants}>
        <div className="footer-disclaimer">
          <p>
            ⚠️ For educational and authorized security testing only. Always obtain proper authorization before testing systems. Misuse may be illegal.
          </p>
        </div>

        <div className="footer-copyright">
          <p>
            <FaHeart className="heart-icon" /> Made with passion by
            <motion.a href="https://www.linkedin.com/in/sharan-vasoya-b6a21824a" target="_blank" rel="noopener noreferrer"
              whileHover={{ color: 'var(--primary)' }}>
              {' '}Sharan Vasoya
            </motion.a>
            {' '} | © {new Date().getFullYear()} CyberCheat v2.0 — All rights reserved.
          </p>
        </div>

        {/* Back to Top Button */}
        <motion.button className="back-to-top" onClick={scrollToTop}
          whileHover={{ scale: 1.1, y: -5 }} whileTap={{ scale: 0.95 }}
          title="Back to top" animate={{ y: [0, 5, 0] }} transition={{ duration: 2, repeat: Infinity }}>
          <FaArrowUp />
        </motion.button>
      </motion.div>
    </motion.footer>
  );
};

export default Footer;