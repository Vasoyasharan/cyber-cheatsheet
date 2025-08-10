import { FaGlobe, FaInfoCircle } from 'react-icons/fa';

const osintLinks = [
  { label: 'Google Dorks', url: 'https://www.exploit-db.com/google-hacking-database/' },
  { label: 'Shodan', url: 'https://www.shodan.io/' },
  { label: 'theHarvester', url: 'https://github.com/laramies/theHarvester' },
  { label: 'SpiderFoot', url: 'https://www.spiderfoot.net/' },
  { label: 'Maltego', url: 'https://www.maltego.com/' },
  { label: 'Recon-ng', url: 'https://github.com/lanmaster53/recon-ng' },
  { label: 'GHunt', url: 'https://github.com/mxrch/GHunt' },
  { label: 'OSINT Framework', url: 'https://osintframework.com/' },
];

const OSINTQuickRef = () => (
  <div className="command-builder">
    <div className="builder-header">
      <FaGlobe className="icon" />
      <h2>OSINT Quick Reference</h2>
      <p>Open Source Intelligence tools and resources</p>
    </div>
    <div className="form-group">
      <label>Popular OSINT Tools & Resources <FaInfoCircle title="Click to open in a new tab" /></label>
      <ul style={{ marginTop: '1rem', marginLeft: '1.5rem' }}>
        {osintLinks.map(link => (
          <li key={link.url} style={{ marginBottom: '0.7rem' }}>
            <a href={link.url} target="_blank" rel="noopener noreferrer">{link.label}</a>
          </li>
        ))}
      </ul>
    </div>
    <div className="info-tip">
      <FaInfoCircle className="icon" />
      <p>OSINT is about gathering information from public sources. Always respect privacy and legal boundaries.</p>
    </div>
  </div>
);

export default OSINTQuickRef;
