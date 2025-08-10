import { FaShieldAlt, FaInfoCircle } from 'react-icons/fa';

const steps = [
  'Identify and contain the incident (disconnect affected systems)',
  'Preserve volatile data (memory, logs, network connections)',
  'Collect and analyze evidence (disk images, logs, malware samples)',
  'Eradicate the threat (remove malware, patch vulnerabilities)',
  'Recover systems (restore from backups, monitor for reinfection)',
  'Document everything (timeline, actions, findings)',
  'Report to stakeholders and authorities as required',
];

const IRChecklist = () => (
  <div className="command-builder">
    <div className="builder-header">
      <FaShieldAlt className="icon" />
      <h2>Incident Response Checklist</h2>
      <p>Basic steps for handling a security incident</p>
    </div>
    <div className="form-group">
      <label>IR Steps <FaInfoCircle title="Follow these steps during an incident" /></label>
      <ol style={{ marginTop: '1rem', marginLeft: '1.5rem' }}>
        {steps.map((step, i) => (
          <li key={i} style={{ marginBottom: '0.7rem' }}>{step}</li>
        ))}
      </ol>
    </div>
    <div className="info-tip">
      <FaInfoCircle className="icon" />
      <p>This is a basic checklist. Always follow your organization’s IR plan and consult with experts as needed.</p>
    </div>
  </div>
);

export default IRChecklist;
