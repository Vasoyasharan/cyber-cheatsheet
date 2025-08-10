import { useState } from 'react';
import { FaKey, FaCopy, FaInfoCircle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const hashTypes = [
  { value: '0', label: 'MD5', example: '8743b52063cd84097a65d1633f5c74f5' },
  { value: '100', label: 'SHA1', example: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' },
  { value: '1400', label: 'SHA256', example: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' },
  { value: '1700', label: 'SHA512', example: 'b109f3bbbc244eb82441917ed06d618b9008dd09c7f1d16c0daade694e6a6c7d' },
  { value: '1800', label: 'bcrypt', example: '$2y$12$...' },
  { value: '22000', label: 'WPA/WPA2', example: '*hccapx file*' },
];

const attackModes = [
  { value: '0', label: 'Straight (Dictionary)' },
  { value: '3', label: 'Brute-force (Mask)' },
  { value: '6', label: 'Hybrid Wordlist + Mask' },
  { value: '7', label: 'Hybrid Mask + Wordlist' },
];

const HashcatBuilder = () => {
  const [hashType, setHashType] = useState('0');
  const [attackMode, setAttackMode] = useState('0');
  const [hashFile, setHashFile] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [mask, setMask] = useState('');
  const [extra, setExtra] = useState('');

  const buildCommand = () => {
    let cmd = `hashcat -m ${hashType} -a ${attackMode}`;
    if (hashFile) cmd += ` ${hashFile}`;
    if (wordlist) cmd += ` ${wordlist}`;
    if (mask && (attackMode === '3' || attackMode === '6' || attackMode === '7')) cmd += ` ${mask}`;
    if (extra) cmd += ` ${extra}`;
    return cmd;
  };

  const handleCopy = async () => {
    try {
      await copyToClipboard(buildCommand());
      toast.success('Command copied to clipboard!', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    } catch {
      toast.error('Failed to copy command', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaKey className="icon" />
        <h2>Hashcat Command Builder</h2>
        <p>Password hash cracking tool</p>
      </div>
      <div className="form-group">
        <label>Hash Type <FaInfoCircle title="Choose the hash algorithm to crack" /></label>
        <select className="select-input" value={hashType} onChange={e => setHashType(e.target.value)}>
          {hashTypes.map(ht => (
            <option key={ht.value} value={ht.value}>{ht.label}</option>
          ))}
        </select>
        <small>Example: {hashTypes.find(ht => ht.value === hashType)?.example}</small>
      </div>
      <div className="form-group">
        <label>Attack Mode <FaInfoCircle title="Choose the attack type" /></label>
        <select className="select-input" value={attackMode} onChange={e => setAttackMode(e.target.value)}>
          {attackModes.map(am => (
            <option key={am.value} value={am.value}>{am.label}</option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label>Hash File</label>
        <input className="text-input" value={hashFile} onChange={e => setHashFile(e.target.value)} placeholder="hashes.txt" />
      </div>
      <div className="form-group">
        <label>Wordlist (for dictionary/hybrid)</label>
        <input className="text-input" value={wordlist} onChange={e => setWordlist(e.target.value)} placeholder="rockyou.txt" />
      </div>
      {(attackMode === '3' || attackMode === '6' || attackMode === '7') && (
        <div className="form-group">
          <label>Mask (for brute-force/hybrid)</label>
          <input className="text-input" value={mask} onChange={e => setMask(e.target.value)} placeholder="?a?a?a?a?a?a" />
        </div>
      )}
      <div className="form-group">
        <label>Extra Options</label>
        <input className="text-input" value={extra} onChange={e => setExtra(e.target.value)} placeholder="--force --status" />
      </div>
      <div className="command-preview">
        <div className="preview-header">
          <span>Preview</span>
          <button className="copy-button" onClick={handleCopy}><FaCopy /> Copy</button>
        </div>
        <code>{buildCommand()}</code>
      </div>
      <div className="info-tip">
        <FaInfoCircle className="icon" />
        <p>Hashcat is a powerful password recovery tool. Always have permission before testing passwords!</p>
      </div>
    </div>
  );
};

export default HashcatBuilder;
