import { useState } from "react";
import { motion } from "framer-motion";
import { FaCopy, FaCheck, FaTimes } from "react-icons/fa";
import { toast } from "react-toastify";
import "./UtilityTools.css";

const RegexTester = () => {
  const [pattern, setPattern] = useState("");
  const [testString, setTestString] = useState("");
  const [flags, setFlags] = useState("g");
  const [matches, setMatches] = useState([]);
  const [isValid, setIsValid] = useState(true);
  const [error, setError] = useState("");

  const testRegex = (pat, str, flg) => {
    try {
      const regex = new RegExp(pat, flg);
      const foundMatches = [];

      if (flg.includes("g")) {
        let match;
        while ((match = regex.exec(str)) !== null) {
          foundMatches.push({
            text: match[0],
            index: match.index,
            groups: match.slice(1),
          });
        }
      } else {
        const match = regex.exec(str);
        if (match) {
          foundMatches.push({
            text: match[0],
            index: match.index,
            groups: match.slice(1),
          });
        }
      }

      setMatches(foundMatches);
      setIsValid(true);
      setError("");
    } catch (err) {
      setIsValid(false);
      setError(err.message);
      setMatches([]);
    }
  };

  const handlePatternChange = (e) => {
    const pat = e.target.value;
    setPattern(pat);
    if (testString) {
      testRegex(pat, testString, flags);
    } else {
      setMatches([]);
    }
  };

  const handleTestStringChange = (e) => {
    const str = e.target.value;
    setTestString(str);
    if (pattern) {
      testRegex(pattern, str, flags);
    } else {
      setMatches([]);
    }
  };

  const toggleFlag = (flag) => {
    let newFlags = flags;
    if (flags.includes(flag)) {
      newFlags = flags.replace(flag, "");
    } else {
      newFlags += flag;
    }
    setFlags(newFlags);
    if (pattern && testString) {
      testRegex(pattern, testString, newFlags);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard!");
  };

  return (
    <div className="utility-tool">
      <div className="regex-config">
        <div className="config-input full-width">
          <label>Regex Pattern</label>
          <input
            type="text"
            value={pattern}
            onChange={handlePatternChange}
            placeholder="Enter regex pattern (e.g., \d+\.\d+\.\d+\.\d+)"
            className="regex-input"
          />
          {!isValid && (
            <div className="error-message">
              <FaTimes /> {error}
            </div>
          )}
        </div>

        <div className="flags-section">
          <label>Flags</label>
          <div className="flags">
            {["g", "i", "m", "s"].map((flag) => (
              <button
                key={flag}
                className={`flag-btn ${flags.includes(flag) ? "active" : ""}`}
                onClick={() => toggleFlag(flag)}
                title={
                  flag === "g"
                    ? "Global - find all matches"
                    : flag === "i"
                      ? "Case insensitive"
                      : flag === "m"
                        ? "Multiline"
                        : "Dotall - . matches newlines"
                }
              >
                {flag.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="regex-test">
        <div className="utility-section">
          <label>Test String</label>
          <textarea
            value={testString}
            onChange={handleTestStringChange}
            placeholder="Enter text to test..."
            className="utility-textarea"
            rows={6}
          />
        </div>

        {matches.length > 0 && (
          <div className="utility-section">
            <label>Matches Found ({matches.length})</label>
            <div className="matches-list">
              {matches.map((match, idx) => (
                <motion.div
                  key={idx}
                  className="match-item"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                >
                  <div className="match-text">
                    <strong>{match.text}</strong>
                    <span className="match-index"> @ index {match.index}</span>
                  </div>
                  {match.groups.length > 0 && (
                    <div className="match-groups">
                      {match.groups.map((group, gIdx) => (
                        <span key={gIdx} className="group">
                          Group {gIdx + 1}: {group || "(empty)"}
                        </span>
                      ))}
                    </div>
                  )}
                  <button
                    onClick={() => copyToClipboard(match.text)}
                    className="copy-match-btn"
                  >
                    <FaCopy />
                  </button>
                </motion.div>
              ))}
            </div>
          </div>
        )}

        {isValid && testString && pattern && matches.length === 0 && (
          <div className="no-matches">
            <FaTimes /> No matches found
          </div>
        )}
      </div>

      <div className="utility-tips">
        <h4>Common Patterns:</h4>
        <ul>
          <li>
            <code>{"\\d+"}</code> - One or more digits
          </li>
          <li>
            <code>{"\\w+"}</code> - One or more word characters
          </li>
          <li>
            <code>{"[a-zA-Z]+"}</code> - One or more letters
          </li>
          <li>
            <code>{"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"}</code> - IP
            address
          </li>
          <li>
            <code>{"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"}</code> -
            Email
          </li>
          <li>
            <code>{"password=([^&]+)"}</code> - Capture parameter value
          </li>
        </ul>
      </div>
    </div>
  );
};

export default RegexTester;
