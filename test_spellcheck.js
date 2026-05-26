// Test script to verify spell checking works
const fs = require('fs');

// Read the app.js file to get the THREAT_PATTERNS and analyzeMessage function
const appJsContent = fs.readFileSync('app.js', 'utf8');

// Extract the THREAT_PATTERNS object
const THREAT_PATTERNS_START = appJsContent.indexOf('const THREAT_PATTERNS = {');
const THREAT_PATTERNS_END = appJsContent.indexOf('};', THREAT_PATTERNS_START) + 2;
const THREAT_PATTERNS_TEXT = appJsContent.substring(THREAT_PATTERNS_START, THREAT_PATTERNS_END);

// Extract the analyzeMessage function
const ANALYZE_MESSAGE_START = appJsContent.indexOf('function analyzeMessage(message, messageType) {');
const ANALYZE_MESSAGE_END = appJsContent.indexOf('}', appJsContent.lastIndexOf('function analyzeMessage') ) + 1;
const ANALYZE_MESSAGE_TEXT = appJsContent.substring(ANALYZE_MESSAGE_START, ANALYZE_MESSAGE_END);

// Create a test script that includes the THREAT_PATTERNS and analyzeMessage function
const testScript = `
${THREAT_PATTERNS_TEXT}

const TOXICITY_DICT = {
  extreme: {
    words: ['kill', 'murder', 'die', 'death', 'rape', 'molest', 'abuse physically', 'execute', 'assassinate', 'lynch', 'beastiality'],
    score: 95
  },
  severe: {
    words: ['hate', 'slur', 'racist', 'casteist', 'sexist', 'traitor', 'scum', 'filth', 'disgusting', 'disgrace', 'shame on you', 'pathetic', 'worthless', 'loser', 'deserve to die', 'go die', 'drop dead'],
    score: 80
  },
  high: {
    words: ['abuse', 'harass', 'threaten', 'intimidate', 'bully', 'humiliate', 'insult', 'stupid', 'idiot', 'moron', 'dumb', 'incompetent', 'liar', 'fraud', 'scam', 'cheat', 'con artist', 'blackmail', 'defame', 'threat', 'threaten', 'will be frozen', 'will be blocked', 'will be suspended', 'will be closed', 'will be cancelled', 'or else', 'otherwise', 'police will', 'court case', 'lawsuit', 'arrest', 'jail', ' imprisonment', 'legal action', 'sue you', 'complaint', 'fir', 'frozen', 'freeze', 'blocked', 'suspended', 'closed account', 'blocked account', 'locked'],
    score: 65
  },
  moderate: {
    words: ['annoying', 'frustrating', 'irritating', 'ridiculous', 'pathetic', 'awful', 'terrible', 'horrible', 'spam', 'scam', 'suspicious', 'fake', 'deceptive', 'misleading', 'manipulative', 'tricky', 'dishonest', 'unethical', 'immediately', 'urgent', 'act now', 'last chance', 'final warning', 'deadline', 'expire', 'expired', 'urgent action', 'limited time', 'time limit'],
    score: 45
  },
  mild: {
    words: ['fake', 'spam', 'misleading', 'suspicious', 'odd', 'strange', 'unusual', 'concerning', 'alarming', 'worrying'],
    score: 25
  }
};

function analyzeMessage(message, messageType) {
  ${ANALYZE_MESSAGE_TEXT.substring(ANALYZE_MESSAGE_TEXT.indexOf('{') + 1, ANALYZE_MESSAGE_TEXT.lastIndexOf('}'))}
}

// Test cases
console.log('Testing spell correction for "bnk" -> "bank"...');

const test1 = 'give me your bank details';
const test2 = 'give me your bnk details';

console.log('\\nTest 1: "' + test1 + '"');
const result1 = analyzeMessage(test1, 'email');
console.log('Risk level:', result1.riskLevel);
console.log('Risk percent:', result1.riskPercent);
console.log('Threats detected:', result1.threats);

console.log('\\nTest 2: "' + test2 + '"');
const result2 = analyzeMessage(test2, 'email');
console.log('Risk level:', result2.riskLevel);
console.log('Risk percent:', result2.riskPercent);
console.log('Threats detected:', result2.threats);

console.log('\\nComparison:');
console.log('Both tests should show similar risk levels and detect financialTheft threat.');
console.log('Test 1 risk percent:', result1.riskPercent);
console.log('Test 2 risk percent:', result2.riskPercent);
console.log('Difference:', Math.abs(result1.riskPercent - result2.riskPercent));
`;

fs.writeFileSync('test_spellcheck.js', testScript);
console.log('Test script created.');

// Note: We can't actually run Node.js in this environment, but we've created the test script
`; }