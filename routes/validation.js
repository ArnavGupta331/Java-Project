const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const db = require('../config/database');

// Validation logic (moved from frontend)
const suspiciousPhrases = [
  'you won\\s*\\$?\\d+',
  'miracle cure',
  'shocking secret',
  'what they wont tell you',
  "what they won't tell you",
  'click here',
  "share before it's deleted",
  'share before its deleted',
  'banned video',
  'cures cancer',
  'flat earth',
  'wake up sheeple',
  'illuminati',
  'qanon',
  'exposed!!!',
  'not a joke',
  'guaranteed',
];

const credibleHints = [
  'according to',
  'reported by',
  'study finds',
  'researchers',
  'data shows',
  'official statement',
  'confirmed by',
  'peer-reviewed',
];

const questionableTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
const typoBrandFragments = ['cnn-', 'bbc-', 'foxnwes', 'nytimesz', 'reutersz'];

function analyzeText(text) {
  const t = (text || '').replace(/\s+/g, ' ').trim();
  if (!t) return { score: 0, reasons: ['Empty input'] };

  let score = 0;
  const reasons = [];

  // Excess punctuation
  const exclamations = (t.match(/!/g) || []).length;
  if (exclamations >= 3) { score += 1.5; reasons.push('Many exclamation marks'); }

  const emojis = (t.match(/[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}]/gu) || []).length;
  if (emojis >= 3) { score += 1; reasons.push('Many emojis'); }

  const words = t.split(' ');
  const allCapsWords = words.filter(w => w.length > 3 && /^[A-Z]{4,}$/.test(w));
  if (allCapsWords.length >= 3) { score += 1; reasons.push('Many ALL-CAPS words'); }

  // Suspicious phrases
  const tLower = t.toLowerCase();
  const phraseHits = suspiciousPhrases.reduce((acc, p) => 
    acc + (new RegExp(p, 'i').test(tLower) ? 1 : 0), 0);
  if (phraseHits > 0) { score += phraseHits * 1.2; reasons.push('Suspicious phrasing'); }

  // Credible hints reduce suspicion
  const credibilityHits = credibleHints.reduce((acc, p) => 
    acc + (tLower.includes(p) ? 1 : 0), 0);
  if (credibilityHits > 0) { 
    score -= credibilityHits * 0.6; 
    reasons.push('Contains neutral/credible phrasing'); 
  }

  // Length analysis
  if (t.length < 40) { score += 0.8; reasons.push('Very short claim'); }
  if (t.length > 1200) { score -= 0.3; reasons.push('Longer explanatory text'); }

  // Money claims
  const moneyClaims = (tLower.match(/\$\s?\d{3,}/g) || []).length;
  if (moneyClaims > 0) { score += 0.6; reasons.push('Money/lottery claim'); }

  // Sensational punctuation
  if (/\?\!|\!\?/g.test(t)) { score += 0.6; reasons.push('Sensational punctuation'); }

  return { score, reasons };
}

function analyzeDomain(domain) {
  if (!domain) return { score: 0, reasons: [] };
  let score = 0;
  const reasons = [];

  const tld = domain.slice(domain.lastIndexOf('.'));
  if (questionableTlds.includes(tld)) {
    score += 1.2;
    reasons.push(`Questionable TLD (${tld})`);
  }

  if (/\d{2,}/.test(domain)) { score += 0.6; reasons.push('Numbers in domain'); }

  if (typoBrandFragments.some(f => domain.includes(f))) {
    score += 1.2; reasons.push('Possible typo-squatting'); 
  }

  const hyphens = (domain.match(/-/g) || []).length;
  if (hyphens >= 2) { score += 0.6; reasons.push('Many hyphens in domain'); }

  return { score, reasons };
}

function getDomainFromUrl(url) {
  if (!url) return '';
  try {
    const normalized = url.includes('://') ? url : `https://${url}`;
    const u = new URL(normalized);
    return u.hostname.toLowerCase();
  } catch (_) {
    return '';
  }
}

function classify(score) {
  if (score >= 2.5) return { label: 'Likely Fake News', tone: 'bad' };
  if (score >= 1.2) return { label: 'Suspicious – Might be Fake', tone: 'warn' };
  return { label: 'Likely Real News', tone: 'ok' };
}

// POST /api/validation/analyze
router.post('/analyze', [
  body('text').isLength({ min: 1, max: 5000 }).withMessage('Text must be between 1-5000 characters'),
  body('source').optional().isLength({ max: 253 }).withMessage('Source URL too long')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { text, source } = req.body;
  const textRes = analyzeText(text);
  const domain = getDomainFromUrl(source);
  const domainRes = analyzeDomain(domain);

  const totalScore = Math.max(0, textRes.score + domainRes.score);
  const reasons = [...textRes.reasons, ...domainRes.reasons];
  const classification = classify(totalScore);

  // Save validation to database if user is logged in
  if (req.session.userId) {
    const reasonsJson = JSON.stringify(reasons);
    db.run(
      'INSERT INTO validations (user_id, text, source_url, score, classification, reasons) VALUES (?, ?, ?, ?, ?, ?)',
      [req.session.userId, text, source || null, totalScore, classification.label, reasonsJson],
      function(err) {
        if (err) {
          console.error('Error saving validation:', err);
        }
      }
    );
  }

  res.json({
    score: totalScore,
    classification,
    reasons,
    confidence: Math.min(95, Math.max(5, Math.round(Math.abs(totalScore - 2.5) * 20)))
  });
});

// GET /api/validation/history - Get user's validation history
router.get('/history', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  db.all(
    'SELECT * FROM validations WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
    [req.session.userId, limit, offset],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        validations: rows,
        page,
        limit,
        hasMore: rows.length === limit
      });
    }
  );
});

module.exports = router;
