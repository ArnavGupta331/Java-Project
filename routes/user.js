const express = require('express');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const db = require('../config/database');

// Middleware to check authentication
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// GET /api/user/profile - Get user profile
router.get('/profile', requireAuth, (req, res) => {
  db.get(
    'SELECT id, email, name, created_at FROM users WHERE id = ?',
    [req.session.userId],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ user });
    }
  );
});

// PUT /api/user/profile - Update user profile
router.put('/profile', requireAuth, [
  body('name').optional().trim().isLength({ max: 100 }).withMessage('Name too long'),
  body('email').optional().isEmail().normalizeEmail().withMessage('Valid email required')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email } = req.body;
  
  if (!name && !email) {
    return res.status(400).json({ error: 'At least one field required' });
  }

  const updates = [];
  const values = [];
  const now = new Date().toISOString();

  if (name) {
    updates.push('name = ?');
    values.push(name);
  }
  
  if (email) {
    // Check if email is already taken by another user
    db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.session.userId], (err, existingUser) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (existingUser) {
        return res.status(409).json({ error: 'Email already taken' });
      }

      updates.push('email = ?');
      values.push(email);
      
      updateUserProfile();
    });
  } else {
    updateUserProfile();
  }

  function updateUserProfile() {
    updates.push('updated_at = ?');
    values.push(now);
    values.push(req.session.userId);

    db.run(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values,
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update profile' });
        }

        if (email) {
          req.session.userEmail = email;
        }
        if (name) {
          req.session.userName = name;
        }

        res.json({ message: 'Profile updated successfully' });
      }
    );
  }
});

// POST /api/user/change-password - Change password
router.post('/change-password', requireAuth, [
  body('currentPassword').notEmpty().withMessage('Current password required'),
  body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { currentPassword, newPassword } = req.body;

  db.get('SELECT password_hash FROM users WHERE id = ?', [req.session.userId], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    try {
      const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
      
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      const saltRounds = 12;
      const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

      db.run(
        'UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?',
        [newPasswordHash, new Date().toISOString(), req.session.userId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to change password' });
          }

          res.json({ message: 'Password changed successfully' });
        }
      );
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  });
});

// DELETE /api/user/account - Delete user account
router.delete('/account', requireAuth, [
  body('password').notEmpty().withMessage('Password required to delete account')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { password } = req.body;

  db.get('SELECT password_hash FROM users WHERE id = ?', [req.session.userId], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    try {
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      
      if (!isValidPassword) {
        return res.status(400).json({ error: 'Password is incorrect' });
      }

      // Delete user and related data
      db.serialize(() => {
        db.run('DELETE FROM validations WHERE user_id = ?', [req.session.userId]);
        db.run('DELETE FROM sessions WHERE user_id = ?', [req.session.userId]);
        db.run('DELETE FROM users WHERE id = ?', [req.session.userId], function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to delete account' });
          }

          req.session.destroy(() => {
            res.clearCookie('connect.sid');
            res.json({ message: 'Account deleted successfully' });
          });
        });
      });
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  });
});

module.exports = router;
