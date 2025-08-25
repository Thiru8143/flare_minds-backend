// backend/middleware/auth.js
const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
  try {
    const authHeader = req.headers['authorization']; // safer than req.header()
    if (!authHeader) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Expected format: "Bearer <token>"
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

    if (!token) {
      return res.status(401).json({ message: 'Token format invalid' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach decoded payload (like id, email) to request
    req.user = decoded;

    next();
  } catch (err) {
    console.error("JWT Error:", err.message);
    return res.status(401).json({ message: 'Token is not valid' });
  }
};
