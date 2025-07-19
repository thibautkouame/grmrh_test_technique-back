const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'JWT';

// le token est valide pendant 1 heure
const EXPIRES_IN = '1h';

function generateToken(payload) {
    const token = jwt.sign(payload, SECRET, { expiresIn: EXPIRES_IN });

    // Log pour tracer la génération du token
    const decoded = jwt.decode(token);
    console.log(`Token généré pour ${payload.email}:`);
    console.log(`- Expiration configurée: ${EXPIRES_IN}`);
    console.log(`- Expiration réelle: ${new Date(decoded.exp * 1000).toISOString()}`);
    console.log(`- Payload:`, payload);

    return token;
}

module.exports = { generateToken, SECRET };