const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

// Secret keys from environment variables
const JWT_SECRET = process.env.JWT_SECRET;
let ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET;

// Check if ENCRYPTION_SECRET is properly loaded
if (!ENCRYPTION_SECRET) {
  console.error('ENCRYPTION_SECRET is missing. Please check your .env file.');
  process.exit(1);
}

// Log the ENCRYPTION_SECRET for debugging
console.log('ENCRYPTION_SECRET:', ENCRYPTION_SECRET);

// Ensure the ENCRYPTION_SECRET is 32 bytes (pad if necessary)
ENCRYPTION_SECRET = ENCRYPTION_SECRET.padEnd(32, '0');  // Pad to 32 bytes for AES-256-CBC
console.log('Padded ENCRYPTION_SECRET:', ENCRYPTION_SECRET);

// Function to encrypt the payload using AES encryption
const encrypt = (payload) => {
  try {
    const cipher = crypto.createCipheriv(
      'aes-256-cbc', 
      Buffer.from(ENCRYPTION_SECRET, 'utf8'), 
      Buffer.from(ENCRYPTION_SECRET.substring(0, 16), 'utf8')
    );
    
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return encrypted;
  } catch (error) {
    console.error('Error during encryption:', error);
  }
};

// Function to decrypt the encrypted payload
const decrypt = (token) => {
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc', 
      Buffer.from(ENCRYPTION_SECRET, 'utf8'), 
      Buffer.from(ENCRYPTION_SECRET.substring(0, 16), 'utf8')
    );
    
    let decrypted = decipher.update(token, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Error during decryption:', error);
  }
};

// Function to create a JWT token
const generateJWT = (payload) => {
  const encryptedPayload = encrypt(payload);
  const token = jwt.sign({ data: encryptedPayload }, JWT_SECRET, { expiresIn: '1h' });
  return token;
};

// Function to verify the JWT token and decrypt the payload
const verifyJWT = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const decryptedPayload = decrypt(decoded.data);
    return decryptedPayload;
  } catch (err) {
    console.error('JWT verification failed:', err);
    return null;
  }
};

// Testing the process
const testEncryptionDecryption = () => {
  const samplePayload = { username: 'john_doe', email: 'john@example.com' };

  console.log('Original Payload:', samplePayload);

  // Generate the JWT
  const token = generateJWT(samplePayload);
  console.log('Generated JWT Token:', token);

  // Verify the JWT and decrypt the payload
  const decryptedData = verifyJWT(token);
  console.log('Decrypted Data:', decryptedData);
};

// Run the test
testEncryptionDecryption();