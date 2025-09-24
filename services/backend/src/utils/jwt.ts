import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const generateToken = (userId: string) => {
  return jwt.sign(
    { id: userId }, 
    JWT_SECRET, 
    { expiresIn: '30m' }
  );
};

const verifyToken = (token: string) => {
  return jwt.verify(token, JWT_SECRET);
};

export default {
  generateToken,
  verifyToken
}