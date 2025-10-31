import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

export function hashPassword(password: string) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export function comparePassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}