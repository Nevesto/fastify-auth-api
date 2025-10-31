import { prisma } from '../lib/prisma';

export function findUserByEmail(email: string) {
  return prisma.user.findUnique({
    where: { email },
  });
}

export function findUserById(id: string) {
  return prisma.user.findUnique({
    where: { id },
  });
}

export function createUser(email: string, passwordHash: string) {
  return prisma.user.create({
    data: {
      email,
      password: passwordHash,
    },
  });
}