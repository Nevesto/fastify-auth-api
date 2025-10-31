import { prisma } from '../lib/prisma';
import { env } from '../lib/env';
import { getExpiryDate } from '../utils/date';

export function createRefreshToken(data: {
  userId: string;
  token: string; // HASH
  deviceInfo?: string;
}) {
  const expiresAt = getExpiryDate(env.REFRESH_TOKEN_EXPIRY);

  return prisma.refreshToken.create({
    data: {
      userId: data.userId,
      token: data.token,
      deviceInfo: data.deviceInfo,
      expiresAt,
    },
  });
}

export function findRefreshTokenByToken(token: string) {
  return prisma.refreshToken.findUnique({
    where: { token },
  });
}

export function deleteRefreshToken(id: string) {
  return prisma.refreshToken.delete({
    where: { id },
  });
}