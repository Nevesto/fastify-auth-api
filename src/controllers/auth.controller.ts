import { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import crypto from 'node:crypto';
import {
  createUser,
  findUserByEmail,
  findUserById,
} from '../services/user.service';
import {
  createRefreshToken,
  deleteRefreshToken,
  findRefreshTokenByToken,
} from '../services/token.service';
import { comparePassword, hashPassword } from '../lib/password';
import { env } from '../lib/env';
import { CookieSerializeOptions } from '@fastify/cookie';
import { getExpiryDate } from '../utils/date';

const registerBodySchema = z.object({
  email: z.string().email('Email inválido'),
  password: z
    .string()
    .min(8, 'Senha deve ter pelo menos 8 caracteres'),
  confirmPassword: z.string(),
});

const loginBodySchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const cookieOptions: CookieSerializeOptions = {
  httpOnly: true,
  secure: env.NODE_ENV === 'production',
  sameSite: 'strict', // CSRF
  path: '/',
};

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function registerHandler(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const { email, password, confirmPassword } = registerBodySchema.parse(
      request.body,
    );

    if (password !== confirmPassword) {
      return reply.code(400).send({ message: 'Senhas não conferem' });
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return reply.code(409).send({ message: 'Email já cadastrado' });
    }

    const passwordHash = await hashPassword(password);
    const user = await createUser(email, passwordHash);

    const { password: _, ...userWithoutPassword } = user;
    return reply.code(201).send(userWithoutPassword);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.code(400).send({ message: 'Dados inválidos', errors: error.format() });
    }
    console.error(error);
    return reply.code(500).send({ message: 'Erro interno do servidor' });
  }
}

export async function loginHandler(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const { email, password } = loginBodySchema.parse(request.body);

    const user = await findUserByEmail(email);
    if (!user) {
      return reply.code(401).send({ message: 'Credenciais inválidas' });
    }

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return reply.code(401).send({ message: 'Credenciais inválidas' });
    }

    const accessToken = await reply.jwtSign(
      { sub: user.id }, // Payload
      { expiresIn: env.ACCESS_TOKEN_EXPIRY },
    );

    const opaqueRefreshToken = crypto.randomBytes(64).toString('hex');
    const hashedRefreshToken = hashToken(opaqueRefreshToken);

    const deviceInfo = request.headers['user-agent'] ?? 'unknown';

    await createRefreshToken({
      userId: user.id,
      token: hashedRefreshToken,
      deviceInfo,
    });

    reply.setCookie('refreshToken', opaqueRefreshToken, {
      ...cookieOptions,
      expires: getExpiryDate(env.REFRESH_TOKEN_EXPIRY),
    });

    return reply.code(200).send({ accessToken });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return reply.code(400).send({ message: 'Dados inválidos', errors: error.format() });
    }
    console.error(error);
    return reply.code(500).send({ message: 'Erro interno do servidor' });
  }
}

export async function refreshHandler(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const { refreshToken: opaqueTokenFromCookie } = request.cookies;

    if (!opaqueTokenFromCookie) {
      return reply.code(401).send({ message: 'Refresh token não encontrado' });
    }

    const hashedToken = hashToken(opaqueTokenFromCookie);
    const dbToken = await findRefreshTokenByToken(hashedToken);

    if (!dbToken || new Date() > new Date(dbToken.expiresAt)) {
      reply.clearCookie('refreshToken', cookieOptions);
      return reply.code(401).send({ message: 'Refresh token inválido ou expirado' });
    }

    const accessToken = await reply.jwtSign(
      { sub: dbToken.userId },
      { expiresIn: env.ACCESS_TOKEN_EXPIRY },
    );

    return reply.code(200).send({ accessToken });
  } catch (error) {
    console.error(error);
    return reply.code(500).send({ message: 'Erro interno do servidor' });
  }
}

export async function logoutHandler(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    const { refreshToken: opaqueTokenFromCookie } = request.cookies;

    if (opaqueTokenFromCookie) {
      const hashedToken = hashToken(opaqueTokenFromCookie);
      const dbToken = await findRefreshTokenByToken(hashedToken);

      if (dbToken) {
        await deleteRefreshToken(dbToken.id);
      }
    }

    reply.clearCookie('refreshToken', cookieOptions);

    return reply.code(204).send();
  } catch (error) {
    console.error(error);
    return reply.code(500).send({ message: 'Erro interno do servidor' });
  }
}

export async function meHandler(request: FastifyRequest, reply: FastifyReply) {
  const userId = request.user.sub;

  const user = await findUserById(userId);

  if (!user) {
    return reply.code(404).send({ message: 'Usuário não encontrado' });
  }

  const { password, ...userWithoutPassword } = user;
  return reply.code(200).send(userWithoutPassword);
}