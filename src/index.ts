import Fastify, { FastifyRequest, FastifyReply, FastifyPluginAsync } from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyCookie from '@fastify/cookie';
import { env } from './lib/env';
import { authRoutes } from './routes/auth.routes';

export const app = Fastify({
  logger: env.NODE_ENV === 'development',
});

app.register(fastifyJwt, {
  secret: env.JWT_ACCESS_SECRET,
  sign: {
    expiresIn: env.ACCESS_TOKEN_EXPIRY,
  },
  cookie: {
    cookieName: 'accessToken',
    signed: false,  
  },
});

app.register(fastifyCookie);

app.decorate(
  'authenticate',
  async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      await request.jwtVerify();
    } catch (err) {
      reply.code(401).send({ message: 'Autenticação necessária' });
    }
  },
);

app.get('/api/health', (_request, reply) => {
  return reply.send({ status: 'ok', timestamp: new Date().toISOString() });
});

app.register(authRoutes as FastifyPluginAsync, {
  prefix: '/api/auth',
});

const start = async () => {
  try {
    await app.listen({ port: 6666, host: '0.0.0.0' });
    app.log.info(`Servidor da API rodando em http://localhost:6666`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();