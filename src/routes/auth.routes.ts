import { FastifyInstance } from 'fastify';
import {
  registerHandler,
  loginHandler,
  refreshHandler,
  logoutHandler,
  meHandler,
} from '../controllers/auth.controller';

export async function authRoutes(
  app: FastifyInstance,
  // options: any,
  done: () => void,
) {
  app.post('/register', registerHandler);
  app.post('/login', loginHandler);
  app.post('/refresh', refreshHandler);

  app.get('/me', { preHandler: [app.authenticate] }, meHandler);
  app.post('/logout', { preHandler: [app.authenticate] }, logoutHandler);
}