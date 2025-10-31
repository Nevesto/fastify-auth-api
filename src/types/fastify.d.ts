import '@fastify/jwt';

declare module 'fastify' {
  // interface for FastifyInstance
  interface FastifyInstance {
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => Promise<void>;
  }
}

declare module '@fastify/jwt' {
  // Defines the shape of JWT payload and user object
  interface FastifyJWT {
    payload: { sub: string };
    user: {
      sub: string;
    };
  }
}