import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_ACCESS_SECRET: z.string().min(1),
  JWT_REFRESH_SECRET: z.string().min(1), // cookie
  ACCESS_TOKEN_EXPIRY: z.string().min(1),
  REFRESH_TOKEN_EXPIRY: z.string().min(1),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error(
    'Variáveis de ambiente inválidas:',
    parsedEnv.error.format(),
  );
  throw new Error('Variáveis de ambiente inválidas.');
}

export const env = parsedEnv.data;