import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import GitHub from 'next-auth/providers/github';
 
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

async function getUserByGithubId(githubId: number): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE github_id = ${githubId}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user by GitHub ID:', error);
    throw new Error('Failed to fetch user by GitHub ID.');
  }
}

const createGithubUser = async ({ name, email, githubId }: {
  name: string,
  email: string,
  githubId: number
}) => {
  try {
    await sql`
      INSERT INTO users (name, email, github_id) 
      VALUES (${name}, ${email}, ${githubId})
      ON CONFLICT (github_id) 
      DO NOTHING
    `
  } catch (error) {
    console.error('Error creating user:', error);
    throw new Error('Failed to create user');
  }
};

// run signIn action on login page / logout - logout button
export const { auth, signIn, signOut, handlers} = NextAuth({
  ...authConfig,
  callbacks: {
    ...authConfig.callbacks,
    async signIn({ user, account }) {
      if (account?.provider === 'github') {
        const githubId = Number(account.providerAccountId);
        const existingUser = await getUserByGithubId(githubId);
        if (!existingUser) {
          await createGithubUser({ email: user.email!, name: user.name!, githubId });
        }
      }
      return true; // Allow sign-in
    },
  },
  providers: [GitHub, Credentials({
    async authorize(credentials) {
      const parsedCredentials = z
        .object({ email: z.string().email(), password: z.string().min(6) })
        .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password!);
 
          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;

    },
  })],
});