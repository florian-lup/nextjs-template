import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import { headers } from 'next/headers';

import './globals.css';
import { ThemeProvider } from '@/components/theme-provider';

// Configure the Geist Sans font with variable support
const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

// Configure the Geist Mono font with variable support
const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

// Viewport configuration for better mobile experience
export const viewport = {
  maximumScale: 1, // Disable auto-zoom on mobile Safari
};

// SEO metadata configuration with relevant keywords
export const metadata: Metadata = {
  metadataBase: new URL(
    process.env['NEXT_PUBLIC_SITE_URL'] ?? 'http://localhost:3000',
  ),
  title: 'Next.js Starter Kit',
  description: 'A starter template for your Next.js project',
  keywords: [
    'template',
    'scaffolding',
    'next.js',
    'react',
    'tailwind',
    'shadcn',
    'ui',
    'components',
    'design',
    'system',
    'framework',
  ],
};

/**
 * Root layout component that wraps all pages
 * Configures theme support, fonts, and CSP nonce
 */
export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Get CSP nonce from middleware headers for secure script/style loading
  const nonce = (await headers()).get('x-nonce') ?? '';

  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
          nonce={nonce}
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
