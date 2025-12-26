import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL('https://subpass.com'),
  title: {
    default: "SUBPASS - Advanced Subdomain Enumeration Tool | 19 OSINT Sources",
    template: "%s | SUBPASS"
  },
  description: "Advanced subdomain enumeration using 19 OSINT data sources including crt.sh, AlienVault, CommonCrawl, and more. Professional reconnaissance tool for security researchers and penetration testers.",
  keywords: [
    "subdomain enumeration",
    "subdomain scanner",
    "OSINT tool",
    "security reconnaissance",
    "penetration testing",
    "subdomain discovery",
    "cybersecurity tool",
    "bug bounty",
    "information gathering",
    "DNS enumeration",
    "crt.sh",
    "security research",
    "ethical hacking",
    "recon tool",
    "web security"
  ],
  authors: [{ name: "SUBPASS", url: "https://subpass.com" }],
  creator: "SUBPASS",
  publisher: "SUBPASS",
  themeColor: "#00f0ff",
  applicationName: "SUBPASS",
  generator: "Next.js",
  referrer: "origin-when-cross-origin",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://subpass.com",
    siteName: "SUBPASS",
    title: "SUBPASS - Advanced Subdomain Enumeration Tool",
    description: "Advanced subdomain enumeration using 19 OSINT data sources. Professional reconnaissance tool for security researchers and penetration testers.",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "SUBPASS - Subdomain Reconnaissance System",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "SUBPASS - Advanced Subdomain Enumeration Tool",
    description: "Advanced subdomain enumeration using 19 OSINT data sources. Professional reconnaissance tool for security researchers.",
    images: ["/og-image.png"],
    creator: "@subpass",
  },
  viewport: {
    width: "device-width",
    initialScale: 1,
    maximumScale: 5,
  },
  verification: {
    // Add verification codes when available
    // google: "verification_code",
    // yandex: "verification_code",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "SUBPASS",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web",
    "description": "Advanced subdomain enumeration using 19 OSINT data sources. Professional reconnaissance tool for security researchers and penetration testers.",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "featureList": [
      "19 OSINT Data Sources",
      "Parallel Scanning",
      "Real-time Status Verification",
      "DNS and HTTP/HTTPS Checks",
      "Smart Batching"
    ],
    "screenshot": "https://subpass.com/og-image.png",
    "aggregateRating": {
      "@type": "AggregateRating",
      "ratingValue": "5",
      "ratingCount": "1"
    }
  };

  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Orbitron:wght@400;500;600;700;800;900&display=swap"
          rel="stylesheet"
        />
        <link rel="canonical" href="https://subpass.com" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
