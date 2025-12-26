import { ImageResponse } from 'next/og'

// Image metadata
export const alt = 'SUBPASS - Subdomain Reconnaissance System'
export const size = {
  width: 1200,
  height: 630,
}
export const contentType = 'image/png'

// Image generation
export default async function OgImage() {
  return new ImageResponse(
    (
      <div
        style={{
          height: '100%',
          width: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%)',
          position: 'relative',
        }}
      >
        {/* Cyber grid background */}
        <div
          style={{
            position: 'absolute',
            width: '100%',
            height: '100%',
            opacity: 0.1,
            backgroundImage: 'linear-gradient(#00f0ff 1px, transparent 1px), linear-gradient(90deg, #00f0ff 1px, transparent 1px)',
            backgroundSize: '50px 50px',
          }}
        />

        {/* Content */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 20,
          }}
        >
          {/* Logo */}
          <div
            style={{
              fontSize: 120,
              fontWeight: 900,
              letterSpacing: '0.1em',
              display: 'flex',
              gap: 10,
            }}
          >
            <span style={{ color: '#00f0ff', textShadow: '0 0 20px rgba(0, 240, 255, 0.5)' }}>SUB</span>
            <span style={{ color: '#ff00a8', textShadow: '0 0 20px rgba(255, 0, 168, 0.5)' }}>PASS</span>
          </div>

          {/* Subtitle */}
          <div
            style={{
              fontSize: 32,
              color: '#8888a0',
              letterSpacing: '0.2em',
              textTransform: 'uppercase',
            }}
          >
            Subdomain Reconnaissance System
          </div>

          {/* Features */}
          <div
            style={{
              display: 'flex',
              gap: 20,
              marginTop: 30,
              fontSize: 20,
              color: '#555566',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#39ff14' }}>●</span>
              <span>19 OSINT Sources</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#39ff14' }}>●</span>
              <span>Parallel Scanning</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#39ff14' }}>●</span>
              <span>Real-time Verification</span>
            </div>
          </div>
        </div>
      </div>
    ),
    {
      ...size,
    }
  )
}
