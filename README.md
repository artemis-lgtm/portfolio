# Artemis Portfolio

Live portfolio tracker with password protection.

## Features
- Real-time crypto prices via CoinGecko (free, no API key)
- Stock prices via Yahoo Finance (CORS proxy fallback)
- NFT floor prices via CoinGecko
- Add/edit/remove positions (stored in browser localStorage)
- PWA-ready: install as app on mobile
- AES-256-GCM client-side encryption (password gate)
- Dark theme, responsive design

## Usage
Visit the GitHub Pages URL and enter the password.

On mobile: tap Share > Add to Home Screen to install as an app.

## Rebuilding
To change the password:
```bash
node build.js "your-new-password"
git add index.html && git commit -m "update" && git push
```

## Data Sources
- **Crypto**: CoinGecko free API (no key, CORS-friendly)
- **Stocks**: Yahoo Finance via corsproxy.io
- **NFTs**: CoinGecko NFT endpoint
- All client-side, no backend required
