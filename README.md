# 🃏 Whispr Cards

Disposable digital business cards for privacy-conscious networking.

## Features

✅ **Create disposable contact cards** with auto-expiry  
✅ **Beautiful card display** with consistent layout  
✅ **QR code generation** for easy sharing  
✅ **vCard download** compatible with phones  
✅ **Custom expiry times** (1 hour to 1 month)  
✅ **Analytics dashboard** with usage statistics  
✅ **SQLite database** for data persistence  

## Tech Stack

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express
- **Database**: SQLite
- **Libraries**: QRCode, CORS

## API Endpoints

- `POST /api/cards` - Create new card
- `GET /api/cards/:id` - Get card by ID  
- `GET /qr/:id` - Generate QR code
- `GET /vcard/:id` - Download vCard
- `GET /api/analytics` - View statistics

## Contact Fields

- First Name, Last Name
- Title, Function, Company
- Address, Email, Phone
- Custom expiry time

## Privacy Features

- Auto-expiry after set time
- No personal data in analytics
- Disposable by design
- Access counting only

## Development

```bash
npm install
node server.js