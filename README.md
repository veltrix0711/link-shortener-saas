# Link Shortener SaaS

A simple URL shortening service built with Node.js, Express, and SQLite.

## Features

- Create shortened URLs from long ones
- Track click counts for each shortened URL
- Dashboard to view all shortened URLs
- Pagination support for the dashboard
- Proper error handling
- Support for both in-memory and file-based SQLite database

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn

## Installation

1. Clone this repository
2. Install dependencies:
```
npm install
```

## Running the Application

### Development Mode

```
npm run dev
```

### Production Mode

```
npm start
```

By default, the server starts on port 3000, but you can change this by setting the PORT environment variable.

## API Endpoints

- `GET /`: API information
- `POST /shorten`: Create a new shortened URL
  - Request body: `{ "url": "https://example.com/very/long/url" }`
  - Response: `{ "success": true, "short_url": "http://hostname/abc123", "original_url": "https://example.com/very/long/url", "id": "abc123" }`

- `GET /:id`: Redirect to the original URL
  - Example: `GET /abc123` redirects to the original URL

- `GET /dashboard`: Get all shortened URLs with stats
  - Query parameters:
    - `page` (optional, default: 1): Page number
    - `limit` (optional, default: 10): Links per page
  - Response: Paginated list of all links with stats

## Deployment to Railway

Railway offers seamless deployment with automatic HTTPS and custom domains.

### Quick Deploy to Railway

1. **One-Click Deploy**: 
   - Click this button: [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template)
   - Or manually follow the steps below

2. **Manual Deployment**:
   - Create a Railway account at [railway.app](https://railway.app)
   - Install Railway CLI: `npm install -g @railway/cli`
   - Login: `railway login`
   - Initialize: `railway init`
   - Deploy: `railway up`

3. **GitHub Integration** (Recommended):
   - Push your code to GitHub
   - Connect your GitHub repository in Railway dashboard
   - Railway will automatically deploy on every push

### Environment Variables for Railway

Set these in your Railway dashboard:

- `NODE_ENV`: `production`
- `DB_PATH`: `./data/links.db` (for file-based persistence)
- `RAILWAY_STATIC_URL`: (automatically set by Railway)

### Upgrading to File-based SQLite for Persistence

For persistent data storage on Railway:

1. Create a data directory:
```bash
mkdir data
```

2. Set environment variable in Railway dashboard:
   - `DB_PATH`: `./data/links.db`

3. Railway automatically provides persistent storage for your application.

### Custom Domain Setup

1. Go to your Railway project dashboard
2. Navigate to "Settings" → "Domains"
3. Add your custom domain
4. Configure DNS records as instructed by Railway

## Deployment to Render (Alternative)

### Setup

1. Create a new Web Service on Render
2. Connect your GitHub repository
3. Configure the following settings:
   - Build Command: `npm install`
   - Start Command: `node index.js`
   - Environment Variables:
     - `PORT`: `10000` (or any port provided by Render)
     - `DB_PATH`: `./data/links.db` (for persistence)

### Upgrading to File-based SQLite for Persistence

To use a file-based SQLite database:

1. Create a data directory in your project:
```
mkdir data
```

2. Set the DB_PATH environment variable:
```
DB_PATH=./data/links.db npm start
```

3. For Render deployment, add the DB_PATH environment variable in the dashboard.

4. Make sure the data directory is included in your Git repository if you want the database file to be deployed with your code.

### Important Notes for Production

- The SQLite database file should be in a directory that has write permissions.
- For higher traffic, consider upgrading to a more robust database like PostgreSQL.
- Consider adding authentication for the dashboard in a production environment.
