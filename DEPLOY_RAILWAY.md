# Railway Deployment Guide

## Quick Steps to Deploy on Railway

### Method 1: GitHub Integration (Recommended)

1. **Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit - Link Shortener SaaS"
   git branch -M main
   git remote add origin https://github.com/yourusername/link-shortener-saas.git
   git push -u origin main
   ```

2. **Deploy on Railway**:
   - Go to [railway.app](https://railway.app)
   - Sign up/Login with GitHub
   - Click "Deploy from GitHub repo"
   - Select your repository
   - Railway will automatically detect it's a Node.js app and deploy

3. **Configure Environment Variables** (Optional):
   - In Railway dashboard, go to Variables tab
   - Add: `DB_PATH` = `./data/links.db` (for persistence)
   - Add: `NODE_ENV` = `production`

### Method 2: Railway CLI

1. **Install Railway CLI**:
   ```bash
   npm install -g @railway/cli
   ```

2. **Login and Deploy**:
   ```bash
   railway login
   railway init
   railway up
   ```

### Method 3: One-Click Deploy

Use this button to deploy instantly:
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template)

## Post-Deployment

1. **Get your app URL**: Railway will provide a `.railway.app` domain
2. **Test the API**: 
   - `GET https://your-app.railway.app/` - API info
   - `POST https://your-app.railway.app/shorten` - Create short URLs
   - `GET https://your-app.railway.app/dashboard` - View dashboard

3. **Optional - Custom Domain**:
   - Go to Settings → Domains in Railway dashboard
   - Add your custom domain
   - Update DNS records as instructed

## Database Persistence

- **In-Memory** (default): Data resets on each deployment
- **File-Based**: Set `DB_PATH=./data/links.db` environment variable
- **PostgreSQL**: For production, consider Railway's PostgreSQL addon

## Monitoring

- View logs in Railway dashboard
- Monitor usage and performance
- Set up alerts for downtime

Your Link Shortener SaaS is now ready for Railway deployment! 🚀
