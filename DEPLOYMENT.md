# Link Shortener SaaS - Deployment Guide

## Railway Deployment

### Required Environment Variables
Set these in your Railway project dashboard:

```bash
# Required for production security
JWT_SECRET=<generate-a-secure-random-string>
SESSION_SECRET=<generate-another-secure-random-string>

# Database (already set in railway.toml)
DB_PATH=./links.db
NODE_ENV=production
```

### Generate Secure Secrets
You can generate secure secrets using:
```bash
# Generate JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate SESSION_SECRET  
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Railway CLI Deployment
```bash
# Install Railway CLI (if not already installed)
npm install -g @railway/cli

# Login to Railway
railway login

# Link to your project (or create new)
railway link

# Set environment variables
railway variables set JWT_SECRET=<your-generated-jwt-secret>
railway variables set SESSION_SECRET=<your-generated-session-secret>

# Deploy
railway up
```

### Features Included in Deployment
✅ Complete user authentication system
✅ User registration and login
✅ JWT-based sessions
✅ Secure password hashing
✅ Custom aliases with validation
✅ Advanced click analytics
✅ Link expiration system
✅ Link management dashboard
✅ Responsive UI
✅ Persistent SQLite database

### Post-Deployment Testing
1. Test user registration
2. Test user login
3. Test link creation (authenticated vs anonymous)
4. Test dashboard functionality
5. Test link management features
6. Test analytics tracking

### Production Security Features
- Secure JWT tokens with configurable secrets
- Password hashing with bcryptjs (12 salt rounds)
- HTTPS-only cookies in production
- Session management with secure cookies
- Input validation and sanitization
- Protected routes with authentication middleware
