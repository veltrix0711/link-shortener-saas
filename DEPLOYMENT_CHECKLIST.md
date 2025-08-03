# Production Deployment Checklist

## Pre-Deployment
- [x] All 5 features implemented and tested locally
- [x] Authentication system working
- [x] Database persistence enabled  
- [x] All dependencies in package.json
- [x] Railway configuration ready
- [x] Fixed Railway URL handling for QR codes and links

## Railway Environment Variables
Set these in Railway dashboard > Variables:

```
JWT_SECRET=cec5871aec539230efec3a37cf2bd333397690255d21acdc16c085f038f0b82209636243e3e67fbaefd2a614a2bb4022be0f77ed0a5a0966ebcfd15425688cddfd52

SESSION_SECRET=3871e4feeb8050f7a2c969e8b8baebc8a5e895698c975e0ec979ca7d94f3733774b7e7653280dc96a603520b033664444d840df6fe97eb57741c58ad25ab02aa0261

NODE_ENV=production
DB_PATH=./links.db
```

**Note:** Railway automatically sets `RAILWAY_STATIC_URL` - do not set this manually.

## Recent Fixes Applied
- ✅ Fixed HTTPS URL generation for Railway deployment
- ✅ Updated base URL handling to use proper protocol (https://)
- ✅ Fixed server binding to listen on all interfaces (0.0.0.0)
- ✅ QR code generation now uses correct Railway domain

## Deploy Steps
1. Push to GitHub (already done)
2. Set environment variables in Railway dashboard  
3. Deploy via Railway dashboard or CLI
4. Test all features on live site

## Post-Deployment Testing
- [ ] Homepage loads correctly
- [ ] User registration works
- [ ] User login works  
- [ ] Link creation works (authenticated)
- [ ] Link creation works (anonymous)
- [ ] **QR code generation works with correct URLs**
- [ ] **Short URLs resolve correctly**
- [ ] Dashboard shows user data
- [ ] Link management functions work
- [ ] Analytics tracking works
- [ ] Link expiration works
- [ ] Navigation works across all pages

## Live Testing URLs (after deployment)
- Main page: https://your-app.railway.app/
- Login: https://your-app.railway.app/login.html
- Register: https://your-app.railway.app/register.html
- Dashboard: https://your-app.railway.app/dashboard
- Management: https://your-app.railway.app/manage.html
