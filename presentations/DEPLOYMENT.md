# Deployment Instructions for LAWFULLY_FLARE Web App

This document provides step-by-step instructions for deploying the LAWFULLY_FLARE web app to production.

## Prerequisites
- Node.js and npm installed
- MongoDB database set up
- Git installed
- AWS/GCP/Azure account (or other hosting provider)

## 1. Backend Deployment

### Set up Environment Variables
Create a `.env` file in the `backend` directory with the following variables:
```
PORT=3000
MONGODB_URI=<your-mongodb-uri>
JWT_SECRET=<your-jwt-secret>
```

### Install Dependencies
Navigate to the `backend` directory and install dependencies:
```bash
cd backend
npm install
```

### Build the Backend
Compile TypeScript files:
```bash
npm run build
```

### Start the Backend Server
```bash
npm start
```

## 2. Frontend Deployment

### Install Dependencies
Navigate to the `frontend` directory and install dependencies:
```bash
cd frontend
npm install
```

### Build the Frontend
```bash
npm run build
```

### Serve the Frontend
```bash
npm run start
```

## 3. Deployment to a Hosting Provider

### Option A: Deploy to Heroku
1. Install the Heroku CLI: `brew install heroku`
2. Login to Heroku: `heroku login`
3. Create a new Heroku app: `heroku create`
4. Add buildpacks:
   ```bash
   heroku buildpacks:add heroku/nodejs
   heroku buildpacks:add heroku/python
   ```
5. Deploy the app:
   ```bash
   git push heroku main
   ```

### Option B: Deploy to Vercel
1. Install Vercel CLI: `npm install -g vercel`
2. Initialize the project: `vercel`
3. Deploy: `vercel --prod`

## 4. Configure CI/CD (Optional)
Set up GitHub Actions or other CI/CD tools to automate deployment on code changes.

## 5. Domain Setup
Configure your custom domain with your hosting provider and set up SSL certificates.

## 6. Monitoring and Maintenance
Set up monitoring tools (e.g., Sentry, New Relic) and ensure regular backups.

