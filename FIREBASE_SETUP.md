# Firebase Authentication Setup Guide

Complete guide to set up Firebase authentication for the Hospital Bed Prediction System.

## Why Firebase?

Firebase provides a comprehensive authentication solution with:
- ✅ Multiple authentication providers (Google, Email/Password, Facebook, GitHub, Twitter, Phone)
- ✅ Built-in user management
- ✅ Real-time database integration
- ✅ Cloud storage for patient records
- ✅ Analytics and monitoring
- ✅ Free tier with generous limits

## Prerequisites

- A Google account
- Firebase account (free)
- Hospital Bed Prediction System project

## Step-by-Step Setup

### Step 1: Create a Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click **"Add Project"** or **"Create a Project"**
3. Enter project name: `Hospital Bed Prediction System`
4. Accept the terms and click **"Create Project"**
5. Wait for project creation (1-2 minutes)

### Step 2: Enable Authentication

1. In Firebase Console, go to **"Build"** → **"Authentication"**
2. Click **"Get Started"**
3. Go to **"Sign-in method"** tab

#### Enable Email/Password Authentication:
1. Click **"Email/Password"** provider
2. Toggle **"Enable"** switch
3. Click **"Save"**

#### Enable Google OAuth:
1. Click **"Google"** provider
2. Toggle **"Enable"** switch
3. Select a project support email
4. Click **"Save"**

#### Optional: Enable Other Providers
- Facebook
- GitHub
- Twitter
- Phone Number Authentication

### Step 3: Get Your Configuration

#### Method A: Web Configuration (for web apps)
1. Go to **Project Settings** (gear icon)
2. Click **"Your apps"** → **"Web"** (or add new web app)
3. Copy your Firebase config:
   ```javascript
   const firebaseConfig = {
       apiKey: "AIzaSy...",
       authDomain: "your-project.firebaseapp.com",
       projectId: "your-project",
       databaseURL: "https://your-project.firebaseio.com",
       storageBucket: "your-project.appspot.com"
   };
   ```

#### Method B: Service Account Key (for backend/admin use)
1. Go to **Project Settings** → **"Service Accounts"**
2. Click **"Generate New Private Key"**
3. Save the JSON file as `firebase-credentials.json`
4. ⚠️ **KEEP THIS FILE SECURE** - Never commit to GitHub

### Step 4: Set Up Environment Variables

#### Option 1: Using `.env` File (Recommended for Development)

Create a `.env` file in your project root:
```
FIREBASE_API_KEY=AIzaSy...
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_DATABASE_URL=https://your-project.firebaseio.com
FIREBASE_STORAGE_BUCKET=your-project.appspot.com
FIREBASE_CREDENTIALS_PATH=./firebase-credentials.json
```

#### Option 2: Using System Environment Variables

**Windows (PowerShell):**
```powershell
$env:FIREBASE_API_KEY = "AIzaSy..."
$env:FIREBASE_AUTH_DOMAIN = "your-project.firebaseapp.com"
$env:FIREBASE_PROJECT_ID = "your-project-id"
$env:FIREBASE_DATABASE_URL = "https://your-project.firebaseio.com"
$env:FIREBASE_STORAGE_BUCKET = "your-project.appspot.com"
$env:FIREBASE_CREDENTIALS_PATH = "./firebase-credentials.json"
```

**Windows (Command Prompt):**
```cmd
set FIREBASE_API_KEY=AIzaSy...
set FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
set FIREBASE_PROJECT_ID=your-project-id
set FIREBASE_DATABASE_URL=https://your-project.firebaseio.com
set FIREBASE_STORAGE_BUCKET=your-project.appspot.com
set FIREBASE_CREDENTIALS_PATH=./firebase-credentials.json
```

**macOS/Linux:**
```bash
export FIREBASE_API_KEY="AIzaSy..."
export FIREBASE_AUTH_DOMAIN="your-project.firebaseapp.com"
export FIREBASE_PROJECT_ID="your-project-id"
export FIREBASE_DATABASE_URL="https://your-project.firebaseio.com"
export FIREBASE_STORAGE_BUCKET="your-project.appspot.com"
export FIREBASE_CREDENTIALS_PATH="./firebase-credentials.json"
```

### Step 5: Configure .gitignore

Make sure Firebase credentials are not committed to GitHub:

```gitignore
# Firebase
firebase-credentials.json
.env
.env.local
.env.*.local
```

### Step 6: Install Dependencies

```bash
pip install -r requirements.txt
```

Main packages:
- `firebase-admin==6.4.0` - Firebase Admin SDK
- `python-firebase==1.2` - Python Firebase client

### Step 7: Test the Setup

1. Set environment variables (from Step 4)
2. Place `firebase-credentials.json` in project root
3. Run the application:
```bash
streamlit run app.py
```

4. You should see **Firebase Authentication** options on the login page

## Troubleshooting

### "Firebase Configuration Not Valid" Error

**Problem:** Firebase authentication not working even after setup

**Solutions:**
1. Verify all environment variables are set correctly
2. Check that `firebase-credentials.json` exists in the correct path
3. Ensure the JSON file is not corrupted
4. Restart the application after setting environment variables

### "Permission Denied" Error

**Problem:** Firebase operations failing with permission errors

**Solutions:**
1. In Firebase Console, go to **Firestore Database** or **Realtime Database**
2. Go to **Rules** tab
3. For development, temporarily set rules to:
   ```
   {
     "rules": {
       ".read": true,
       ".write": true
     }
   }
   ```
4. ⚠️ Change to proper security rules before production!

### "Invalid Credentials" Error

**Problem:** Service account key is not valid

**Solutions:**
1. Delete the old `firebase-credentials.json`
2. Generate a new private key from **Project Settings** → **Service Accounts**
3. Replace the file in your project
4. Restart the application

## Production Deployment

### For Streamlit Cloud:

1. Create a new repository secret:
   - Go to your Streamlit app settings
   - Click **"Secrets"**
   - Add all FIREBASE_* variables

2. Upload `firebase-credentials.json` contents as a secret:
   - Click **"New secret"**
   - Name: `FIREBASE_CREDENTIALS`
   - Value: (paste entire JSON content)

3. Update `FIREBASE_SETUP.md` with correct URLs

### For Other Platforms (Heroku, Render, AWS, etc.):

1. Set environment variables in deployment settings
2. Upload `firebase-credentials.json` securely
3. Use the app's secret management system

### Update Authorized Domains:

1. Go to **Authentication** → **Settings** (gear icon)
2. Add your production domain to **Authorized domains**:
   - `localhost:8501` (for local development)
   - `your-app.streamlit.app` (if using Streamlit Cloud)
   - `your-production-domain.com` (your custom domain)

## Security Best Practices

### Critical:
- ✅ Never commit `firebase-credentials.json` to GitHub
- ✅ Never expose API keys in client-side code
- ✅ Always use HTTPS in production
- ✅ Rotate credentials periodically

### Recommended:
- ✅ Use environment variables for sensitive data
- ✅ Enable MFA for Firebase console access
- ✅ Use strong, unique passwords
- ✅ Monitor Firebase console for suspicious activity
- ✅ Set up billing alerts

### Firestore Security Rules (Production):

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Allow authenticated users to read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth.uid == userId;
    }
    
    // Allow authenticated users to read hospital data
    match /hospitals/{document=**} {
      allow read: if request.auth != null;
    }
    
    // Only admins can write to hospital data
    match /hospitals/{document=**} {
      allow write: if request.auth.token.admin == true;
    }
  }
}
```

## Features Available with Firebase

Once set up, you can use:

### User Management:
- Email/Password registration and login
- Google OAuth login
- User profile management
- Password reset
- Email verification

### Database:
- Real-time data sync with Firestore
- Store patient records
- Store bed occupancy data
- Store user preferences

### Cloud Storage:
- Store patient documents (X-rays, reports)
- Store medical records
- Store user avatars

### Analytics:
- Track user behavior
- Monitor app usage
- Identify popular features

## Next Steps

1. ✅ Complete setup following this guide
2. ✅ Test authentication with demo users
3. ✅ Integrate Firestore database for patient records
4. ✅ Add cloud storage for medical documents
5. ✅ Set up proper security rules for production

## Useful Links

- [Firebase Documentation](https://firebase.google.com/docs)
- [Firebase Admin SDK (Python)](https://firebase.google.com/docs/database/admin/start)
- [Firestore Security Rules](https://firebase.google.com/docs/firestore/security/start)
- [Firebase Authentication](https://firebase.google.com/docs/auth)
- [Firebase Console](https://console.firebase.google.com/)

## Support

For issues or questions:
1. Check [Firebase Documentation](https://firebase.google.com/docs)
2. Review troubleshooting section above
3. Check console output for error messages
4. Enable debug logging by setting environment variable: `DEBUG=1`

---

**Last Updated:** 2026-06-11  
**Firebase Admin SDK:** 6.4.0  
**Python Version:** 3.7+
