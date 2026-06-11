# Google OAuth Setup Guide

This guide will help you set up Google OAuth login for the Hospital Bed Prediction System.

## Prerequisites
- A Google account
- Access to Google Cloud Console

## Step-by-Step Setup

### 1. Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown at the top
3. Click "NEW PROJECT"
4. Enter project name: `Hospital Bed Prediction System`
5. Click "CREATE"

### 2. Enable Google+ API

1. In the left sidebar, go to "APIs & Services" → "Enabled APIs & services"
2. Click "+ ENABLE APIS AND SERVICES"
3. Search for "Google+ API" or "Google Identity API"
4. Click on it and click "ENABLE"

### 3. Create OAuth 2.0 Credentials

1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth 2.0 Client ID"
3. If prompted, click "Configure OAuth Consent Screen" first:
   - Select "External" for User Type
   - Fill in App name: `Hospital Bed Prediction System`
   - Add your email
   - Add any required scopes (leave defaults)
   - Add your email as a test user
   - Click "Create"

4. Back to Credentials, click "Create Credentials" → "OAuth 2.0 Client ID"
5. Select "Web application"
6. Name: `Hospital Bed Prediction`
7. Add Authorized Redirect URIs:
   - `http://localhost:8501/`
   - `http://localhost:8501/callback`
   - `http://localhost:8501/api/callback`

8. Click "Create"

### 4. Get Your Credentials

1. After creation, a dialog will appear with:
   - **Client ID**
   - **Client Secret**
2. Click "Copy" for each and save them securely
3. Or download as JSON file

### 5. Set Environment Variables

#### On Windows (PowerShell):
```powershell
$env:GOOGLE_CLIENT_ID = "your_client_id_here"
$env:GOOGLE_CLIENT_SECRET = "your_client_secret_here"
```

#### On Windows (Command Prompt):
```cmd
set GOOGLE_CLIENT_ID=your_client_id_here
set GOOGLE_CLIENT_SECRET=your_client_secret_here
```

#### On macOS/Linux:
```bash
export GOOGLE_CLIENT_ID="your_client_id_here"
export GOOGLE_CLIENT_SECRET="your_client_secret_here"
```

#### Using .env file (Recommended):
Create a `.env` file in your project root:
```
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
```

Then install python-dotenv:
```bash
pip install python-dotenv
```

### 6. Install Required Packages

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install google-auth==2.27.0
pip install google-auth-oauthlib==1.2.0
pip install google-auth-httplib2==0.2.0
pip install streamlit-oauth==0.2.1
```

### 7. Run the Application

```bash
streamlit run app.py
```

## Testing Google Login

1. Launch the app
2. On the login page, click "Sign in with Google"
3. You'll be redirected to Google's login page
4. Log in with your Google account
5. Grant permission to the app
6. You'll be redirected back to the app with your profile loaded

## Deploying to Production

### For Streamlit Cloud:

1. Add your credentials to Streamlit Secrets:
   - Go to your app's settings
   - Click "Secrets"
   - Add:
   ```
   GOOGLE_CLIENT_ID = "your_client_id"
   GOOGLE_CLIENT_SECRET = "your_client_secret"
   ```

2. Update Redirect URI in Google Console:
   - Add: `https://your-app-name.streamlit.app/`

### For Other Platforms (Heroku, Render, etc.):

1. Add environment variables in your deployment settings:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`

2. Update the `REDIRECT_URI` in the code:
   ```python
   REDIRECT_URI = 'https://your-production-domain.com'
   ```

3. Add production URL to Google OAuth Redirect URIs in Google Cloud Console

## Security Best Practices

⚠️ **IMPORTANT:**
- Never commit `.env` file or credentials to GitHub
- Always use environment variables for sensitive data
- Rotate your credentials periodically
- Use HTTPS in production
- Keep your client secret... secret!

## Troubleshooting

### "Redirect URI mismatch" error
- Make sure the redirect URI in Google Console exactly matches your app's URL
- Check for trailing slashes
- Include http:// or https:// prefix

### "Invalid client" error
- Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are correct
- Check that environment variables are properly set

### App is not using Google OAuth
- Verify environment variables are set before running the app
- Restart the application
- Check browser console for errors

## Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)
- [Streamlit Secrets Management](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app/secrets-management)

## Next Steps

Once Google OAuth is configured:
1. Users can log in with their Google account
2. User profile information is automatically retrieved
3. Sessions are managed securely
4. User data is protected with encryption

---

**Need Help?** Check the console for error messages or enable debug mode for detailed logs.
