# Zoom OAuth Lab

Security-focused local web app for testing Zoom OAuth flows side by side:

- Confidential OAuth with `client_id + client_secret`
- PKCE OAuth with a Zoom public client ID

## Run it

```bash
npm start
```

Then open [http://localhost:3000](http://localhost:3000).

## Zoom Marketplace build flow setup

Use the Zoom App Marketplace build flow to prepare both test paths:

1. Create a `General App`.
2. In `App Credentials`, copy your standard `Client ID` and `Client Secret`.
3. Add this redirect URL for local development:

```text
http://localhost:3000/
```

4. Add the scopes you want to validate, for example:

```text
user:read
```

5. Enable `Use Public Client OAuth` to generate a `Public Client ID` for the PKCE flow.
6. Use the `Local Test` page in the Zoom build flow if you want Zoom to add the app to your own account before testing.
7. If you later submit the app for review, include in the build flow notes whether you support:
   - confidential OAuth
   - public client PKCE
   - both

Zoom’s current OAuth docs also note that changing scopes, redirect URLs, or related OAuth settings can trigger a fresh authorization prompt the next time you test.

## How to test

### Confidential flow

1. Enter the standard `Client ID` and `Client Secret`.
2. Click `Start confidential flow`.
3. Sign in to Zoom and approve access.
4. After redirect, click `Exchange code for current callback`.
5. Inspect the callback params and token payload.

### PKCE flow

1. Enter the `Public Client ID`.
2. Click `Start PKCE flow`.
3. Sign in to Zoom and approve access.
4. After redirect, click `Exchange code for current callback`.
5. Confirm the local app exchanges the code with the stored `code_verifier`.

## Security posture

- The app uses an ephemeral in-memory server session with an `HttpOnly` cookie.
- The confidential client secret is not stored in browser `localStorage` or `sessionStorage`.
- PKCE material is generated in the browser, then passed to the local server only for the current test session.
- Sessions expire automatically after 15 minutes.
- Token exchange requests are sent from the local server to `https://zoom.us/oauth/token`.

## Notes

- This is for local validation and debugging, not production deployment.
- Confidential flow uses your standard OAuth `Client ID` and `Client Secret`.
- PKCE flow uses a Zoom `Public Client ID`.
