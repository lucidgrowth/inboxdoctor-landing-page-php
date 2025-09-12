# Inbox Doctor - Contact Form

A JavaScript/Node.js application converted from PHP that handles contact form submissions with Redis integration for email storage and validation.

## Features

- ✅ **Form Validation**: Email and phone number validation with fake/temporary email detection
- ✅ **Redis Integration**: Stores submitted emails in Redis instead of text files
- ✅ **Email Sending**: Sends form submissions via email using Nodemailer
- ✅ **Duplicate Prevention**: Prevents duplicate email submissions
- ✅ **Modern UI**: Responsive, beautiful form interface
- ✅ **Error Handling**: Comprehensive error handling and user feedback

## Prerequisites

- Node.js (v14 or higher)
- Redis server
- SMTP email account (Gmail, etc.)

## Installation

1. **Clone or download the project**
   ```bash
   cd hello-lucid
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp env.example .env
   ```
   
   Edit `.env` file with your configuration:
   ```env
   # Server Configuration
   PORT=3000

   # Redis Configuration
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_PASSWORD=

   # Email Configuration
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASS=your-app-password
   FROM_EMAIL=hello@getnos.io
   TO_EMAIL=sriethiraj@getnos.io
   ```

4. **Start Redis server**
   - **Windows**: Download Redis from [redis.io](https://redis.io/download) or use Docker
   - **macOS**: `brew install redis` then `brew services start redis`
   - **Linux**: `sudo apt-get install redis-server` then `sudo systemctl start redis`

5. **Run the application**
   ```bash
   # Development mode (with auto-restart)
   npm run dev
   
   # Production mode
   npm start
   ```

6. **Access the application**
   Open your browser and go to `http://localhost:3000`

## Configuration

### Email Setup (Gmail Example)

1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a password for "Mail"
   - Use this password in `SMTP_PASS`

### Redis Setup

The application uses Redis to store submitted emails. Each email is stored with:
- Key: `email:{email_address}`
- Value: `{submission_date}`
- Set: `submitted_emails` contains all submissions

## API Endpoints

- `GET /` - Serves the contact form
- `POST /submit` - Processes form submission
- `GET /admin/emails` - Returns all submitted emails (for admin purposes)

## Form Validation

### Email Validation
- Blocks disposable email domains (Gmail, Yahoo, temporary emails)
- Detects fake email patterns (test, dummy, fake, etc.)
- Prevents duplicate submissions

### Phone Validation
- Blocks fake phone numbers (1234567890, etc.)
- Detects repeated digits (1111111111)
- Detects sequential patterns (1234567890)

## Deployment

### Using PM2 (Recommended)
```bash
npm install -g pm2
pm2 start server.js --name "inbox-form"
pm2 startup
pm2 save
```

### Using Docker
```bash
# Create Dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Variables for Production
Make sure to set these in your production environment:
- `REDIS_HOST` - Your Redis server host
- `REDIS_PASSWORD` - Redis password if required
- `SMTP_USER` - Your email username
- `SMTP_PASS` - Your email app password
- `TO_EMAIL` - Where to send form submissions

## Monitoring

### View Submitted Emails
```bash
# Using Redis CLI
redis-cli
> SMEMBERS submitted_emails

# Or use the admin endpoint
curl http://localhost:3000/admin/emails
```

### Logs
The application logs important events to the console. For production, consider using a logging service.

## Differences from PHP Version

1. **Storage**: Uses Redis instead of `submitted_emails.txt` file
2. **Validation**: More robust validation with express-validator
3. **Error Handling**: Better error handling and user feedback
4. **API**: RESTful API endpoints instead of direct form processing
5. **Scalability**: Can handle multiple concurrent requests
6. **Security**: Better input sanitization and validation

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   - Ensure Redis server is running
   - Check Redis host and port configuration

2. **Email Sending Failed**
   - Verify SMTP credentials
   - Check if 2FA is enabled and app password is used
   - Ensure SMTP host and port are correct

3. **Port Already in Use**
   - Change PORT in .env file
   - Or kill the process using the port

### Debug Mode
Set `NODE_ENV=development` to enable detailed error messages.

## Support

For issues or questions, please check the logs and ensure all dependencies are properly installed and configured.
