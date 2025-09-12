const express = require('express');
const { body, validationResult } = require('express-validator');
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.static('public'));

// Redis client setup
const redisClient = new Redis({
  host: process.env.REDIS_HOST,
  port: Number.isNaN(parseInt(process.env.REDIS_PORT))
    ? 6379
    : parseInt(process.env.REDIS_PORT),
  password: process.env.REDIS_PASSWORD,
  connectTimeout: 60 * 1000 * 5,
  maxRetriesPerRequest: null,
  tls: { rejectUnauthorized: false },
});

redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

// Email transporter setup
const transporter = nodemailer.createTransport({
    host: 'email-smtp.us-east-1.amazonaws.com',
    port: 465,
    secure: true,
    auth: {
      user: 'AKIA57QXAEZ2NLD5F2HU',
      pass: 'BEYiOrq2TAkWJf+CRyIA/C6vX1LL+/PX2ooycmZe4Z9b',
    },
    tls: {
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    },
  });

// Validation arrays (converted from PHP)
const disposableDomains = [
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
  "yahoo.com", "outlook.com", "sample.com"
];

const fakeEmailPatterns = [
  /^test/i, /^dummy/i, /^fake/i, /^abcd/i,
  /^qwerty/i, /^random/i, /^user/i, /^unknown/i,
  /^example/i, /^temp/i, /\d{6,}/
];

const fakePhoneNumbers = [
  "1234567890", "0987654321", "0000000000", "1111111111", "2222222222",
  "3333333333", "4444444444", "5555555555", "6666666666", "7777777777",
  "8888888888", "9999999999", "9876543210"
];

// Validation functions
function validateEmail(email) {
  const emailDomain = email.split('@')[1];
  const emailUsername = email.split('@')[0];
  
  // Check disposable domains
  if (disposableDomains.includes(emailDomain)) {
    return { valid: false, message: 'Gmail, Yahoo, and temporary email addresses are not allowed. Please use a valid work email.' };
  }
  
  // Check fake email patterns
  for (const pattern of fakeEmailPatterns) {
    if (pattern.test(emailUsername)) {
      return { valid: false, message: 'Fake or temporary emails are not allowed. Please enter a valid work email.' };
    }
  }
  
  return { valid: true };
}

function validatePhone(phone) {
  const rawPhone = phone.replace(/\D/g, ''); // remove non-digits
  
  // Check fake phone numbers
  if (fakePhoneNumbers.includes(rawPhone)) {
    return { valid: false, message: 'Please enter a valid phone number. Random, sequential, or repeated numbers are not allowed.' };
  }
  
  // Check repeated digits (6+ repeated digits)
  const repeatedDigitsPattern = /^(\d)\1{5,}$/;
  if (repeatedDigitsPattern.test(rawPhone)) {
    return { valid: false, message: 'Please enter a valid phone number. Random, sequential, or repeated numbers are not allowed.' };
  }
  
  // Check sequential digits
  const sequentialPattern = /(?:0123456789|123456789|234567890|345678901|456789012|567890123|678901234|789012345|890123456|901234567|9876543210|876543210|76543210|6543210|543210)/;
  if (sequentialPattern.test(rawPhone)) {
    return { valid: false, message: 'Please enter a valid phone number. Random, sequential, or repeated numbers are not allowed.' };
  }
  
  return { valid: true };
}

// Check for duplicate email in Redis
async function checkDuplicateEmail(email) {
  try {
    const exists = await redisClient.exists(`email:${email}`);
    return exists === 1;
  } catch (error) {
    console.error('Error checking duplicate email:', error);
    return false;
  }
}

// Store email in Redis
async function storeEmail(email, submissionDate) {
  try {
    await redisClient.set(`email:${email}`, submissionDate);
    await redisClient.sadd('submitted_emails', `${email} | ${submissionDate}`);
  } catch (error) {
    console.error('Error storing email:', error);
    throw error;
  }
}

// Send email
async function sendEmail(formData) {
  const { first_name, agency_name, email, full_phone, monthly_client_volume, deliverability_pain, timeline, ready, submissionDate } = formData;
  
  const mailOptions = {
    from: 'AKIA57QXAEZ2NLD5F2HU',
    to: 'sriethiraj@getnos.io',
    bcc:['sumith@inboxdoctor.ai','sales@inboxdoctor.ai'],
    subject: 'BOOKING INBOX DOCTOR - ENQUIRY FORM',
    headers: {
          'Return-Path': 'no-reply@inboxdoctor.ai',
          'Reply-To': 'no-reply@inboxdoctor.ai',
        },
    text: `You have received a new form submission request:

First Name: ${first_name}
Agency Name: ${agency_name}
Work Email: ${email}
Phone: ${full_phone}
Monthly Client Volume: ${monthly_client_volume}
Deliverability Pain: ${deliverability_pain}
Timeline: ${timeline}
Ready: ${ready}
Submitted On: ${submissionDate}`
  };
  
  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
}

// Form submission route
app.post('/submit', [
  body('first_name').notEmpty().withMessage('First name is required'),
  body('agency_name').notEmpty().withMessage('Agency name is required'),
  body('business_email').isEmail().withMessage('Valid email is required'),
  body('country_code').notEmpty().withMessage('Country code is required'),
  body('phone').notEmpty().withMessage('Phone number is required'),
  body('monthly_client_volume').notEmpty().withMessage('Monthly client volume is required'),
  body('deliverability_pain').notEmpty().withMessage('Deliverability pain is required'),
  body('timeline').notEmpty().withMessage('Timeline is required'),
  body('ready').notEmpty().withMessage('Ready status is required')
], async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const {
      first_name,
      agency_name,
      business_email: email,
      country_code,
      phone,
      monthly_client_volume,
      deliverability_pain,
      timeline,
      ready
    } = req.body;

    const full_phone = `${country_code} ${phone}`;
    const submissionDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format

    // Validate email
    const emailValidation = validateEmail(email);
    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message
      });
    }

    // Validate phone
    const phoneValidation = validatePhone(phone);
    if (!phoneValidation.valid) {
      return res.status(400).json({
        success: false,
        message: phoneValidation.message
      });
    }

    // Check for duplicate email
    const isDuplicate = await checkDuplicateEmail(email);
    if (isDuplicate) {
      return res.status(400).json({
        success: false,
        message: 'This email has already been submitted. Please use a different email ID.'
      });
    }

    // Prepare form data
    const formData = {
      first_name,
      agency_name,
      email,
      full_phone,
      monthly_client_volume,
      deliverability_pain,
      timeline,
      ready,
      submissionDate
    };

    // Send email
    const emailSent = await sendEmail(formData);
    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send email. Please try again later.'
      });
    }

    // Store email in Redis
    await storeEmail(email, submissionDate);

    // Redirect to Calendly
    res.json({
      success: true,
      redirectUrl: 'https://calendly.com/inboxdoctor-sales/inboxdoctor-product-demolp'
    });

  } catch (error) {
    console.error('Error processing form:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

// Get submitted emails (for admin purposes)
app.get('/admin/emails', async (req, res) => {
  try {
    const emails = await redisClient.smembers('submitted_emails');
    res.json({ emails });
  } catch (error) {
    console.error('Error fetching emails:', error);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to view the form`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await redisClient.disconnect();
  process.exit(0);
});
