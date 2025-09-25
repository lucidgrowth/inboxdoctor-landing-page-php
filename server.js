const express = require('express');
const { body, validationResult } = require('express-validator');
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
const { google } = require('googleapis');
const { JWT } = require('google-auth-library');
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

// Google Sheets configuration
const SPREADSHEET_ID = '1fP9qecJoBxZY3jKdAbD4nCMvySHsw2zV8XaVzTx-_sM';
const RANGE = 'A:H'; // A: Name, B: Agency, C: Email, D: Phone, E: Score, F: Date, G: Time (IST), H: Country

// Initialize Google Sheets API
let sheets;
async function initializeGoogleSheets() {
  try {
    // Handle private key formatting for different environments
    let privateKey = process.env.GOOGLE_PRIVATE_KEY;
    
    if (privateKey) {
      // Replace escaped newlines with actual newlines
      privateKey = privateKey.replace(/\\n/g, '\n');
      
      // Ensure the key has proper BEGIN/END markers
      if (!privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
        privateKey = `-----BEGIN PRIVATE KEY-----\n${privateKey}\n-----END PRIVATE KEY-----`;
      }
    }

    const auth = new JWT({
      email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      key: privateKey,
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });

    sheets = google.sheets({ version: 'v4', auth });
    console.log('Google Sheets API initialized');
  } catch (error) {
    console.error('Error initializing Google Sheets:', error);
    console.error('Please check your GOOGLE_PRIVATE_KEY environment variable');
  }
}

// Lead scoring configuration
const SCORING_WEIGHTS = {
  COUNTRY: 40,      // US gets highest score
  EMAIL_DOMAIN: 25, // Business domains score higher
  PHONE_VALIDITY: 20, // Valid phone numbers
  NAME_QUALITY: 10,  // Professional names
  AGENCY_QUALITY: 5  // Agency name quality
};

// Country codes and their scores (US prioritized)
const COUNTRY_SCORES = {
  'US': 100, 'USA': 100, '+1': 100,
  'CA': 85, 'CAN': 85, '+1': 85, // Canada
  'GB': 80, 'UK': 80, '+44': 80, // UK
  'AU': 75, 'AUS': 75, '+61': 75, // Australia
  'DE': 70, 'DEU': 70, '+49': 70, // Germany
  'FR': 65, 'FRA': 65, '+33': 65, // France
  'JP': 60, 'JPN': 60, '+81': 60, // Japan
  'IN': 55, 'IND': 55, '+91': 55, // India
  'BR': 50, 'BRA': 50, '+55': 50, // Brazil
  'MX': 45, 'MEX': 45, '+52': 45, // Mexico
  'DEFAULT': 30 // Other countries
};

// High-value business email domains
const BUSINESS_DOMAINS = {
  'gmail.com': 30,
  'outlook.com': 30,
  'hotmail.com': 25,
  'yahoo.com': 20,
  'aol.com': 15,
  'icloud.com': 15,
  'BUSINESS': 90, // Custom business domains
  'EDUCATION': 85, // .edu domains
  'GOVERNMENT': 80, // .gov domains
  'NONPROFIT': 75  // .org domains
};

// Professional name patterns
const PROFESSIONAL_PATTERNS = [
  /^[A-Z][a-z]+ [A-Z][a-z]+$/, // First Last
  /^[A-Z][a-z]+ [A-Z]\. [A-Z][a-z]+$/, // First M. Last
  /^[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+$/ // First Middle Last
];

// Country mapping based on phone extensions
const COUNTRY_EXTENSIONS = {
  '+91': 'India',
  '+1': 'USA',
  '+44': 'UK',
  '+61': 'Australia',
  '+971': 'UAE',
  '+65': 'Singapore',
  '+63': 'Philippines'
};

// Function to get country name from phone extension
function getCountryFromExtension(countryCode) {
  return COUNTRY_EXTENSIONS[countryCode] || 'Unknown';
}

// Function to get IST timestamp in 12-hour format
function getISTTimestamp() {
  const now = new Date();
  const istTime = new Date(now.toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
  
  const hours = istTime.getHours();
  const minutes = istTime.getMinutes();
  const seconds = istTime.getSeconds();
  
  const ampm = hours >= 12 ? 'PM' : 'AM';
  const displayHours = hours % 12 || 12;
  
  return `${displayHours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')} ${ampm}`;
}

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

// Lead scoring functions
function scoreCountry(countryCode) {
  const normalizedCode = countryCode?.toUpperCase().trim();
  return COUNTRY_SCORES[normalizedCode] || COUNTRY_SCORES.DEFAULT;
}

function scoreEmailDomain(email) {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) return 0;

  // Check for business domains
  if (BUSINESS_DOMAINS[domain]) {
    return BUSINESS_DOMAINS[domain];
  }

  // Check for special domain types
  if (domain.endsWith('.edu')) return BUSINESS_DOMAINS.EDUCATION;
  if (domain.endsWith('.gov')) return BUSINESS_DOMAINS.GOVERNMENT;
  if (domain.endsWith('.org')) return BUSINESS_DOMAINS.NONPROFIT;
  
  // Custom business domains (not common email providers)
  const commonProviders = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com', 'icloud.com'];
  if (!commonProviders.includes(domain)) {
    return BUSINESS_DOMAINS.BUSINESS;
  }

  return 0;
}

function scorePhoneValidity(phone) {
  const rawPhone = phone.replace(/\D/g, '');
  
  // Check if it's a fake number
  if (fakePhoneNumbers.includes(rawPhone)) return 0;
  
  // Check for repeated digits
  const repeatedDigitsPattern = /^(\d)\1{5,}$/;
  if (repeatedDigitsPattern.test(rawPhone)) return 0;
  
  // Check for sequential digits
  const sequentialPattern = /(?:0123456789|123456789|234567890|345678901|456789012|567890123|678901234|789012345|890123456|901234567|9876543210|876543210|76543210|6543210|543210)/;
  if (sequentialPattern.test(rawPhone)) return 0;
  
  // Valid phone number length (7-15 digits)
  if (rawPhone.length >= 7 && rawPhone.length <= 15) {
    return 100;
  }
  
  return 50; // Partial score for somewhat valid numbers
}

function scoreNameQuality(name) {
  if (!name || name.trim().length < 2) return 0;
  
  const trimmedName = name.trim();
  
  // Check for professional patterns
  for (const pattern of PROFESSIONAL_PATTERNS) {
    if (pattern.test(trimmedName)) {
      return 100;
    }
  }
  
  // Check for single name (less professional)
  if (trimmedName.split(' ').length === 1) {
    return 30;
  }
  
  // Check for too many parts (might be fake)
  if (trimmedName.split(' ').length > 4) {
    return 20;
  }
  
  // Check for numbers in name (unprofessional)
  if (/\d/.test(trimmedName)) {
    return 10;
  }
  
  return 70; // Default score for reasonable names
}

function scoreAgencyQuality(agencyName) {
  if (!agencyName || agencyName.trim().length < 2) return 0;
  
  const trimmedAgency = agencyName.trim();
  
  // Check for generic/fake agency names
  const fakeAgencyPatterns = [
    /^test/i, /^dummy/i, /^fake/i, /^company/i, /^business/i,
    /^agency/i, /^corp/i, /^inc/i, /^llc/i, /^ltd/i
  ];
  
  for (const pattern of fakeAgencyPatterns) {
    if (pattern.test(trimmedAgency)) {
      return 20;
    }
  }
  
  // Check for very short names
  if (trimmedAgency.length < 3) {
    return 10;
  }
  
  // Check for numbers only
  if (/^\d+$/.test(trimmedAgency)) {
    return 5;
  }
  
  return 80; // Default score for reasonable agency names
}

function calculateLeadScore(formData) {
  const { first_name, agency_name, business_email, country_code, phone } = formData;
  
  const countryScore = scoreCountry(country_code);
  const emailScore = scoreEmailDomain(business_email);
  const phoneScore = scorePhoneValidity(phone);
  const nameScore = scoreNameQuality(first_name);
  const agencyScore = scoreAgencyQuality(agency_name);
  
  // Calculate weighted score
  const totalScore = Math.round(
    (countryScore * SCORING_WEIGHTS.COUNTRY / 100) +
    (emailScore * SCORING_WEIGHTS.EMAIL_DOMAIN / 100) +
    (phoneScore * SCORING_WEIGHTS.PHONE_VALIDITY / 100) +
    (nameScore * SCORING_WEIGHTS.NAME_QUALITY / 100) +
    (agencyScore * SCORING_WEIGHTS.AGENCY_QUALITY / 100)
  );
  
  // Ensure score is between 0-100
  return Math.max(0, Math.min(100, totalScore));
}

// Google Sheets functions
async function ensureHeaderRow() {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return false;
    }

    // Check if sheet has any data
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: 'A1:F1',
    });

    const existingData = response.data.values;
    
    // If no data exists, add header row
    if (!existingData || existingData.length === 0) {
      const headerValues = [
        ['Name', 'Agency', 'Email', 'Phone', 'Score', 'Date', 'Time (IST)', 'Country']
      ];

      await sheets.spreadsheets.values.update({
        spreadsheetId: SPREADSHEET_ID,
        range: 'A1:H1',
        valueInputOption: 'RAW',
        resource: { values: headerValues }
      });

      console.log('Header row added to Google Sheets');
    }

    return true;
  } catch (error) {
    console.error('Error ensuring header row:', error);
    return false;
  }
}

async function appendLeadToSheet(leadData) {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return false;
    }

    // Ensure header row exists
    await ensureHeaderRow();

    const values = [
      [
        leadData.first_name,
        leadData.agency_name,
        leadData.email,
        leadData.full_phone,
        leadData.score,
        leadData.submissionDate,
        leadData.istTimestamp,
        leadData.country
      ]
    ];

    console.log('Adding lead to Google Sheets:', values[0]);

    const response = await sheets.spreadsheets.values.append({
      spreadsheetId: SPREADSHEET_ID,
      range: RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      resource: { values }
    });

    console.log('Lead added to Google Sheets successfully');
    return true;
  } catch (error) {
    console.error('Error adding lead to Google Sheets:', error);
    
    // Check if it's an authentication error
    if (error.message && error.message.includes('DECODER routines')) {
      console.error('Authentication error: Please check your GOOGLE_PRIVATE_KEY format');
      console.error('The private key should be properly formatted with newlines');
    }
    
    return false;
  }
}

async function getAllLeadsFromSheet() {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return [];
    }

    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range: RANGE,
    });

    const data = response.data.values || [];
    
    // If only header row exists, return empty array
    if (data.length <= 1) {
      return [];
    }
    
    return data;
  } catch (error) {
    console.error('Error fetching leads from Google Sheets:', error);
    return [];
  }
}

async function sortLeadsByScore() {
  try {
    const leads = await getAllLeadsFromSheet();
    
    // If no leads to sort, return true
    if (leads.length === 0) {
      console.log('No leads to sort');
      return true;
    }
    
    // Skip header row if it exists
    const dataRows = leads.slice(1);
    
    // If no data rows, return true
    if (dataRows.length === 0) {
      console.log('No data rows to sort');
      return true;
    }
    
    // Sort by score (column E, index 4) in descending order
    const sortedLeads = dataRows.sort((a, b) => {
      const scoreA = parseInt(a[4]) || 0;
      const scoreB = parseInt(b[4]) || 0;
      return scoreB - scoreA;
    });
    
    // Prepare data for update (include header + sorted data)
    const headerRow = leads[0] || ['Name', 'Agency', 'Email', 'Phone', 'Score', 'Date', 'Time (IST)', 'Country'];
    const sortedData = [headerRow, ...sortedLeads];
    
    // Update the sheet with sorted data
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: RANGE,
      valueInputOption: 'RAW',
      resource: { values: sortedData }
    });
    
    console.log('Leads sorted by score');
    return true;
  } catch (error) {
    console.error('Error sorting leads:', error);
    return false;
  }
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
  const { first_name, agency_name, email, full_phone, submissionDate } = formData;
  
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
Country: ${formData.country}
Lead Score: ${formData.score}/100
Submitted On: ${submissionDate} at ${formData.istTimestamp} IST`
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
    } = req.body;

    const full_phone = `${country_code} ${phone}`;
    const submissionDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    const istTimestamp = getISTTimestamp();
    const country = getCountryFromExtension(country_code);

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

    // Calculate lead score
    const leadScore = calculateLeadScore({
      first_name,
      agency_name,
      business_email: email,
      country_code,
      phone
    });

    // Prepare form data with score
    const formData = {
      first_name,
      agency_name,
      email,
      full_phone,
      submissionDate,
      istTimestamp,
      country,
      score: leadScore
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

    // Add lead to Google Sheets with score
    const sheetAdded = await appendLeadToSheet(formData);
    if (sheetAdded) {
      // Sort leads by score after adding new lead
      await sortLeadsByScore();
    }

    // Redirect to Calendly
    res.json({
      success: true,
      redirectUrl: 'https://calendly.com/inboxdoctor-sales/inboxdoctor-product-demolp',
      leadScore: leadScore
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

// Initialize Google Sheets on startup
initializeGoogleSheets();

// Admin endpoint to get all leads with scores
app.get('/admin/leads', async (req, res) => {
  try {
    const leads = await getAllLeadsFromSheet();
    res.json({ leads });
  } catch (error) {
    console.error('Error fetching leads:', error);
    res.status(500).json({ error: 'Failed to fetch leads' });
  }
});

// Admin endpoint to sort leads by score
app.post('/admin/sort-leads', async (req, res) => {
  try {
    const sorted = await sortLeadsByScore();
    res.json({ success: sorted, message: sorted ? 'Leads sorted successfully' : 'Failed to sort leads' });
  } catch (error) {
    console.error('Error sorting leads:', error);
    res.status(500).json({ error: 'Failed to sort leads' });
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
