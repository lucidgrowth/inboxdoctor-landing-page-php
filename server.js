const express = require('express');
const { body, validationResult } = require('express-validator');
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
const { google } = require('googleapis');
const { JWT } = require('google-auth-library');
const twilio = require('twilio');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Trust proxy for accurate IP detection (important for production)
app.set('trust proxy', true);

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

// Twilio client setup
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

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
const SPREADSHEET_ID_2 = '1f5sO10G6hfc8a4ToqT_gQQFa_uO6_j60ljDXVFF7Wus';
const RANGE = 'A:Q'; // A: S/Num, B: Lead ID, C: Name, D: Agency, E: Email, F: Phone, G: Score, H: Date, I: Time (IST), J: Country, K: Lead Score Cluster, L: Lead Source, M: IP Address, N: OS & Browser, O: Lead Type, P: Email Verified, Q: Phone Verified

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

// Lead source constant
const LEAD_SOURCE = 'https://offer.inboxdoctor.ai/';

// Lead ID counter (in production, this should be stored in Redis or database)
let leadIdCounter = 1;

// Function to generate unique Lead ID (Date/Month/Year format)
function generateLeadId() {
  const now = new Date();
  const day = now.getDate().toString().padStart(2, '0');
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const year = now.getFullYear().toString().slice(-2); // Last 2 digits of year
  const sequence = leadIdCounter.toString().padStart(4, '0');
  
  leadIdCounter++;
  return `${day}${month}${year}${sequence}`;
}

// Function to get client information from request
function getClientInfo(req) {
  // Extract IP address from various sources
  let ip = 'Unknown';
  let ipSource = 'Unknown';
  
  // Debug: Log all available IP information
  console.log('=== IP DETECTION DEBUG ===');
  console.log('req.ip:', req.ip);
  console.log('req.connection?.remoteAddress:', req.connection?.remoteAddress);
  console.log('req.socket?.remoteAddress:', req.socket?.remoteAddress);
  console.log('req.headers:', JSON.stringify(req.headers, null, 2));
  
  // Method 1: Check X-Forwarded-For header (for proxies/load balancers)
  if (req.headers['x-forwarded-for']) {
    ip = req.headers['x-forwarded-for'].split(',')[0].trim();
    ipSource = 'X-Forwarded-For';
  }
  // Method 2: Check X-Real-IP header
  else if (req.headers['x-real-ip']) {
    ip = req.headers['x-real-ip'];
    ipSource = 'X-Real-IP';
  }
  // Method 3: Check X-Client-IP header
  else if (req.headers['x-client-ip']) {
    ip = req.headers['x-client-ip'];
    ipSource = 'X-Client-IP';
  }
  // Method 4: Check CF-Connecting-IP header (Cloudflare)
  else if (req.headers['cf-connecting-ip']) {
    ip = req.headers['cf-connecting-ip'];
    ipSource = 'CF-Connecting-IP';
  }
  // Method 5: Check Express req.ip (if trust proxy is set)
  else if (req.ip) {
    ip = req.ip;
    ipSource = 'req.ip';
  }
  // Method 6: Check connection remote address
  else if (req.connection && req.connection.remoteAddress) {
    ip = req.connection.remoteAddress;
    ipSource = 'connection.remoteAddress';
  }
  // Method 7: Check socket remote address
  else if (req.socket && req.socket.remoteAddress) {
    ip = req.socket.remoteAddress;
    ipSource = 'socket.remoteAddress';
  }
  
  // Clean up IPv6 mapped IPv4 addresses
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  
  // Clean up IPv6 localhost
  if (ip === '::1') {
    ip = '127.0.0.1';
  }
  
  // Check for APIPA addresses (169.254.x.x) - these are invalid
  if (ip.startsWith('169.254.')) {
    console.log('WARNING: Detected APIPA address (169.254.x.x) - this indicates network configuration issues');
    console.log('Trying alternative IP detection methods...');
    
    // Try to get IP from other sources
    const alternativeIPs = [];
    
    // Check all possible headers
    const ipHeaders = [
      'x-forwarded-for', 'x-real-ip', 'x-client-ip', 'cf-connecting-ip',
      'x-cluster-client-ip', 'forwarded-for', 'forwarded'
    ];
    
    for (const header of ipHeaders) {
      if (req.headers[header]) {
        alternativeIPs.push(`${header}: ${req.headers[header]}`);
      }
    }
    
    console.log('Alternative IP sources found:', alternativeIPs);
    
    // If we have alternative sources, use the first valid one
    if (alternativeIPs.length > 0) {
      const firstAlternative = alternativeIPs[0].split(': ')[1];
      if (firstAlternative && !firstAlternative.startsWith('169.254.')) {
        ip = firstAlternative.split(',')[0].trim();
        ipSource = 'Alternative Header';
        console.log('Using alternative IP:', ip);
      }
    }
    
    // If still no valid IP, try to get it from User-Agent or other sources
    if (ip.startsWith('169.254.')) {
      console.log('Still getting APIPA address, this might be a server configuration issue');
      console.log('Consider checking:');
      console.log('1. Server network configuration');
      console.log('2. Load balancer/proxy settings');
      console.log('3. Docker/container networking');
      console.log('4. Cloud provider networking settings');
      
      // For now, mark as unknown rather than using invalid APIPA
      ip = 'Unknown (APIPA detected)';
      ipSource = 'APIPA Fallback';
    }
  }
  
  console.log('Final IP:', ip);
  console.log('IP Source:', ipSource);
  console.log('=== END IP DEBUG ===');
  
  const userAgent = req.headers['user-agent'] || 'Unknown';
  
  // Parse OS and Browser from User-Agent
  let os = 'Unknown';
  let browser = 'Unknown';
  
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac')) os = 'macOS';
  else if (userAgent.includes('Linux')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iOS')) os = 'iOS';
  
  if (userAgent.includes('Chrome')) browser = 'Chrome';
  else if (userAgent.includes('Firefox')) browser = 'Firefox';
  else if (userAgent.includes('Safari')) browser = 'Safari';
  else if (userAgent.includes('Edge')) browser = 'Edge';
  else if (userAgent.includes('Opera')) browser = 'Opera';
  
  return {
    ip: ip,
    os,
    browser,
    userAgent,
    ipSource: ipSource
  };
}

// Function to check if lead is duplicate based on email and phone
async function checkLeadDuplicate(email, phone) {
  try {
    // Check Redis for existing email or phone
    const emailExists = await redisClient.exists(`email:${email}`);
    const phoneExists = await redisClient.exists(`phone:${phone}`);
    
    return emailExists === 1 || phoneExists === 1;
  } catch (error) {
    console.error('Error checking lead duplicate:', error);
    return false;
  }
}

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

// Function to get lead score cluster based on score
function getLeadScoreCluster(score) {
  if (score >= 0 && score <= 20) {
    return "0–20 → Cold Leads ❄️";
  } else if (score >= 21 && score <= 40) {
    return "21–40 → Low-Intent Leads 🌙";
  } else if (score >= 41 && score <= 60) {
    return "41–60 → Warm Leads 🔥";
  } else if (score >= 61 && score <= 80) {
    return "61–80 → Qualified Leads 🚀";
  } else if (score >= 81 && score <= 100) {
    return "81–100 → Hot Leads 🔥🔥";
  } else {
    return "Unknown Score";
  }
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

// ValidEmail.net API configuration
const VALID_EMAIL_API_URL = 'https://api.ValidEmail.net/';
const VALID_EMAIL_TOKEN = '790e18d5ec364d28b343e70fc8ae17e3';

// Twilio validation functions
async function validateEmailWithTwilio(email) {
  try {
    // Basic email format validation first
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(email)) {
      return { 
        valid: false, 
        message: 'Invalid email format. Please enter a valid email address.' 
      };
    }
    
    // Use ValidEmail.net API for comprehensive email validation
    try {
      const response = await fetch(`${VALID_EMAIL_API_URL}?email=${encodeURIComponent(email)}&token=${VALID_EMAIL_TOKEN}`);
      
      if (!response.ok) {
        throw new Error(`ValidEmail API error: ${response.status}`);
      }
      
      const emailData = await response.json();
      
      console.log('ValidEmail API response:', emailData);
      
      // Check if email is valid and deliverable
      if (emailData.IsValid && emailData.State === 'Deliverable') {
        return { 
          valid: true, 
          message: 'Email validated successfully',
          domain: emailData.Domain,
          score: emailData.Score,
          state: emailData.State,
          reason: emailData.Reason,
          free: emailData.Free,
          role: emailData.Role,
          disposable: emailData.Disposable,
          acceptAll: emailData.AcceptAll,
          mxRecord: emailData.MXRecord,
          validationMethod: 'VALIDEMAIL_API'
        };
      } else {
        // Email is not valid or not deliverable
        let errorMessage = 'Invalid email address. Please enter a valid work email.';
        
        if (emailData.Reason) {
          switch (emailData.Reason) {
            case 'INVALID MAIL':
              errorMessage = 'Invalid email address. Please enter a valid work email.';
              break;
            case 'DISPOSABLE EMAIL':
              errorMessage = 'Temporary email addresses are not allowed. Please use a valid work email.';
              break;
            case 'ROLE EMAIL':
              errorMessage = 'Role-based email addresses (like admin@, info@) are not allowed. Please use a personal work email.';
              break;
            case 'FREE EMAIL':
              errorMessage = 'Free email providers are not allowed. Please use a work email address.';
              break;
            default:
              errorMessage = `Email validation failed: ${emailData.Reason}. Please enter a valid work email.`;
          }
        }
        
        return { 
          valid: false, 
          message: errorMessage,
          domain: emailData.Domain,
          score: emailData.Score,
          state: emailData.State,
          reason: emailData.Reason,
          free: emailData.Free,
          role: emailData.Role,
          disposable: emailData.Disposable,
          validationMethod: 'VALIDEMAIL_API'
        };
      }
    } catch (apiError) {
      console.error('ValidEmail API error:', apiError);
      
      // Fallback to basic validation if API fails
      const domain = email.split('@')[1].toLowerCase();
      const disposableDomains = [
        '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 
        'mailinator.com', 'throwaway.email', 'temp-mail.org',
        'tempmail.net', 'guerrillamail.net', 'sharklasers.com',
        'grr.la', 'guerrillamail.biz', 'guerrillamail.de',
        'guerrillamail.info', 'guerrillamail.org', 'guerrillamailblock.com',
        'yopmail.com', 'yopmail.net', 'yopmail.org', 'yopmail.fr',
        'tempail.com', 'tempmail2.com', 'tempmaildemo.com'
      ];
      
      if (disposableDomains.includes(domain)) {
        return { 
          valid: false, 
          message: 'Temporary email addresses are not allowed. Please use a valid work email.' 
        };
      }
      
      // Basic DNS validation as fallback
      try {
        const dns = require('dns').promises;
        const emailDomain = email.split('@')[1];
        const mxRecords = await dns.resolveMx(emailDomain);
        
        if (mxRecords && mxRecords.length > 0) {
          return { 
            valid: true, 
            message: 'Email validated successfully (fallback method)',
            domain: emailDomain,
            mxRecords: mxRecords.length,
            validationMethod: 'DNS_MX_LOOKUP_FALLBACK'
          };
        } else {
          return { 
            valid: false, 
            message: 'Invalid email domain. Please enter a valid work email.' 
          };
        }
      } catch (dnsError) {
        return { 
          valid: false, 
          message: 'Invalid email domain. Please enter a valid work email.' 
        };
      }
    }
    
  } catch (error) {
    console.error('Email validation error:', error);
    return { 
      valid: false, 
      message: 'Email validation service temporarily unavailable. Please try again later.' 
    };
  }
}

// Twilio Verify API for email verification (sends verification code)
async function sendEmailVerificationCode(email) {
  try {
    // Create a verification service if it doesn't exist
    const service = await twilioClient.verify.v2.services.create({
      friendlyName: 'InboxDoctor Email Verification'
    });
    
    // Send verification code to email
    const verification = await twilioClient.verify.v2
      .services(service.sid)
      .verifications
      .create({
        to: email,
        channel: 'email'
      });

    console.log('Email verification code sent to:', verification);
    
    return {
      success: true,
      serviceSid: service.sid,
      verificationSid: verification.sid,
      status: verification.status
    };
  } catch (error) {
    console.error('Error sending email verification code:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Verify the email verification code
async function verifyEmailCode(serviceSid, email, code) {
  try {
    const verificationCheck = await twilioClient.verify.v2
      .services(serviceSid)
      .verificationChecks
      .create({
        to: email,
        code: code
      });
    
    return {
      success: verificationCheck.status === 'approved',
      status: verificationCheck.status,
      valid: verificationCheck.valid
    };
  } catch (error) {
    console.error('Error verifying email code:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

async function validatePhoneWithTwilio(phoneNumber, countryCode) {
  try {
    // Format phone number with country code
    const formattedPhone = countryCode + phoneNumber.replace(/\D/g, '');
    
    // Use Twilio Phone Number Lookup API
    const lookup = await twilioClient.lookups.v1.phoneNumbers(formattedPhone).fetch({
      type: ['carrier']
    });

    console.log('Twilio phone number lookup:', lookup);
    
    // Check if the phone number is valid and reachable
    if (lookup.phoneNumber && lookup.carrier && lookup.carrier.type === 'mobile') {
      return { 
        valid: true, 
        message: 'Phone number validated successfully',
        carrier: lookup.carrier.name || 'Unknown',
        countryCode: lookup.countryCode || countryCode,
        nationalFormat: lookup.nationalFormat || formattedPhone
      };
    } else {
      return { 
        valid: false, 
        message: 'Invalid phone number. Please enter a valid phone number.' 
      };
    }
  } catch (error) {
    // If Twilio lookup fails, it means the phone number is invalid
    if (error.code === 20404) {
      return { 
        valid: false, 
        message: 'Invalid phone number. Please enter a valid phone number.' 
      };
    }
    
    // For other errors, log and fall back to basic validation
    console.error('Twilio phone validation error:', error);
    return { 
      valid: false, 
      message: 'Phone validation service temporarily unavailable. Please try again later.' 
    };
  }
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
async function ensureHeaderRow(spreadsheetId = SPREADSHEET_ID) {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return false;
    }

    // Check if sheet has any data
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: spreadsheetId,
      range: 'A1:Q1',
    });

    const existingData = response.data.values;
    
    // If no data exists, add header row
    if (!existingData || existingData.length === 0) {
      const headerValues = [
        ['S/Num', 'Lead ID', 'Name', 'Agency', 'Email', 'Phone', 'Score', 'Date', 'Time (IST)', 'Country', 'Lead Score Cluster', 'Lead Source', 'IP Address', 'OS & Browser', 'Lead Type', 'Email Verified', 'Phone Verified']
      ];

      await sheets.spreadsheets.values.update({
        spreadsheetId: spreadsheetId,
        range: 'A1:Q1',
        valueInputOption: 'RAW',
        resource: { values: headerValues }
      });

      console.log(`Header row added to Google Sheets: ${spreadsheetId}`);
    }

    return true;
  } catch (error) {
    console.error(`Error ensuring header row for ${spreadsheetId}:`, error);
    return false;
  }
}

async function appendLeadToSheet(leadData) {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return false;
    }

    const values = [
      [
        leadData.serialNumber, // S/Num
        leadData.leadId, // Lead ID
        leadData.first_name, // Name
        leadData.agency_name, // Agency
        leadData.email, // Email
        leadData.full_phone, // Phone
        leadData.score, // Score
        leadData.submissionDate, // Date
        leadData.istTimestamp, // Time (IST)
        leadData.country, // Country
        leadData.leadScoreCluster, // Lead Score Cluster
        leadData.leadSource, // Lead Source
        leadData.ipAddress, // IP Address
        leadData.osBrowser, // OS & Browser
        leadData.leadType, // Lead Type
        leadData.emailVerified, // Email Verified
        leadData.phoneVerified // Phone Verified
      ]
    ];

    console.log('Adding lead to Google Sheets:', values[0]);

    // Ensure header row exists for both sheets
    await ensureHeaderRow(SPREADSHEET_ID);
    await ensureHeaderRow(SPREADSHEET_ID_2);

    // Append to first sheet
    const response1 = await sheets.spreadsheets.values.append({
      spreadsheetId: SPREADSHEET_ID,
      range: RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      resource: { values }
    });

    console.log('Lead added to first Google Sheet successfully');

    // Append to second sheet
    const response2 = await sheets.spreadsheets.values.append({
      spreadsheetId: SPREADSHEET_ID_2,
      range: RANGE,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      resource: { values }
    });

    console.log('Lead added to second Google Sheet successfully');
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

async function getAllLeadsFromSheet(spreadsheetId = SPREADSHEET_ID) {
  try {
    if (!sheets) {
      console.error('Google Sheets not initialized');
      return [];
    }

    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: spreadsheetId,
      range: RANGE,
    });

    const data = response.data.values || [];
    
    // If only header row exists, return empty array
    if (data.length <= 1) {
      return [];
    }
    
    return data;
  } catch (error) {
    console.error(`Error fetching leads from Google Sheets ${spreadsheetId}:`, error);
    return [];
  }
}

async function sortLeadsByScore(spreadsheetId = SPREADSHEET_ID) {
  try {
    const leads = await getAllLeadsFromSheet(spreadsheetId);
    
    // If no leads to sort, return true
    if (leads.length === 0) {
      console.log(`No leads to sort in sheet ${spreadsheetId}`);
      return true;
    }
    
    // Skip header row if it exists
    const dataRows = leads.slice(1);
    
    // If no data rows, return true
    if (dataRows.length === 0) {
      console.log(`No data rows to sort in sheet ${spreadsheetId}`);
      return true;
    }
    
    // Sort by score (column G, index 6) in descending order
    const sortedLeads = dataRows.sort((a, b) => {
      const scoreA = parseInt(a[6]) || 0;
      const scoreB = parseInt(b[6]) || 0;
      return scoreB - scoreA;
    });
    
    // Prepare data for update (include header + sorted data)
    const headerRow = leads[0] || ['S/Num', 'Lead ID', 'Name', 'Agency', 'Email', 'Phone', 'Score', 'Date', 'Time (IST)', 'Country', 'Lead Score Cluster', 'Lead Source', 'IP Address', 'OS & Browser', 'Lead Type', 'Email Verified', 'Phone Verified'];
    const sortedData = [headerRow, ...sortedLeads];
    
    // Update the sheet with sorted data
    await sheets.spreadsheets.values.update({
      spreadsheetId: spreadsheetId,
      range: RANGE,
      valueInputOption: 'RAW',
      resource: { values: sortedData }
    });
    
    console.log(`Leads sorted by score in sheet ${spreadsheetId}`);
    return true;
  } catch (error) {
    console.error(`Error sorting leads in sheet ${spreadsheetId}:`, error);
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

Serial Number: ${formData.serialNumber}
Lead ID: ${formData.leadId}
First Name: ${first_name}
Agency Name: ${agency_name}
Work Email: ${email}
Email Verified: ${formData.emailVerified}
Email Domain: ${formData.emailDomain}
Email Validation Method: ${formData.emailValidationMethod}
Phone: ${full_phone}
Phone Verified: ${formData.phoneVerified}
Country: ${formData.country}
Lead Score: ${formData.score}/100
Lead Score Cluster: ${formData.leadScoreCluster}
Lead Source: ${formData.leadSource}
IP Address: ${formData.ipAddress}
OS & Browser: ${formData.osBrowser}
Lead Type: ${formData.leadType}
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

// Background processing function for lead data
async function processLeadInBackground(data) {
  try {
    const {
      first_name,
      agency_name,
      email,
      country_code,
      phone,
      full_phone,
      submissionDate,
      istTimestamp,
      country,
      leadId,
      serialNumber,
      clientInfo,
      osBrowser,
      emailValidation,
      phoneValidation
    } = data;

    // Calculate lead score in background
    const leadScore = calculateLeadScore({
      first_name,
      agency_name,
      business_email: email,
      country_code,
      phone
    });

    // Get lead score cluster
    const leadScoreCluster = getLeadScoreCluster(leadScore);

    // Prepare form data with score and validation info
    const formData = {
      serialNumber,
      leadId,
      first_name,
      agency_name,
      email,
      full_phone: full_phone,
      submissionDate,
      istTimestamp,
      country: phoneValidation.countryCode || country,
      score: leadScore,
      leadScoreCluster,
      leadSource: LEAD_SOURCE,
      ipAddress: clientInfo.ip,
      osBrowser,
      leadType: 'New', // Since we already checked for duplicates
      emailDomain: emailValidation.domain || email.split('@')[1],
      emailValidationMethod: emailValidation.validationMethod || 'BASIC',
      emailVerified: emailValidation.valid ? 'Yes' : 'No',
      phoneVerified: phoneValidation.valid ? 'Yes' : 'No'
    };

    // Run email sending, Redis storage, and Google Sheets operations in parallel
    const [emailSent, , sheetAdded] = await Promise.all([
      // Send email
      sendEmail(formData),
      
      // Store email and phone in Redis to prevent duplicates (run in parallel)
      Promise.all([
        storeEmail(email, submissionDate),
        redisClient.setex(`phone:${phone}`, 86400, 'submitted') // 24 hours
      ]),
      
      // Add lead to Google Sheets with score
      appendLeadToSheet(formData)
    ]);

    // Log email sending result
    if (!emailSent) {
      console.error('Failed to send email for lead:', leadId);
    }

    // Sort leads by score after adding new lead (only if sheet was updated)
    if (sheetAdded) {
      // Run sorting operations in parallel for both sheets (after adding is complete)
      await Promise.all([
        sortLeadsByScore(SPREADSHEET_ID),
        sortLeadsByScore(SPREADSHEET_ID_2)
      ]);
    }

    console.log(`Lead ${leadId} processed successfully in background`);

  } catch (error) {
    console.error('Error processing lead in background:', error);
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
    // Format date as DD/MM/YYYY
    const now = new Date();
    const day = now.getDate().toString().padStart(2, '0');
    const month = (now.getMonth() + 1).toString().padStart(2, '0');
    const year = now.getFullYear();
    const submissionDate = `${day}/${month}/${year}`; // DD/MM/YYYY format
    const istTimestamp = getISTTimestamp();
    const country = getCountryFromExtension(country_code);
    
    // Generate Lead ID and get client info
    const leadId = generateLeadId();
    const clientInfo = getClientInfo(req);
    const osBrowser = `${clientInfo.os} - ${clientInfo.browser}`;
    
    // Get next serial number (in production, this should be stored in Redis)
    const serialNumber = leadIdCounter;

    // Run critical validations in parallel for fast response
    const [
      emailValidation,
      phoneValidation,
      isDuplicate
    ] = await Promise.all([
      // Email validation (both Twilio and basic)
      validateEmailWithTwilio(email).then(async (twilioResult) => {
        if (!twilioResult.valid) {
          return twilioResult;
        }
        const basicResult = validateEmail(email);
        if (!basicResult.valid) {
          return basicResult;
        }
        return twilioResult;
      }),
      
      // Phone validation (both Twilio and basic)
      validatePhoneWithTwilio(phone, country_code).then(async (twilioResult) => {
        if (!twilioResult.valid) {
          return twilioResult;
        }
        const basicResult = validatePhone(phone);
        if (!basicResult.valid) {
          return basicResult;
        }
        return twilioResult;
      }),
      
      // Duplicate check
      checkLeadDuplicate(email, phone)
    ]);

    // Check validation results - return immediately if invalid
    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message
      });
    }

    if (!phoneValidation.valid) {
      return res.status(400).json({
        success: false,
        message: phoneValidation.message
      });
    }

    // Check for duplicates - return immediately if duplicate
    if (isDuplicate) {
      return res.status(400).json({
        success: false,
        message: 'Lead already exists (duplicate email or phone). Please use different contact information.'
      });
    }

    // Return success response immediately after critical validations pass
    res.json({
      success: true,
      redirectUrl: 'https://calendly.com/inboxdoctor-sales/inboxdoctor-product-demolp',
      message: 'Form submitted successfully! Redirecting to calendar...'
    });

    // Continue processing in background (don't await these)
    processLeadInBackground({
      first_name,
      agency_name,
      email,
      country_code,
      phone,
      full_phone,
      submissionDate,
      istTimestamp,
      country,
      leadId,
      serialNumber,
      clientInfo,
      osBrowser,
      emailValidation,
      phoneValidation
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

// Admin endpoint to get all leads from second sheet
app.get('/admin/leads2', async (req, res) => {
  try {
    const leads = await getAllLeadsFromSheet(SPREADSHEET_ID_2);
    res.json({ leads });
  } catch (error) {
    console.error('Error fetching leads from second sheet:', error);
    res.status(500).json({ error: 'Failed to fetch leads from second sheet' });
  }
});

// Admin endpoint to sort leads by score
app.post('/admin/sort-leads', async (req, res) => {
  try {
    const sorted1 = await sortLeadsByScore(SPREADSHEET_ID);
    const sorted2 = await sortLeadsByScore(SPREADSHEET_ID_2);
    const success = sorted1 && sorted2;
    res.json({ 
      success, 
      message: success ? 'Leads sorted successfully in both sheets' : 'Failed to sort leads in one or both sheets',
      sheet1: sorted1,
      sheet2: sorted2
    });
  } catch (error) {
    console.error('Error sorting leads:', error);
    res.status(500).json({ error: 'Failed to sort leads' });
  }
});

// Email verification endpoints
app.post('/verify-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    // First validate email format and domain
    const emailValidation = await validateEmailWithTwilio(email);
    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message
      });
    }
    
    // Send verification code
    const verificationResult = await sendEmailVerificationCode(email);
    
    if (verificationResult.success) {
      res.json({
        success: true,
        message: 'Verification code sent to your email',
        serviceSid: verificationResult.serviceSid
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to send verification code. Please try again later.'
      });
    }
  } catch (error) {
    console.error('Error in email verification:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

app.post('/confirm-email', async (req, res) => {
  try {
    const { email, code, serviceSid } = req.body;
    
    if (!email || !code || !serviceSid) {
      return res.status(400).json({
        success: false,
        message: 'Email, code, and serviceSid are required'
      });
    }
    
    const verificationResult = await verifyEmailCode(serviceSid, email, code);
    
    if (verificationResult.success) {
      res.json({
        success: true,
        message: 'Email verified successfully',
        verified: true
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Invalid verification code. Please try again.',
        verified: false
      });
    }
  } catch (error) {
    console.error('Error in email confirmation:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

// Admin endpoint to set up lead cluster dropdown
app.post('/admin/setup-dropdown', async (req, res) => {
  try {
    if (!sheets) {
      return res.status(500).json({ error: 'Google Sheets not initialized' });
    }

    // Set up data validation for Lead Score Cluster and Lead Type columns
    const request = {
      requests: [
        {
          setDataValidation: {
            range: {
              sheetId: 0, // First sheet
              startRowIndex: 1, // Start from row 2 (skip header)
              endRowIndex: 1000, // Apply to 1000 rows
              startColumnIndex: 10, // Column K (Lead Score Cluster)
              endColumnIndex: 11
            },
            rule: {
              condition: {
                type: 'ONE_OF_LIST',
                values: [
                  { userEnteredValue: '0–20 → Cold Leads ❄️' },
                  { userEnteredValue: '21–40 → Low-Intent Leads 🌙' },
                  { userEnteredValue: '41–60 → Warm Leads 🔥' },
                  { userEnteredValue: '61–80 → Qualified Leads 🚀' },
                  { userEnteredValue: '81–100 → Hot Leads 🔥🔥' }
                ]
              },
              showCustomUi: true,
              strict: false
            }
          }
        },
        {
          setDataValidation: {
            range: {
              sheetId: 0, // First sheet
              startRowIndex: 1, // Start from row 2 (skip header)
              endRowIndex: 1000, // Apply to 1000 rows
              startColumnIndex: 14, // Column O (Lead Type)
              endColumnIndex: 15
            },
            rule: {
              condition: {
                type: 'ONE_OF_LIST',
                values: [
                  { userEnteredValue: 'New' },
                  { userEnteredValue: 'Duplicate' }
                ]
              },
              showCustomUi: true,
              strict: false
            }
          }
        }
      ]
    };

    // Set up dropdowns for both sheets
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: request
    });

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID_2,
      resource: request
    });
    
    res.json({ success: true, message: 'Lead Score Cluster dropdown set up successfully in both sheets' });
  } catch (error) {
    console.error('Error setting up dropdown:', error);
    res.status(500).json({ error: 'Failed to set up dropdown' });
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
