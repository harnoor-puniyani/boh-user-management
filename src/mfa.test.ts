import request from 'supertest';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sql from 'mssql';
import { authenticator } from 'otplib';
import mfaRouter from './mfa';
import * as globals from './globals';

// Mock dependencies
jest.mock('mssql');
jest.mock('./globals');
jest.mock('otplib');
jest.mock('bcryptjs');
jest.mock('qrcode');
jest.mock('@azure/service-bus');

describe('MFA API Tests', () => {
  let app: Express;
  let mockConnection: any;
  let mockRequest: any;

  beforeEach(() => {
    // Create express app with mfa router
    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use('/mfa', mfaRouter);

    // Mock SQL connection
    mockConnection = {
      close: jest.fn(),
    };

    mockRequest = {
      input: jest.fn().mockReturnThis(),
      query: jest.fn(),
    };

    (globals.dbconnect as jest.Mock).mockResolvedValue(mockConnection);
    (globals.dbdisconnect as jest.Mock).mockResolvedValue(undefined);
    (sql.Request as any) = jest.fn(() => mockRequest);

    // Set environment variables
    process.env.JWT_SECRET = 'test-secret-key';
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Helper function to create MFA token
  const createMfaToken = (scope: string, userId: string = '123', email: string = 'test@example.com') => {
    return jwt.sign(
      { userId, email, Role: 'user', scope },
      'test-secret-key',
      { expiresIn: '1h' }
    );
  };

  describe('POST /mfa/verify - Positive Tests', () => {
    it('should successfully verify TOTP code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'TOTP',
        MFASecret: 'test-secret',
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      (authenticator.check as jest.Mock).mockReturnValue(true);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toBe('Login successful.');
    });

    it('should successfully verify SMS OTP code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'SMS',
        MFASecret: null,
      };

      const mockOtpRecord = {
        OTPHash: 'hashed_otp',
        ExpiresAt: new Date(Date.now() + 60000).toISOString(),
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [mockOtpRecord] })
        .mockResolvedValueOnce({ recordset: [] }); // Delete query

      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful.');
    });

    it('should successfully verify EMAIL OTP code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'EMAIL',
        MFASecret: null,
      };

      const mockOtpRecord = {
        OTPHash: 'hashed_otp',
        ExpiresAt: new Date(Date.now() + 60000).toISOString(),
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [mockOtpRecord] })
        .mockResolvedValueOnce({ recordset: [] });

      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(200);
    });

    it('should set final JWT cookie on successful verification', async () => {
      const mockUser = {
        Role: 'admin',
        MFAMethod: 'TOTP',
        MFASecret: 'test-secret',
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      (authenticator.check as jest.Mock).mockReturnValue(true);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Login successful.');
      expect(response.headers['set-cookie']).toBeDefined();
    });
  });

  describe('POST /mfa/verify - Negative Tests', () => {
    it('should return 401 if no token is provided', async () => {
      const response = await request(app)
        .post('/mfa/verify')
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('No token provided');
    });

    it('should return 400 if OTP code is missing', async () => {
      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toBe('OTP code is required.');
    });

    it('should return 404 if user not found', async () => {
      mockRequest.query.mockResolvedValueOnce({
        recordset: [],
      });

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('User not found.');
    });

    it('should return 401 for invalid TOTP code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'TOTP',
        MFASecret: 'test-secret',
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      (authenticator.check as jest.Mock).mockReturnValue(false);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '999999',
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid OTP code.');
    });

    it('should return 400 if SMS OTP has expired', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'SMS',
        MFASecret: null,
      };

      const mockOtpRecord = {
        OTPHash: 'hashed_otp',
        ExpiresAt: new Date(Date.now() - 60000).toISOString(), // Expired
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [mockOtpRecord] });

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Your OTP has expired.');
    });

    it('should return 400 if no OTP record found for SMS/EMAIL', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'SMS',
        MFASecret: null,
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [] });

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('No OTP found. Please try again.');
    });

    it('should return 401 for incorrect SMS/EMAIL OTP code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'EMAIL',
        MFASecret: null,
      };

      const mockOtpRecord = {
        OTPHash: 'hashed_otp',
        ExpiresAt: new Date(Date.now() + 60000).toISOString(),
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [mockOtpRecord] });

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '999999',
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid OTP code.');
    });

    it('should return 400 if TOTP is not configured properly', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: 'TOTP',
        MFASecret: null, // No secret configured
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('TOTP is not configured correctly.');
    });

    it('should return 400 if no MFA method is enabled', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: null,
        MFASecret: null,
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      const token = createMfaToken('mfa-verify');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('No MFA method is enabled for this user.');
    });

    it('should return 403 if token has invalid scope', async () => {
      const token = createMfaToken('invalid-scope');

      const response = await request(app)
        .post('/mfa/verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('Invalid token scope');
    });
  });

  describe('POST /mfa/setup - Positive Tests', () => {
    it('should successfully setup Mobile MFA', async () => {
      mockRequest.query.mockResolvedValueOnce({
        recordset: [],
      });

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'Mobile',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toContain('Mobile');
    });

    it('should successfully setup Email MFA', async () => {
      mockRequest.query.mockResolvedValueOnce({
        recordset: [],
      });

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'Email',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toContain('Email');
    });

    it('should successfully setup TOTP and return QR code', async () => {
      (authenticator.generateSecret as jest.Mock).mockReturnValue('TESTSECRET123');
      (authenticator.keyuri as jest.Mock).mockReturnValue('otpauth://totp/test');

      const qrcode = require('qrcode');
      qrcode.toDataURL = jest.fn().mockResolvedValue('data:image/png;base64,TEST');

      mockRequest.query.mockResolvedValueOnce({
        recordset: [],
      });

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'TOTP',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('qrCode');
      expect(response.body.mfaMethod).toBe('TOTP');
      expect(response.body.message).toContain('scan the QR code');
    });
  });

  describe('POST /mfa/setup - Negative Tests', () => {
    it('should return 401 if no token is provided', async () => {
      const response = await request(app)
        .post('/mfa/setup')
        .send({
          mfaMethod: 'TOTP',
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toContain('No token provided');
    });

    it('should return 401 for invalid user token', async () => {
      const token = jwt.sign(
        { email: 'test@example.com', scope: 'mfa-register' }, // Missing userId
        'test-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'TOTP',
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid user token.');
    });

    it('should return 400 for invalid mfaMethod', async () => {
      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'INVALID',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Invalid mfaMethod');
    });

    it('should return 403 if token has invalid scope', async () => {
      const token = createMfaToken('invalid-scope'); // Invalid scope

      const response = await request(app)
        .post('/mfa/setup')
        .set('Cookie', [`token=${token}`])
        .send({
          mfaMethod: 'TOTP',
        });

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('Invalid token scope');
    });
  });

  describe('POST /mfa/setup-verify - Positive Tests', () => {
    it('should successfully verify TOTP setup', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: null,
        MFASecret: 'test-secret',
      };

      mockRequest.query
        .mockResolvedValueOnce({ recordset: [mockUser] })
        .mockResolvedValueOnce({ recordset: [] });

      (authenticator.check as jest.Mock).mockReturnValue(true);

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup-verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('successfully registered');
    });
  });

  describe('POST /mfa/setup-verify - Negative Tests', () => {
    it('should return 401 if no token is provided', async () => {
      const response = await request(app)
        .post('/mfa/setup-verify')
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(401);
    });

    it('should return 404 if user not found', async () => {
      mockRequest.query.mockResolvedValueOnce({
        recordset: [],
      });

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup-verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('User not found.');
    });

    it('should return 400 for incorrect verification code', async () => {
      const mockUser = {
        Role: 'user',
        MFAMethod: null,
        MFASecret: 'test-secret',
      };

      mockRequest.query.mockResolvedValueOnce({
        recordset: [mockUser],
      });

      (authenticator.check as jest.Mock).mockReturnValue(false);

      const token = createMfaToken('mfa-register');

      const response = await request(app)
        .post('/mfa/setup-verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '999999',
        });

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('registration verification failed pls try again');
    });

    it('should return 401 for invalid user token', async () => {
      const token = jwt.sign(
        { email: 'test@example.com', scope: 'mfa-register' }, // Missing userId
        'test-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .post('/mfa/setup-verify')
        .set('Cookie', [`token=${token}`])
        .send({
          otpCode: '123456',
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Invalid user token.');
    });
  });
});
