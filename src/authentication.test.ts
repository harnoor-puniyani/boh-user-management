import request from 'supertest';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import sql from 'mssql';
import authRouter from './authentication';
import * as globals from './globals';

// Mock dependencies
jest.mock('mssql');
jest.mock('./globals');
jest.mock('argon2');

describe('Authentication API Tests', () => {
  let app: Express;
  let mockConnection: any;
  let mockRequest: any;

  beforeEach(() => {
    // Create express app with auth router
    app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use('/auth', authRouter);

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

    // Set JWT secret for tests
    process.env.JWT_SECRET = 'test-secret-key';
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/login - Positive Tests', () => {
    it('should successfully login with valid email and password', async () => {
      const mockUser = {
        UserID: '123',
        Email: 'test@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'user',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.UserID).toBe('123');
      expect(response.body.user.Email).toBe('test@example.com');
    });

    it('should successfully login with valid phone number and password', async () => {
      const mockUser = {
        UserID: '456',
        Email: 'user@example.com',
        PhoneNumber: '+9876543210',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'user',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          PhoneNumber: '+9876543210',
          password: 'password123',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body.user.PhoneNumber).toBe('+9876543210');
    });

    it('should set csrf-token cookie on successful login', async () => {
      const mockUser = {
        UserID: '789',
        Email: 'csrf@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'user',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'csrf@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeDefined();
      const cookies = response.headers['set-cookie'] as string[] | string;
      const cookieArray = Array.isArray(cookies) ? cookies : [cookies];
      expect(cookieArray.some((cookie: string) => cookie.includes('csrf-token'))).toBe(true);
    });

    it('should handle user with MFA enabled (TOTP)', async () => {
      const mockUser = {
        UserID: '999',
        Email: 'mfa@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'user',
        MFAMethod: 'TOTP',
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'mfa@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(200);
      expect(response.body.user.MFAMethod).toBe('TOTP');
      expect(response.body).toHaveProperty('token');
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should handle admin user login', async () => {
      const mockUser = {
        UserID: '111',
        Email: 'admin@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'admin',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'admin@example.com',
          password: 'adminpass',
        });

      expect(response.status).toBe(200);
      expect(response.body.user.Role).toBe('admin');
    });
  });

  describe('POST /auth/login - Negative Tests', () => {
    it('should return 400 if email/phone and password are missing', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toContain('Email or PhoneNumber and password required');
    });

    it('should return 400 if only email is provided without password', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'test@example.com',
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
    });

    it('should return 400 if only password is provided without email/phone', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          password: 'password123',
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
    });

    it('should return 401 for non-existent user', async () => {
      mockRequest.query.mockResolvedValue({
        recordset: [],
      });

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'nonexistent@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return 401 for incorrect password', async () => {
      const mockUser = {
        UserID: '123',
        Email: 'test@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: true,
        Role: 'user',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(false);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'test@example.com',
          password: 'wrongpassword',
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return 403 for inactive user', async () => {
      const mockUser = {
        UserID: '123',
        Email: 'inactive@example.com',
        PhoneNumber: '+1234567890',
        PasswordHash: 'hashed_password',
        IsActive: false,
        Role: 'user',
        MFAMethod: null,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'inactive@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('User not active');
    });

    it('should return 500 for database connection errors', async () => {
      (globals.dbconnect as jest.Mock).mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error');
    });

    it('should return 500 for database query errors', async () => {
      mockRequest.query.mockRejectedValue(new Error('Query failed'));

      const response = await request(app)
        .post('/auth/login')
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error');
    });
  });

  describe('JWT Verification Middleware Tests', () => {
    it('should return 401 if no token is provided', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(cookieParser());
      
      const { verifyJWT } = require('./authentication');
      testApp.get('/protected', verifyJWT, (req, res) => {
        res.status(200).json({ message: 'success' });
      });

      const response = await request(testApp).get('/protected');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('No token provided');
    });

    it('should return 401 for invalid token', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(cookieParser());
      
      const { verifyJWT } = require('./authentication');
      testApp.get('/protected', verifyJWT, (req, res) => {
        res.status(200).json({ message: 'success' });
      });

      const response = await request(testApp)
        .get('/protected')
        .set('Cookie', ['token=invalid_token']);

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Invalid token');
    });

    it('should allow access with valid token', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(cookieParser());
      
      const { verifyJWT } = require('./authentication');
      testApp.get('/protected', verifyJWT, (req, res) => {
        res.status(200).json({ message: 'success' });
      });

      const token = jwt.sign(
        { userId: '123', email: 'test@example.com', Role: 'user' },
        'test-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/protected')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('success');
    });
  });

  describe('Admin Check Middleware Tests', () => {
    it('should allow access for admin users', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(cookieParser());
      
      const { verifyJWT, checkAdmin } = require('./authentication');
      testApp.get('/admin', verifyJWT, checkAdmin, (req, res) => {
        res.status(200).json({ message: 'admin access granted' });
      });

      const token = jwt.sign(
        { userId: '123', email: 'admin@example.com', Role: 'admin' },
        'test-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/admin')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('admin access granted');
    });

    it('should deny access for non-admin users', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.use(cookieParser());
      
      const { verifyJWT, checkAdmin } = require('./authentication');
      testApp.get('/admin', verifyJWT, checkAdmin, (req, res) => {
        res.status(200).json({ message: 'admin access granted' });
      });

      const token = jwt.sign(
        { userId: '123', email: 'user@example.com', Role: 'user' },
        'test-secret-key',
        { expiresIn: '1h' }
      );

      const response = await request(testApp)
        .get('/admin')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(403);
      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('Admin access required');
    });
  });
});
