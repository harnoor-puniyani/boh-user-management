import request from 'supertest';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import sql from 'mssql';
import * as globals from './globals';

// Mock dependencies
jest.mock('mssql');
jest.mock('./globals');
jest.mock('argon2');
jest.mock('./authentication');
jest.mock('./mfa');

describe('User Management API Tests', () => {
  let app: Express;
  let mockConnection: any;
  let mockRequest: any;
  let mockTransaction: any;

  const createValidToken = (role: string = 'user') => {
    return jwt.sign(
      { userId: '123', email: 'test@example.com', Role: role },
      'test-secret-key',
      { expiresIn: '1h' }
    );
  };

  beforeEach(() => {
    // Create express app
    app = express();
    app.use(express.json()).use(cookieParser());

    // Mock authentication middleware
    const authMock = require('./authentication');
    authMock.default = express.Router();
    authMock.verifyJWT = jest.fn((req, res, next) => {
      const token = req.cookies.token;
      if (!token) {
        return res.status(401).json({ message: 'No token provided' });
      }
      try {
        req.user = jwt.verify(token, 'test-secret-key');
        next();
      } catch (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }
    });
    authMock.checkAdmin = jest.fn((req, res, next) => {
      if (req.user && req.user.Role === 'admin') {
        next();
      } else {
        return res.status(403).json({ message: 'Admin access required' });
      }
    });

    // Mock MFA middleware
    const mfaMock = require('./mfa');
    mfaMock.default = express.Router();

    // Setup CSRF middleware
    const protectWithCSRF = (req: any, res: any, next: any) => {
      if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
      }
      const csrfFromHeader = req.headers['x-csrf-token'];
      const csrfFromCookie = req.cookies['csrf-token'];
      if (!csrfFromHeader || !csrfFromCookie || csrfFromHeader !== csrfFromCookie) {
        return res.status(403).json({ message: 'Invalid or missing CSRF token.' });
      }
      next();
    };

    // Mock SQL connection
    mockConnection = {
      close: jest.fn(),
    };

    mockRequest = {
      input: jest.fn().mockReturnThis(),
      query: jest.fn(),
    };

    mockTransaction = {
      begin: jest.fn().mockResolvedValue(mockTransaction),
      commit: jest.fn().mockResolvedValue(undefined),
      rollback: jest.fn().mockResolvedValue(undefined),
    };

    (globals.dbconnect as jest.Mock).mockResolvedValue(mockConnection);
    (globals.dbdisconnect as jest.Mock).mockResolvedValue(undefined);
    (globals.connected as any) = true;
    (globals.schema as any) = 'user';
    (sql.Request as any) = jest.fn((conn) => mockRequest);
    (sql.Transaction as any) = jest.fn(() => mockTransaction);

    // Setup routes
    app.get(
      ['/users/:id', '/userProfile/:id', '/address/:id'],
      authMock.verifyJWT,
      protectWithCSRF,
      async (req: any, res: any) => {
        let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
        try {
          switch (true) {
            case req.path.startsWith('/users/'):
              if (globals.connected && req.params.id != null) {
                await new sql.Request(sqlconnection)
                  .query(`Select UserID,Email,PhoneNumber,IsActive from [user].Users where UserID='${req.params.id}'`)
                  .then((result) => {
                    res.status(200).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(404).json(err);
                  });
              }
              break;
            case req.path.startsWith('/userProfile'):
              if (globals.connected && req.params.id != null) {
                await new sql.Request(sqlconnection)
                  .query(`Select * from [user].UserProfiles where UserID = '${req.params.id}'`)
                  .then((result) => {
                    res.status(200).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(400).json(err);
                  });
              }
              break;
            case req.path.startsWith('/address'):
              if (globals.connected && req.params.id != null) {
                await new sql.Request(sqlconnection)
                  .query(`Select * from [user].Addresses where UserID = '${req.params.id}'`)
                  .then((result) => {
                    res.status(200).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(400).json(err);
                  });
              }
              break;
          }
        } catch (error) {
          res.status(500).json(error);
        } finally {
          await globals.dbdisconnect(sqlconnection);
        }
      }
    );

    app.post(
      ['/users', '/userProfile', '/address'],
      authMock.verifyJWT,
      protectWithCSRF,
      async (req: any, res: any) => {
        let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
        try {
          switch (true) {
            case req.path.startsWith('/users'):
              if (globals.connected && req.body.UserID == null) {
                const hashedPassword = await argon2.hash(req.body.password);
                await new sql.Request(sqlconnection)
                  .input('Email', sql.NVarChar, req.body.Email)
                  .input('PhoneNumber', sql.NVarChar, req.body.PhoneNumber)
                  .input('IsActive', sql.Bit, req.body.IsActive)
                  .input('PasswordHash', hashedPassword)
                  .query(`INSERT INTO [user].[Users] (Email, PhoneNumber, IsActive,PasswordHash) VALUES (@Email, @PhoneNumber, @IsActive,@PasswordHash)`)
                  .then((result) => {
                    res.status(202).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(403).json(err);
                  });
              }
              break;
            case req.path.startsWith('/userProfile'):
              if (globals.connected && req.body.UserID != null) {
                await new sql.Request(sqlconnection)
                  .query(`INSERT INTO [user].[UserProfiles] (DateOfBirth,FirstName,LastName,UserID,UserProfileID,KYCStatus) VALUES (...)`)
                  .then((result) => {
                    res.status(200).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(404).json(err);
                  });
              }
              break;
            case req.path.startsWith('/address'):
              if (globals.connected && req.body.UserID != null) {
                await new sql.Request(sqlconnection)
                  .query(`INSERT INTO [user].[Addresses] (...) VALUES (...)`)
                  .then((result) => {
                    res.status(200).json({ value: result.recordset });
                  })
                  .catch((err) => {
                    res.status(200).json(err);
                  });
              }
              break;
          }
        } catch (error) {
          res.status(505).json(error);
        }
      }
    );

    app.get(
      ['/development/:id'],
      authMock.verifyJWT,
      protectWithCSRF,
      authMock.checkAdmin,
      async (req: any, res: any) => {
        let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
        try {
          const table = req.path.split('/development/');
          await new sql.Request(sqlconnection)
            .query(`Select * from [user].${table[1]}`)
            .then((result) => {
              res.status(200).json({ body: result.recordset });
            })
            .catch((err) => {
              res.status(500).json(err);
            });
        } catch (err) {
          res.status(500).json({ error: err });
        } finally {
          await globals.dbdisconnect(sqlconnection);
        }
      }
    );

    app.post('/new', async (req: any, res: any) => {
      let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
      let transaction = await new sql.Transaction(sqlconnection).begin();
      try {
        if (globals.connected && req.body.user.UserID == null) {
          const hashedPassword = await argon2.hash(req.body.user.password);
          let userRequest = await new sql.Request(transaction)
            .input('Email', sql.NVarChar, req.body.user.Email)
            .input('PhoneNumber', sql.NVarChar, req.body.user.PhoneNumber)
            .input('IsActive', sql.Bit, req.body.user.IsActive)
            .input('PasswordHash', hashedPassword)
            .query(`INSERT INTO [user].[Users] (Email, PhoneNumber, IsActive,PasswordHash) OUTPUT inserted.UserID VALUES (@Email, @PhoneNumber, @IsActive,@PasswordHash)`);

          const userID = userRequest.recordset[0].UserID;
          await transaction.commit();
          res.status(200).json({ value: userID });
        } else {
          res.sendStatus(500);
        }
      } catch (error) {
        await transaction.rollback();
        res.status(500).json({ error: error, message: 'transaction rollbacked' });
      }
    });

    process.env.JWT_SECRET = 'test-secret-key';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /users/:id - Positive Tests', () => {
    it('should get user details with valid ID', async () => {
      const mockUser = {
        UserID: '123',
        Email: 'test@example.com',
        PhoneNumber: '+1234567890',
        IsActive: true,
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockUser],
      });

      const token = createValidToken();

      const response = await request(app)
        .get('/users/123')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('value');
      expect(response.body.value[0].UserID).toBe('123');
    });
  });

  describe('GET /users/:id - Negative Tests', () => {
    it('should return 401 without authentication token', async () => {
      const response = await request(app).get('/users/123');

      expect(response.status).toBe(401);
    });

    it('should return 404 when user not found', async () => {
      mockRequest.query.mockRejectedValue(new Error('User not found'));

      const token = createValidToken();

      const response = await request(app)
        .get('/users/999')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(404);
    });

    it('should return 500 for database errors', async () => {
      (globals.dbconnect as jest.Mock).mockRejectedValue(new Error('DB connection failed'));

      const token = createValidToken();

      const response = await request(app)
        .get('/users/123')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(500);
    });
  });

  describe('GET /userProfile/:id - Positive Tests', () => {
    it('should get user profile with valid ID', async () => {
      const mockProfile = {
        UserProfileID: '1',
        UserID: '123',
        FirstName: 'John',
        LastName: 'Doe',
        DateOfBirth: '1990-01-01',
        KYCStatus: 'Approved',
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockProfile],
      });

      const token = createValidToken();

      const response = await request(app)
        .get('/userProfile/123')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body.value[0].FirstName).toBe('John');
    });
  });

  describe('GET /userProfile/:id - Negative Tests', () => {
    it('should return 401 without authentication', async () => {
      const response = await request(app).get('/userProfile/123');

      expect(response.status).toBe(401);
    });

    it('should return 400 when profile not found', async () => {
      mockRequest.query.mockRejectedValue(new Error('Profile not found'));

      const token = createValidToken();

      const response = await request(app)
        .get('/userProfile/999')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(400);
    });
  });

  describe('GET /address/:id - Positive Tests', () => {
    it('should get user address with valid ID', async () => {
      const mockAddress = {
        AddressID: '1',
        UserID: '123',
        AddressLine1: '123 Main St',
        City: 'New York',
        State: 'NY',
        PostalCode: '10001',
        Country: 'USA',
      };

      mockRequest.query.mockResolvedValue({
        recordset: [mockAddress],
      });

      const token = createValidToken();

      const response = await request(app)
        .get('/address/123')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body.value[0].City).toBe('New York');
    });
  });

  describe('GET /address/:id - Negative Tests', () => {
    it('should return 401 without authentication', async () => {
      const response = await request(app).get('/address/123');

      expect(response.status).toBe(401);
    });

    it('should return 400 when address not found', async () => {
      mockRequest.query.mockRejectedValue(new Error('Address not found'));

      const token = createValidToken();

      const response = await request(app)
        .get('/address/999')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(400);
    });
  });

  describe('POST /users - Positive Tests', () => {
    it('should create new user with valid data', async () => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed_password');
      mockRequest.query.mockResolvedValue({ recordset: [] });

      const token = createValidToken();
      const csrfToken = 'test-csrf-token';

      const response = await request(app)
        .post('/users')
        .set('Cookie', [`token=${token}`, `csrf-token=${csrfToken}`])
        .set('x-csrf-token', csrfToken)
        .send({
          Email: 'newuser@example.com',
          PhoneNumber: '+1234567890',
          IsActive: true,
          password: 'password123',
        });

      expect(response.status).toBe(202);
    });
  });

  describe('POST /users - Negative Tests', () => {
    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .post('/users')
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(401);
    });

    it('should return 403 without CSRF token', async () => {
      const token = createValidToken();

      const response = await request(app)
        .post('/users')
        .set('Cookie', [`token=${token}`])
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('CSRF token');
    });

    it('should return 403 with mismatched CSRF tokens', async () => {
      const token = createValidToken();

      const response = await request(app)
        .post('/users')
        .set('Cookie', [`token=${token}`, 'csrf-token=cookie-token'])
        .set('x-csrf-token', 'different-header-token')
        .send({
          Email: 'test@example.com',
          password: 'password123',
        });

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('CSRF token');
    });

    it('should return 403 when database insert fails', async () => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed_password');
      mockRequest.query.mockRejectedValue(new Error('Insert failed'));

      const token = createValidToken();
      const csrfToken = 'test-csrf-token';

      const response = await request(app)
        .post('/users')
        .set('Cookie', [`token=${token}`, `csrf-token=${csrfToken}`])
        .set('x-csrf-token', csrfToken)
        .send({
          Email: 'test@example.com',
          PhoneNumber: '+1234567890',
          IsActive: true,
          password: 'password123',
        });

      expect(response.status).toBe(403);
    });
  });

  describe('POST /userProfile - Positive Tests', () => {
    it('should create user profile with valid data', async () => {
      mockRequest.query.mockResolvedValue({ recordset: [] });

      const token = createValidToken();
      const csrfToken = 'test-csrf-token';

      const response = await request(app)
        .post('/userProfile')
        .set('Cookie', [`token=${token}`, `csrf-token=${csrfToken}`])
        .set('x-csrf-token', csrfToken)
        .send({
          UserID: '123',
          FirstName: 'John',
          LastName: 'Doe',
          DateOfBirth: '1990-01-01',
          KYCStatus: 'Pending',
        });

      expect(response.status).toBe(200);
    });
  });

  describe('POST /userProfile - Negative Tests', () => {
    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .post('/userProfile')
        .send({
          UserID: '123',
          FirstName: 'John',
        });

      expect(response.status).toBe(401);
    });

    it('should return 403 without CSRF token', async () => {
      const token = createValidToken();

      const response = await request(app)
        .post('/userProfile')
        .set('Cookie', [`token=${token}`])
        .send({
          UserID: '123',
          FirstName: 'John',
        });

      expect(response.status).toBe(403);
    });
  });

  describe('POST /address - Positive Tests', () => {
    it('should create address with valid data', async () => {
      mockRequest.query.mockResolvedValue({ recordset: [] });

      const token = createValidToken();
      const csrfToken = 'test-csrf-token';

      const response = await request(app)
        .post('/address')
        .set('Cookie', [`token=${token}`, `csrf-token=${csrfToken}`])
        .set('x-csrf-token', csrfToken)
        .send({
          UserID: '123',
          AddressLine1: '123 Main St',
          City: 'New York',
          State: 'NY',
          PostalCode: '10001',
          Country: 'USA',
        });

      expect(response.status).toBe(200);
    });
  });

  describe('POST /address - Negative Tests', () => {
    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .post('/address')
        .send({
          UserID: '123',
          AddressLine1: '123 Main St',
        });

      expect(response.status).toBe(401);
    });
  });

  describe('GET /development/:id - Positive Tests', () => {
    it('should allow admin to access development endpoint', async () => {
      mockRequest.query.mockResolvedValue({
        recordset: [{ id: 1, data: 'test' }],
      });

      const token = createValidToken('admin');

      const response = await request(app)
        .get('/development/Users')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('body');
    });
  });

  describe('GET /development/:id - Negative Tests', () => {
    it('should deny access to non-admin users', async () => {
      const token = createValidToken('user');

      const response = await request(app)
        .get('/development/Users')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(403);
      expect(response.body.message).toContain('Admin access required');
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app).get('/development/Users');

      expect(response.status).toBe(401);
    });

    it('should return 500 for database errors', async () => {
      mockRequest.query.mockRejectedValue(new Error('Query failed'));

      const token = createValidToken('admin');

      const response = await request(app)
        .get('/development/Users')
        .set('Cookie', [`token=${token}`]);

      expect(response.status).toBe(500);
    });
  });

  describe('POST /new - Positive Tests', () => {
    it('should create complete user with transaction', async () => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed_password');
      mockRequest.query.mockResolvedValue({
        recordset: [{ UserID: 'new-user-123' }],
      });

      const response = await request(app)
        .post('/new')
        .send({
          user: {
            Email: 'newuser@example.com',
            PhoneNumber: '+1234567890',
            IsActive: true,
            password: 'password123',
          },
          userProfile: {
            FirstName: 'John',
            LastName: 'Doe',
            DateOfBirth: '1990-01-01',
            KYCStatus: 'Pending',
          },
          address: {
            AddressLine1: '123 Main St',
            AddresssType: 'Home',
            City: 'New York',
            State: 'NY',
            PostalCode: '10001',
            Country: 'USA',
            IsPrimary: true,
          },
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('value');
      expect(mockTransaction.commit).toHaveBeenCalled();
    });
  });

  describe('POST /new - Negative Tests', () => {
    it('should return 500 if UserID already exists', async () => {
      const response = await request(app)
        .post('/new')
        .send({
          user: {
            UserID: '123', // Already exists
            Email: 'test@example.com',
            password: 'password123',
          },
        });

      expect(response.status).toBe(500);
    });

    it('should rollback transaction on error', async () => {
      (argon2.hash as jest.Mock).mockResolvedValue('hashed_password');
      mockRequest.query.mockRejectedValue(new Error('Insert failed'));

      const response = await request(app)
        .post('/new')
        .send({
          user: {
            Email: 'test@example.com',
            PhoneNumber: '+1234567890',
            IsActive: true,
            password: 'password123',
          },
          userProfile: {
            FirstName: 'John',
            LastName: 'Doe',
          },
          address: {
            AddressLine1: '123 Main St',
            City: 'New York',
          },
        });

      expect(response.status).toBe(500);
      expect(mockTransaction.rollback).toHaveBeenCalled();
    });

    it('should handle database connection errors', async () => {
      (globals.dbconnect as jest.Mock).mockRejectedValue(new Error('Connection failed'));

      const response = await request(app)
        .post('/new')
        .send({
          user: {
            Email: 'test@example.com',
            password: 'password123',
          },
        });

      expect(response.status).toBe(500);
    });
  });
});
