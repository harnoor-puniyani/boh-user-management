# Testing Guide for BOH User Management Service

## Overview
This guide explains how the unit tests work and how to validate authentication and MFA functionality in the BOH User Management Service.

## Understanding Test Credentials

### Login Test Parameters

The tests use **mocked data** - they don't require real credentials because all database and authentication services are mocked. Here's how it works:

#### Example 1: Email Login
```typescript
// Test sends this data:
{
  Email: 'test@example.com',
  password: 'password123'
}

// Mock returns this user:
{
  UserID: '123',
  Email: 'test@example.com',
  PasswordHash: 'hashed_password',
  IsActive: true,
  Role: 'user'
}

// Mock password verification (argon2.verify) returns: true
```

**Key Point**: The actual password value (`'password123'`) doesn't matter in tests because `argon2.verify` is mocked to return `true` or `false` based on what the test needs to verify.

#### Example 2: Phone Number Login
```typescript
// Test sends this data:
{
  PhoneNumber: '+9876543210',
  password: 'password123'
}

// Mock returns this user:
{
  UserID: '456',
  Email: 'user@example.com',
  PhoneNumber: '+9876543210',
  PasswordHash: 'hashed_password',
  IsActive: true
}
```

### Real-World Usage (Not in Tests)

For actual API usage (not unit tests):

1. **User Registration**: Use `POST /new` to create a user with a password
   - Password will be hashed using argon2
   - Stored securely in the database

2. **Login**: Use `POST /auth/login` with actual credentials
   - Email or PhoneNumber
   - Plain text password (hashed on the server)
   - Returns JWT token on success

## TOTP Validation Explained

### How TOTP Works in Tests

TOTP (Time-based One-Time Password) is used with authenticator apps like Google Authenticator. Here's how tests validate it:

#### TOTP Setup Flow (Tests)
```typescript
// 1. User requests TOTP setup
POST /mfa/setup
Body: { mfaMethod: 'TOTP' }

// 2. Mock generates a secret
authenticator.generateSecret() → 'TESTSECRET123'

// 3. Mock creates QR code URL
authenticator.keyuri(email, 'Bank of Harnoor', secret)
→ 'otpauth://totp/Bank%20of%20Harnoor:test@example.com?secret=TESTSECRET123'

// 4. QR code is returned to user
qrcode.toDataURL() → 'data:image/png;base64,TEST'
```

#### TOTP Verification Flow (Tests)
```typescript
// User submits TOTP code
POST /mfa/verify
Body: { otpCode: '123456' }

// Mock validates the code against the secret
authenticator.check('123456', 'test-secret') → true/false

// Returns success or error based on validation
```

### Test Examples

#### Positive Test - Valid TOTP
```typescript
it('should successfully verify TOTP code', async () => {
  // 1. Setup: Mock user with TOTP enabled
  const mockUser = {
    Role: 'user',
    MFAMethod: 'TOTP',
    MFASecret: 'test-secret',
  };
  
  mockRequest.query.mockResolvedValueOnce({
    recordset: [mockUser],
  });
  
  // 2. Mock: TOTP verification returns true
  (authenticator.check as jest.Mock).mockReturnValue(true);
  
  // 3. Create valid MFA token
  const token = createMfaToken('mfa-verify');
  
  // 4. Send request with TOTP code
  const response = await request(app)
    .post('/mfa/verify')
    .set('Cookie', [`token=${token}`])
    .send({ otpCode: '123456' });
  
  // 5. Verify success
  expect(response.status).toBe(200);
  expect(response.body.message).toBe('Login successful.');
});
```

#### Negative Test - Invalid TOTP
```typescript
it('should return 401 for invalid TOTP code', async () => {
  // Setup same as above
  
  // Mock: TOTP verification returns false (invalid code)
  (authenticator.check as jest.Mock).mockReturnValue(false);
  
  // Send request with wrong code
  const response = await request(app)
    .post('/mfa/verify')
    .set('Cookie', [`token=${token}`])
    .send({ otpCode: '999999' });
  
  // Verify error response
  expect(response.status).toBe(401);
  expect(response.body.message).toBe('Invalid OTP code.');
});
```

## Real-World TOTP Validation (Not in Tests)

For actual implementation:

### Setup Phase
1. User enables TOTP via `POST /mfa/setup`
2. Server generates a secret using `authenticator.generateSecret()`
3. Server creates QR code with `qrcode.toDataURL(otpAuthUrl)`
4. User scans QR code with Google Authenticator/Authy
5. Secret is stored in database (MFASecret column)

### Verification Phase
1. User enters 6-digit code from authenticator app
2. Server retrieves user's MFASecret from database
3. Server validates: `authenticator.check(userCode, storedSecret)`
4. Returns success/failure based on validation

### TOTP Code Generation
- **Time-based**: Changes every 30 seconds
- **Secret-based**: Each user has unique secret
- **Standard**: RFC 6238 compliant
- **Format**: 6 digits (usually)

## Other MFA Methods

### SMS OTP
```typescript
// Setup
POST /mfa/setup
Body: { mfaMethod: 'Mobile' }

// Generate OTP (6 digits)
const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

// Hash and store
const otpHash = await bcrypt.hash(otpCode, 10);
// Store in OneTimePasscodes table with expiration

// Verify
const isValid = await bcrypt.compare(userInputCode, storedHash);
```

### Email OTP
Same as SMS, but:
- Method: `'Email'`
- Sent to user's email instead of phone
- Same hashing and validation process

## Mock vs Real Data

| Aspect | Unit Tests (Mocked) | Real Implementation |
|--------|---------------------|---------------------|
| Database | Mocked with jest.mock() | Real MSSQL database |
| Passwords | argon2.verify mocked | Real argon2 hashing |
| TOTP | authenticator.check mocked | Real otplib validation |
| JWT | Real jwt.sign/verify | Real jwt.sign/verify |
| Credentials | Any values work | Must match database |

## Key Testing Concepts

### 1. Mocking
Tests don't hit real services. All external dependencies are mocked:
```typescript
jest.mock('mssql');           // Database
jest.mock('argon2');          // Password hashing
jest.mock('otplib');          // TOTP generation/verification
jest.mock('bcryptjs');        // OTP hashing
```

### 2. Test Isolation
Each test is independent:
- `beforeEach()`: Sets up fresh mocks
- `afterEach()`: Clears all mocks
- No shared state between tests

### 3. Supertest
Makes HTTP requests to the Express app:
```typescript
const response = await request(app)
  .post('/auth/login')
  .send({ Email: 'test@example.com', password: 'test' });
```

## Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test authentication.test.ts

# Run with coverage
npm run test:coverage

# Run in watch mode
npm run test:watch
```

## Common Test Patterns

### Pattern 1: Positive Test
1. Mock successful database response
2. Mock successful validation (argon2.verify = true)
3. Send valid request
4. Expect 200 status and valid response

### Pattern 2: Negative Test
1. Mock failure condition (no user, wrong password, etc.)
2. Send request
3. Expect error status (400, 401, 403, 500) and error message

### Pattern 3: Security Test
1. Send request without required token/CSRF
2. Expect 401/403 rejection
3. Verify security middleware works

## Summary

- **Login tests**: Use any email/phone + password (mocked validation)
- **TOTP validation**: Mocked `authenticator.check()` returns true/false
- **Real usage**: Requires actual database and generated secrets
- **Test purpose**: Verify application logic, not external services
- **Mocking**: Ensures fast, reliable, isolated tests

For real API usage, you'll need:
1. A running database with actual users
2. Properly hashed passwords in the database
3. Generated TOTP secrets for users with MFA
4. A working authenticator app (for TOTP)
5. Email/SMS service (for Email/SMS OTP)
