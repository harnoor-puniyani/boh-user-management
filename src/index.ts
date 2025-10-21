// src/server.ts
import express, { Request, Response } from "express";
import sql from "mssql";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies

// --- Database Configuration ---
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER!,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: true, // Required for Azure SQL
    trustServerCertificate: true,
  },
};

// --- User Registration Endpoint ---
app.post("/register", async (req: Request, res: Response) => {
  const { email, password, firstName, lastName, dateOfBirth } = req.body;

  if (!email || !password || !firstName || !lastName || !dateOfBirth) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hashedPassword = crypto
    .pbkdf2Sync(password, salt, 1000, 64, `sha512`)
    .toString(`hex`);

  let pool;
  try {
    pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    const userInsertResult = await new sql.Request(transaction)
      .input("email", sql.NVarChar, email)
      .input("passwordHash", sql.NVarChar, hashedPassword)
      .input("passwordSalt", sql.NVarChar, salt)
      .query(
        `INSERT INTO [user].[Users] (Email, PasswordHash, PasswordSalt) OUTPUT INSERTED.UserID VALUES (@email, @passwordHash, @passwordSalt);`
      );

    const newUserId = userInsertResult.recordset[0].UserID;

    await new sql.Request(transaction)
      .input("userId", sql.UniqueIdentifier, newUserId)
      .input("firstName", sql.NVarChar, firstName)
      .input("lastName", sql.NVarChar, lastName)
      .input("dateOfBirth", sql.Date, dateOfBirth)
      .query(
        `INSERT INTO [user].[UserProfiles] (UserID, FirstName, LastName, DateOfBirth) VALUES (@userId, @firstName, @lastName, @dateOfBirth);`
      );
    await transaction.commit();

    res
      .status(201)
      .json({ message: "User registered successfully!", userId: newUserId });
    
  } catch (error:any) {
    console.error("Registration Error:", error);
    if (error.number === 2627) {
    
      return res
        .status(409)
        .json({ message: "An account with this email already exists." });
    }
    res.status(500).json({ message: "Internal server error." });
  }

});

// --- User Login Endpoint ---
app.post("/login", async (req: Request, res: Response) => {
  // ... (Login logic will go here in the next step) ...
  res.status(501).json({ message: "Login endpoint not implemented yet." });
});

// --- Start the Server ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(
    `🚀 User Management Service is running on http://localhost:${PORT}`
  );
});
