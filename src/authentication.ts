import express, { Request, Response, NextFunction } from "express";
import sql from "mssql";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import * as globals from "./globals";
import argon2 from "argon2";

const router = express.Router();
dotenv.config({
  debug: true,
});

export interface AuthenticatedRequest extends Request {
  user?: string  | jwt.JwtPayload ;
}

export function verifyJWT(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const token = req.cookies.token;
  const jwtSecret = process.env.JWT_SECRET;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  if (!jwtSecret) {
    return res.status(500).json({ message: "Server configuration error." });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded; // Add user info to the request object
    next(); // Token is valid, proceed
  } catch (error) {
    return res.status(401).json({ message: "Invalid token." });
  }
}

// POST /login - accepts Email or PhoneNumber and password, verifies and returns JWT
router.post("/login", async (req: Request, res: Response) => {
  const { Email, PhoneNumber, password } = req.body;
  if ((!Email && !PhoneNumber) || !password) {
    return res
      .status(400)
      .json({ error: "Email or PhoneNumber and password required" });
  }

  let sqlconnection: sql.ConnectionPool | undefined;
  try {
    sqlconnection = await globals.dbconnect(globals.dbConfig);

    const request = new sql.Request(sqlconnection)
      .input("Email", sql.NVarChar, Email || "")
      .input("PhoneNumber", sql.NVarChar, PhoneNumber || "");

    const query = `SELECT UserID, Email, PhoneNumber, PasswordHash, IsActive,Role,MFAMethod FROM [${globals.schema}].Users WHERE Email = @Email OR PhoneNumber = @PhoneNumber `;

    const result = await request.query(query);
    if (!result.recordset || result.recordset.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.recordset[0];
    if (user.IsActive === false || user.IsActive === 0) {
      return res.status(403).json({ error: "User not active" });
    }

    const verified = await argon2.verify(user.PasswordHash, password);
    if (!verified) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const secret = process.env.JWT_SECRET || "change_this_secret";

    const csrfToken = crypto.randomBytes(32).toString("hex");
    let token = "";
    res.cookie("csrf-token", csrfToken, {
      secure: process.env.NODE_ENV === "production",
      sameSite: true,
      path: "/",
      maxAge: 60 * 60 * 1000,
    });

    if (user.MFAMethod != null) {
      token = jwt.sign(
        {
          userId: user.UserID,
          email: user.Email,
          Role: user.Role,
          scope: "mfa-verify",
        },
        secret,
        {
          expiresIn: "1h",
        }
      );
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: true,
        path: "/mfa/verify",
        maxAge: 60 * 60 * 1000,
      });
    } else {
      token = jwt.sign(
        {
          userId: user.UserID,
          email: user.Email,
          Role: user.Role,
          scope: "mfa-register",
        },
        secret,
        {
          expiresIn: "1h",
        }
      );
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: true,
        path: "/mfa/setup",
        maxAge: 60 * 60 * 1000,
      });
    }

    return res.status(200).json({
      token,
      user: {
        UserID: user.UserID,
        Email: user.Email,
        PhoneNumber: user.PhoneNumber,
        Role: user.Role,
        MFAMethod: user.MFAMethod,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || err });
  } finally {
    if (sqlconnection) await globals.dbdisconnect(sqlconnection);
  }
});

// In your authentication.ts file, alongside verifyJWT

export function checkAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const user = req.user;

  // Type-safe check for the 'Role' property
  if (user && typeof user !== "string" && user.Role === "admin") {
    // User is an admin, let them proceed
    next();
  } else {
    // Not an admin or user data is missing
    return res
      .status(403)
      .json({ message: "Forbidden: Admin access required." });
  }
}


export default router;
