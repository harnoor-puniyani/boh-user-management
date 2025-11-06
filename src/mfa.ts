import { Router, Response, NextFunction } from "express";
import { authenticator } from "otplib";
import sql from "mssql";
import qrcode from "qrcode";
import { AuthenticatedRequest, verifyJWT } from "./authentication"; // Your auth middleware
import * as globals from "./globals";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { ServiceBusClient } from "@azure/service-bus";

const mfaRouter = Router();
dotenv.config({
  debug: true,
});

export function verifyMfaToken(
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
    const decoded = jwt.verify(token, jwtSecret) as jwt.JwtPayload;

    // Check if the token has the correct scope
    if (decoded.scope === "mfa-verify" || decoded.scope === "mfa-register") {
      req.body.user = decoded; // Add user info to the request
      next(); // Token is valid and has the right scope
    } else {
      return res
        .status(403)
        .json({ message: "Forbidden: Invalid token scope." });
    }
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
}

mfaRouter.post(
  "/verify",
  verifyMfaToken,
  async (req: AuthenticatedRequest, res: Response) => {
    const { otpCode } = req.body;

    // 1. Get UserID from the temporary token (added by verifyMfaToken middleware)
    const userId = req.body.user.userId;

    if (!otpCode) {
      return res.status(400).json({ message: "OTP code is required." });
    }

    let sqlconnection: sql.ConnectionPool;

    try {
      sqlconnection = await globals.dbconnect(globals.dbConfig);
      const request = await new sql.Request(sqlconnection);
      let isValid = false;

      // 2. Fetch the user's MFA info
      const userResult = await request
        .input("UserID", userId)
        .query(
          "SELECT Role, MFAMethod, MFASecret FROM [user].[Users] WHERE UserID = @UserID"
        );

      if (!userResult.recordset.length) {
        return res.status(404).json({ message: "User not found." });
      }

      const user = userResult.recordset[0];

      // 3. Handle the verification based on the user's chosen method
      switch (user.MFAMethod) {
        case "TOTP":
          if (!user.MFASecret) {
            return res
              .status(400)
              .json({ message: "TOTP is not configured correctly." });
          }
          isValid = authenticator.check(otpCode, user.MFASecret);
          break;

        case "SMS":
        case "EMAIL":
          const otpResult = await request.input("UserID", userId).query(`
            SELECT TOP 1 OTPHash, ExpiresAt 
            FROM [user].[OneTimePasscodes] 
            WHERE UserID = @UserID ORDER BY CreatedAt DESC
          `);

          if (!otpResult.recordset.length) {
            return res
              .status(400)
              .json({ message: "No OTP found. Please try again." });
          }

          const otpRecord = otpResult.recordset[0];
          if (new Date() > new Date(otpRecord.ExpiresAt)) {
            return res.status(400).json({ message: "Your OTP has expired." });
          }

          // Check if the hashed code matches
          isValid = await bcrypt.compare(otpCode, otpRecord.OTPHash);

          if (isValid) {
            // IMPORTANT: Delete the OTP so it cannot be re-used
            await request
              .input("OTPHash", otpRecord.OTPHash)
              .query(
                "DELETE FROM [user].[OneTimePasscodes] WHERE OTPHash = @OTPHash"
              );
          }
          break;

        default:
          return res
            .status(400)
            .json({ message: "No MFA method is enabled for this user." });
      }

      // 4. Final step: Check if validation was successful
      if (isValid) {
        // SUCCESS! Promote the token.

        // 5. Create the FINAL JWT (the real one)
        const payload = {
          UserID: userId,
          Role: user.Role,
          // Add any other user info you need
        };

        const jwtSecret = process.env.JWT_SECRET;
        const finalToken = jwt.sign(payload, <jwt.Secret>jwtSecret, {
          expiresIn: "1h",
        });
        // jwt.sign(payload, jwtSecret, { expiresIn: "1h" }); // Or your session duration

        // 6. Set the FINAL, GLOBAL cookie
        res.cookie("token", finalToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          path: "/", // The global path
          sameSite: "strict",
        });

        return res.json({ message: "Login successful." });
      } else {
        // FAILURE
        return res.status(401).json({ message: "Invalid OTP code." });
      }
    } catch (error) {
      console.error("Error during MFA verification:", error);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

/**
 * [POST] /api/mfa/setup
 * -----------------
 * Initiates the MFA setup process for a logged-in user.
 * The user must specify their chosen method in the body.
 *
 * BODY: { "mfaMethod": "TOTP" | "SMS" | "EMAIL" }
 */
mfaRouter.post(
  "/setup",
  verifyMfaToken,
  async (req: AuthenticatedRequest, res: Response) => {
    const { mfaMethod } = req.body;

    // 1. Get UserID from the verified JWT
    if (
      !req.body.user ||
      typeof req.body.user === "string" ||
      !req.body.user.userId
    ) {
      return res.status(401).json({ message: "Invalid user token." });
    }
    const userId = req.body.user.userId;
    let sqlconnection = await globals.dbconnect(globals.dbConfig);
    try {
      const request = await new sql.Request(sqlconnection); // Get a request object

      switch (mfaMethod) {
        // -----------------------------------------------------------------
        // Case 1 & 2: User chose SMS or EMAIL
        // -----------------------------------------------------------------
        case "Mobile":
        case "Email":
          // This is simple. We just set their preference.
          // We'll also clear any old TOTP secret, just in case.
          await request.input("UserID", userId).input("MFAMethod", mfaMethod)
            .query(`
            UPDATE [user].[Users] 
            SET MFAMethod = @MFAMethod, MFASecret = NULL 
            WHERE UserID = @UserID
          `);

          return res.json({
            message: `MFA method successfully set to ${mfaMethod}.`,
          });

        // -----------------------------------------------------------------
        // Case 3: User chose TOTP (Authenticator App)
        // -----------------------------------------------------------------
        case "TOTP":
          // This is a 2-step setup. We first generate a secret and a QR code.

          // 1. Generate a new secret
          const secret = authenticator.generateSecret();

          // 2. Create the 'otpauth://' URL
          const userEmail = req.body.user.email; // Assuming Email is in your JWT
          const serviceName = "Bank of Harnoor";
          const otpAuthUrl = authenticator.keyuri(
            userEmail,
            serviceName,
            secret
          );

          // 3. Save the *temporary* secret to the user's record.
          //    NOTE: We do NOT set MFAMethod to 'TOTP' yet!
          //    The user must first prove they scanned it.
          await request.input("UserID", userId).input("MFASecret", secret)
            .query(`
            UPDATE [user].[Users] 
            SET MFASecret = @MFASecret, MFAMethod = NULL 
            WHERE UserID = @UserID
          `);

          // 4. Generate the QR code as a data URI
          const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);
          const jwtSecret = process.env.JWT_SECRET;
          const token = jwt.sign(
            {
              userId: userId,
              email: req.body.user.email,
              Role: req.body.user.Role,
              scope: "mfa-register",
            },
            <jwt.Secret>jwtSecret,
            {
              expiresIn: "1h",
            }
          );
          res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: true,
            path: "/mfa/setup-verify",
            maxAge: 60 * 60 * 1000,
          });
          // 5. Send the QR code to the frontend
          return res.json({
            mfaMethod: "TOTP",
            message:
              "Please scan the QR code with your authenticator app, then verify the code.",
            qrCode: qrCodeDataUrl,
          });

        // -----------------------------------------------------------------
        // Default: Invalid choice
        // -----------------------------------------------------------------
        default:
          return res.status(400).json({
            message: "Invalid mfaMethod. Must be TOTP, SMS, or EMAIL.",
          });
      }
    } catch (error) {
      console.error("Error during MFA setup:", error);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

mfaRouter.post(
  "/setup-verify",
  verifyMfaToken,
  async (req: AuthenticatedRequest, res: Response) => {
    if (
      !req.body.user ||
      typeof req.body.user === "string" ||
      !req.body.user.userId
    ) {
      return res.status(401).json({ message: "Invalid user token." });
    }
    const { otpCode } = req.body;
    const userId = req.body.user.userId;
    let sqlconnection: sql.ConnectionPool | undefined;
    try {
      sqlconnection = await globals.dbconnect(globals.dbConfig);
      const request = await new sql.Request(sqlconnection);
      const userResult = await request
        .input("UserID", userId)
        .query(
          "SELECT Role, MFAMethod, MFASecret FROM [user].[Users] WHERE UserID = @UserID"
        );

      if (!userResult.recordset.length) {
        return res.status(404).json({ message: "User not found." });
      }

      const user = userResult.recordset[0];
      console.log(authenticator.check(otpCode, user.MFASecret));

      if (authenticator.check(otpCode, user.MFASecret)) {
        console.log("code entered");

        const updatereq = await request.query(`
        Update [user].[Users]
          set Users.MFAMethod = 'TOTP'
          where UserID = @UserID
        `);

        res.status(200).json({
          message: "successfully registered",
        });
      } else {
        res.status(400).json({
          message: "registration verification failed pls try again",
        });
      }
    } catch (error) {
      res.status(400).json({
        message: "exception occured",
        error: error,
      });
    } finally {
      if (sqlconnection) {
        await globals.dbdisconnect(sqlconnection);
      }
    }
  }
);

mfaRouter.post(
  "generate-otp",
  async (req: AuthenticatedRequest, res: Response) => {
    let sqlconnection: sql.ConnectionPool | undefined;
    try {
      const { email, userId } = req.body.user;

      if (!email) {
        return res.status(400).json({ message: "Email is required." });
      }

      sqlconnection = await globals.dbconnect(globals.dbConfig);
      const request = new sql.Request(sqlconnection);

      const userResult = await request
        .input("Email", email)
        .query(
          "SELECT UserID, Email, PhoneNumber, Role, MFAMethod FROM [user].[Users] WHERE Email = @Email"
        );

      if (!userResult.recordset[0]) {
        // Don't reveal if user exists.
        return res.json({
          message: "If your account exists, an OTP has been sent.",
        });
      }
      const user = userResult.recordset[0];

      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

      const otpHash = await bcrypt.hash(otpCode, 10);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5-minute expiry

      await request
        .input("UserID", userId)
        .input("OTPHash", otpHash)
        .input("ExpiresAt", expiresAt)
        .query(
          "INSERT INTO [user].[OneTimePasscodes] (UserID, OTPHash, ExpiresAt) VALUES (@UserID, @OTPHash, @ExpiresAt)"
        );

      //notification
      const connectionString = process.env.SERVICEBUS_CONNECTION_STRING;
      const queueName = process.env.SERVICEBUS_QUEUE_NAME;

      if (!connectionString || !queueName) {
        console.error("Service Bus is not configured. Cannot send OTP.");
        // We still return 200 so the user isn't blocked, but log the error
        return res.json({
          message: "If your account exists, an OTP has been sent.",
        });
      }

      const otpEvent = {
        messageType: "OTP_REQUEST",
        channels: [
          {
            type: user.MFAMethod,
            contact: user.MFAMethod == "email" ? email : user.PhoneNumber,
          },
        ],
        otpCode: otpCode, // Send plain text code to the queue
      };

      const sbClient = new ServiceBusClient(connectionString);
      const sender = sbClient.createSender(queueName);
      await sender.sendMessages({
        body: otpEvent,
        contentType: "application/json",
      });
      await sender.close();
      await sbClient.close();
    } catch (error) {
      console.error("Generate OTP failed:", error);
      return res.status(500).json({ message: "Server error." });
    } finally {
      if (sqlconnection) {
        await globals.dbdisconnect(sqlconnection);
      }
    }
  }
);

export default mfaRouter;
