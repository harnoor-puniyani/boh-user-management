import { Router, Response, NextFunction } from "express";
import { authenticator } from "otplib";
import sql from "mssql"
import qrcode from "qrcode"
import { AuthenticatedRequest, verifyJWT } from "./authentication"; // Your auth middleware
import * as globals from "./globals"
import jwt from "jsonwebtoken";

const mfaRouter = Router();

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
    const userId = req.body.user.userID;

    if (!otpCode) {
      return res.status(400).json({ message: "OTP code is required." });
    }

    try {
      const request = pool.request();
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
            await request.query(
              "DELETE FROM [user].[OneTimePasscodes] WHERE OTPHash = @OTPHash",
              { OTPHash: otpRecord.OTPHash }
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
        const finalToken = jwt.sign(payload, jwtSecret, { expiresIn: "1h" }); // Or your session duration

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
  verifyJWT,
  async (req: AuthenticatedRequest, res: Response) => {
    const { mfaMethod } = req.body;

    // 1. Get UserID from the verified JWT
    if (!req.user || typeof req.user === "string" || !req.user.UserID) {
      return res.status(401).json({ message: "Invalid user token." });
    }
    const userId = req.user.UserID;
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
          const userEmail = req.user.Email; // Assuming Email is in your JWT
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
          return res
            .status(400)
            .json({
              message: "Invalid mfaMethod. Must be TOTP, SMS, or EMAIL.",
            });
      }
    } catch (error) {
      console.error("Error during MFA setup:", error);
      res.status(500).json({ message: "Internal server error." });
    }
  }
);

export default mfaRouter;
