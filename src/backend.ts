import express, { Request, Response,NextFunction } from "express";
import sql from "mssql";
import dotenv, { config } from "dotenv";
import { add } from "three/tsl";
import { log } from "console";
import argon2 from "argon2";
import * as globals from "./globals"
import { verifyJWT, AuthenticatedRequest } from "./authentication"
import cookieParser from "cookie-parser";
import * as auth from "./authentication"
dotenv.config({
  debug: true,
});


const app = express();
app.use(express.json()).use(cookieParser());


function protectWithCSRF(req: Request, res: Response, next: NextFunction) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }
  const csrfFromHeader = req.headers["x-csrf-token"];
  const csrfFromCookie = req.cookies["csrf-token"];
  if (!csrfFromHeader || !csrfFromCookie || csrfFromHeader !== csrfFromCookie) {
    return res.status(403).json({ message: "Invalid or missing CSRF token." });
  }
  next();
}

//
// # /users:
// #   - create
// #   - update
// #   - list

// # /password:
// #   - update
// /userProfile/{userid}:
// /Addresses/{userid}:
// /LoginHistory/{userid}:

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`${<string>process.env.DB_PORT}`);

  console.log(`User management service runing on Port ${PORT}`);
});

app.get(
  ["/users/:id", "/userProfile/:id", "/address/:id"],
  async (req: Request, res: Response) => {
    let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
    try {
      switch (true) {
        case req.path.startsWith("/users/"):
          if (globals.connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select UserID,Email,PhoneNumber,IsActive from [${globals.schema}].Users where UserID='${req.params.id}'`
              )
              .then((result) => {
                res.status(200).json({
                  value: result.recordset,
                });
              })
              .catch((err) => {
                res.status(404).json(err);
              });
          }
          break;
        case req.path.startsWith("/userProfile"):
          if (globals.connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select * from [${globals.schema}].UserProfiles where UserID = '${req.params.id}'`
              )
              .then((result) => {
                res.status(200).json({
                  value: result.recordset,
                });
              })
              .catch((err) => {
                res.status(400).json(err);
              });
          }
          break;
        case req.path.startsWith("/address"):
          if (globals.connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select * from [${globals.schema}].Addresses where UserID = '${req.params.id}'`
              )
              .then((result) => {
                res.status(200).json({
                  value: result.recordset,
                });
              })
              .catch((err) => {
                res.status(400).json(err);
              });
          }
          break;
        default:
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
  ["/users", "/userProfile", "/address"],auth.verifyJWT, protectWithCSRF,
  async (req: Request, res: Response) => {
    let sqlconnection: sql.ConnectionPool = await globals.dbconnect(globals.dbConfig);
    try {
      switch (true) {
        case req.path.startsWith("/users"):
          if (globals.connected && req.body.UserID == null) {
            let userData: globals.userTable = req.body as globals.userTable;
            const password = req.body.password;
            const hashedPassword = await argon2.hash(password, {
              type: argon2.argon2id,
            });
            console.log(userData);

            await new sql.Request(sqlconnection)
              .input("Email", sql.NVarChar, userData.Email)
              .input("PhoneNumber", sql.NVarChar, userData.PhoneNumber)
              .input("IsActive", sql.Bit, userData.IsActive)
              .input("PasswordHash", hashedPassword)
              .query(
                `INSERT INTO [${globals.schema}].[Users] 
                        (Email, PhoneNumber, IsActive,PasswordHash)
                        VALUES (@Email, @PhoneNumber, @IsActive,@PasswordHash)`
              )
              .then((result) => {
                res.status(202).json({
                  value: result.recordset,
                });
              })
              .catch((err) => {
                res.status(403).json(err);
              });
          }
          break;
        case req.path.startsWith("/userProfile"):
          if (globals.connected && req.body.UserID != null) {
            let userProfileData: globals.userProfileTable =
              req.body as globals.userProfileTable;
            await new sql.Request(sqlconnection)
              .input("DateOfBirth", userProfileData.DateOfBirth)
              .input("FirstName", userProfileData.FirstName)
              .input("LastName", userProfileData.LastName)
              .input("UserID", userProfileData.UserID)
              .input("UserProfileID", userProfileData.UserProfileID)
              .input("KYCStatus", userProfileData.KYCStatus)
              .query(
                `INSERT INTO [${globals.schema}].[UserProfiles] 
                        (DateOfBirth,FirstName,LastName,UserID,UserProfileID,KYCStatus)
                        VALUES (@DateOfBirth,@FirstName,@LastName,@UserID,@UserProfileID,@KYCStatus)
                    `
              )
              .then((result) => {
                res.status(200).json({
                  value: result.recordset,
                });
              })
              .catch((err) => {
                res.status(404).json(err);
              });
          }
          break;
        case req.path.startsWith("/address"):
          if (globals.connected && req.body.UserID != null) {
            let address: globals.AddressTable =
              req.body as globals.AddressTable;

            await new sql.Request(sqlconnection)
              .input("AddressID", address.AddressID)
              .input("AddressLine1", address.AddressLine1)
              .input("AddresssType", address.AddresssType)
              .input("City", address.City)
              .input("Country", address.Country)
              .input("IsPrimary", address.IsPrimary)
              .input("PostalCode", address.PostalCode)
              .input("State", address.State)
              .input("UserID", address.UserID)
              .query(
                `   
                    INSERT INTO [${globals.schema}].[address] 
                    (AddressID,AddressLine1,AddresssType,City,Country,IsPrimary,PostalCode,State,UserID)
                    VALUES (@AddressID,@AddressLine1,@AddresssType,@City,@Country,@IsPrimary,@PostalCode,@State,@UserID)
                `
              )
              .then((result) => {
                res.status(200).json({
                  value: result.recordset,
                });
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

app.get(["/development/:id"], async (req: Request, res: Response) => {
  let sqlconnection: sql.ConnectionPool = await globals.dbconnect(
    globals.dbConfig
  );
  try {
    const table = req.path.split("/development/");
    console.log(table[1]);

    await new sql.Request(sqlconnection)
      .query(`Select * from [user].${table[1]}`)
      .then((result) => {
        console.log(result);
        res.status(200).json({
          body: result.recordset,
        });
      })
      .catch((err) => {
        res.status(500).json(err);
      });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      error: err,
    });
  } finally {
    await globals.dbdisconnect(sqlconnection);
  }
});

app.post("/new", async (req: Request, res: Response) => {
  let sqlconnection: sql.ConnectionPool = await globals.dbconnect(
    globals.dbConfig
  );
  let transaction = await new sql.Transaction(sqlconnection).begin();
  try {
    if (globals.connected && req.body.user.UserID != null) {
      let userData: globals.userTable = req.body.user as globals.userTable;
      const password = req.body.password;

      const hashedPassword = await argon2.hash(password, {
        type: argon2.argon2id,
      });

      let userProfileData: globals.userProfileTable = req.body
        .userProfile as globals.userProfileTable;

      let address: globals.AddressTable = req.body
        .address as globals.AddressTable;

      let userRequest = await new sql.Request(transaction)
        .input("Email", sql.NVarChar, userData.Email)
        .input("PhoneNumber", sql.NVarChar, userData.PhoneNumber)
        .input("IsActive", sql.Bit, userData.IsActive)
        .input("PasswordHash", hashedPassword)
        .query(
          `INSERT INTO [${globals.schema}].[Users] 
            (Email, PhoneNumber, IsActive,PasswordHash)
            OUTPUT inserted.UserID
            VALUES (@Email, @PhoneNumber, @IsActive,@PasswordHash)`
        );

      const userID = await userRequest.recordset[0].UserID;

      let userProfileRequest = await new sql.Request(transaction)
        .input("DateOfBirth", userProfileData.DateOfBirth)
        .input("FirstName", userProfileData.FirstName)
        .input("LastName", userProfileData.LastName)
        .input("UserID", userID)
        .input("KYCStatus", userProfileData.KYCStatus)
        .query(
          `INSERT INTO [${globals.schema}].[UserProfiles] 
            (DateOfBirth,FirstName,LastName,UserID,UserProfileID,KYCStatus)
            VALUES (@DateOfBirth,@FirstName,@LastName,@UserID,@UserProfileID,@KYCStatus)
        `
        );

      let addressRequest = await new sql.Request(transaction)
        .input("AddressID", address.AddressID)
        .input("AddressLine1", address.AddressLine1)
        .input("AddresssType", address.AddresssType)
        .input("City", address.City)
        .input("Country", address.Country)
        .input("IsPrimary", address.IsPrimary)
        .input("PostalCode", address.PostalCode)
        .input("State", address.State)
        .input("UserID", userID)
        .query(
          `   
                    INSERT INTO [${globals.schema}].[address] 
                    (AddressID,AddressLine1,AddresssType,City,Country,IsPrimary,PostalCode,State,UserID)
                    VALUES (@AddressID,@AddressLine1,@AddresssType,@City,@Country,@IsPrimary,@PostalCode,@State,@UserID)
                `
        );

      await transaction.commit();
      res.status(200).json({
        value: userID,
      });
    }
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({
      error: error,
      message: "transaction rollbacked",
    });
  }
});
