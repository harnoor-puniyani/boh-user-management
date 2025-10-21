import express, { Request, Response } from "express";
import sql from "mssql";
import dotenv, { config } from "dotenv";
import { add } from "three/tsl";
import { log } from "console";
import argon2 from "argon2";

dotenv.config({
  debug: true,
});

const app = express();
app.use(express.json());

type userTable = {
  UserID: string;
  Email: string;
  PhoneNumber: string;
  IsActive: boolean;
  CreatedAt: string;
  UpdatedAt: string;
};

enum KYCStatus {
  Pending = "Pending",
  Approved = "Approved",
  Rejected = "Rejected",
}

type userProfileTable = {
  UserProfileID: string;
  UserID: string;
  FirstName: string;
  LastName: string;
  DateOfBirth: Date;
  KYCStatus: KYCStatus;
};

type AddressTable = {
  AddressID: string;
  UserID: string;
  AddressLine1: string;
  City: string;
  State: string;
  PostalCode: string;
  Country: string;
  AddresssType: string;
  IsPrimary: true;
};

type LoginHistoryTable = {
  LogID: string;
  UserID: string;
  AttemptTome: string;
  WasSccessful: boolean;
  IPAddress: string;
  UserAgenet: string;
};

const schema = process.env.DB_USER_SCHEMA;
// const userSchema = "[user]";
const dbConfig: sql.config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER as string,
  port: parseInt(process.env.DB_PORT as any, 10),
  database: process.env.DB_DATABASE,
  options: {
    abortTransactionOnError: true,
    trustServerCertificate: true,
    encrypt: false,
  },
};

let connected = false;

async function dbconnect(config: sql.config): Promise<sql.ConnectionPool> {
  connected = true;
  return await sql.connect(config);
}

async function dbdisconnect(sqlconnect: sql.ConnectionPool) {
  sqlconnect.close();
  connected = false;
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
    let sqlconnection: sql.ConnectionPool = await dbconnect(dbConfig);
    try {
      switch (true) {
        case req.path.startsWith("/users/"):
          if (connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select UserID,Email,PhoneNumber,IsActive from [${schema}].Users where UserID='${req.params.id}'`
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
          if (connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select * from [${schema}].UserProfiles where UserID = '${req.params.id}'`
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
          if (connected && req.params.id != null) {
            await new sql.Request(sqlconnection)
              .query(
                `Select * from [${schema}].Addresses where UserID = '${req.params.id}'`
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
      await dbdisconnect(sqlconnection);
    }
  }
);

app.post(
  ["/users", "/userProfile", "/address"],
  async (req: Request, res: Response) => {
    let sqlconnection: sql.ConnectionPool = await dbconnect(dbConfig);
    try {
      switch (true) {
        case req.path.startsWith("/users"):
          if (connected && req.body.UserID == null) {
            let userData: userTable = req.body as userTable;
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
                `INSERT INTO [${schema}].[Users] 
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
          if (connected && req.body.UserID != null) {
            let userProfileData: userProfileTable =
              req.body as userProfileTable;
            await new sql.Request(sqlconnection)
              .input("DateOfBirth", userProfileData.DateOfBirth)
              .input("FirstName", userProfileData.FirstName)
              .input("LastName", userProfileData.LastName)
              .input("UserID", userProfileData.UserID)
              .input("UserProfileID", userProfileData.UserProfileID)
              .input("KYCStatus", userProfileData.KYCStatus)
              .query(
                `INSERT INTO [${schema}].[UserProfiles] 
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
          if (connected && req.body.UserID != null) {
            let address: AddressTable = req.body as AddressTable;

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
                    INSERT INTO [${schema}].[address] 
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
  let sqlconnection: sql.ConnectionPool = await dbconnect(dbConfig);
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
    await dbdisconnect(sqlconnection);
  }
});

app.post("/new", async (req: Request, res: Response) => {
  let sqlconnection: sql.ConnectionPool = await dbconnect(dbConfig);
  let transaction = await new sql.Transaction(sqlconnection).begin();
  try {
    if (connected && req.body.user.UserID != null) {
      let userData: userTable = req.body.user as userTable;
      const password = req.body.password;

      const hashedPassword = await argon2.hash(password, {
        type: argon2.argon2id,
      });

      let userProfileData: userProfileTable = req.body
        .userProfile as userProfileTable;

      let address: AddressTable = req.body.address as AddressTable;

      let userRequest = await new sql.Request(transaction)
        .input("Email", sql.NVarChar, userData.Email)
        .input("PhoneNumber", sql.NVarChar, userData.PhoneNumber)
        .input("IsActive", sql.Bit, userData.IsActive)
        .input("PasswordHash", hashedPassword)
        .query(
          `INSERT INTO [${schema}].[Users] 
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
          `INSERT INTO [${schema}].[UserProfiles] 
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
                    INSERT INTO [${schema}].[address] 
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
