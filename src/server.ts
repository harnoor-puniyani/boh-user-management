import express, { Request, Response } from "express";
import sql from "mssql";
import dotenv from "dotenv";
import { error, log } from "console";

dotenv.config({
  debug: true,
});


const app = express();
app.use(express.json());

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



const PORT = process.env.PORT || 3001;
let sqlconnection: any;
app.listen(PORT, () => {
  console.log(`${<string>process.env.DB_PORT}`);

  console.log(`User management service runing on Port ${PORT}`);
});

// server.close((error)=>{
//     console.log(`closing connections`);
//     sqlconnection.close();
//     console.log(`closed the connections`);
//     console.log(`error : ${error}`);
// });

app.get("/users/:id", async (req: Request, res: Response) => {
  try {
    var userid: string = req.params.id;
    sqlconnection = await sql.connect(<sql.config>dbConfig);
    await new sql.Request(sqlconnection)
      .query(
        `Select UserID,Email,PhoneNumber,IsActive from [${schema}].Users` +
          userid
          ? ` where UserID = '${userid}'`
          : ""
      )
      .then((result) => {
        res.status(200).json({ value: result.recordset });
      })
      .catch((err) => {
        res.status(500).json(err);
      })
      .finally(() => {
        sqlconnection.close();
      });
  } catch (error) {
    res.status(500).json(error);
  }
});

app.post("/users/:id(\\d+)",async (req:Request,res:Response)=>{
  try {
    var userid:string = req.params.id;
    sqlconnection = await sql.connect(<sql.config>dbConfig);

    await new sql.Request(sqlconnection)
    .input("UserID",sql.NVarChar,req.body.id)
    .in
  } catch (error) {
    
  }
});

app.get("/users", async (req: Request, res: Response) => {
  try {
    sqlconnection = await sql.connect(<sql.config>dbConfig);
    await new sql.Request(sqlconnection)
      .query(`Select * from [user].Users`)
      .then((result) => {
        console.log(result);
        res.status(200).json({
          body: result.recordset,
        });
      })
      .catch((err) => {
        res.status(500).json(err);
      })
      .finally(() => {
        console.log("closing connections");
        sqlconnection.close();
        console.log("connections closed");
      });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      error: err,
    });
  }
});

app.get("/signup", async (req: Request, res: Response) => {
  try {
    console.log(
      `Select * from ${userSchema}.[Users] ${
        req.query.user != "" ? "where USERID=" + req.query.user : ""
      }`
    );
    sqlconnection = await sql.connect(dbConfig);
    await new sql.Request(sqlconnection)
      .query(
        `Select * from ${userSchema}.[Users] ${
          req.query.user != "" ? "where USERID='" + req.query.user + "'" : ""
        }`
      )
      .then((result) => {
        console.log(result.recordset);
        res.status(200).json(result.recordset);
      });
  } catch (error) {}
});
