import dotenv, { config } from "dotenv";
import sql from "mssql";

dotenv.config({
  debug: true,
});

export type userTable = {
  UserID: string;
  Email: string;
  PhoneNumber: string;
  IsActive: boolean;
  CreatedAt: string;
  UpdatedAt: string;
};

export enum KYCStatus {
  Pending = "Pending",
  Approved = "Approved",
  Rejected = "Rejected",
}

export type userProfileTable = {
  UserProfileID: string;
  UserID: string;
  FirstName: string;
  LastName: string;
  DateOfBirth: Date;
  KYCStatus: KYCStatus;
};

export type AddressTable = {
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

export type LoginHistoryTable = {
  LogID: string;
  UserID: string;
  AttemptTome: string;
  WasSccessful: boolean;
  IPAddress: string;
  UserAgenet: string;
};


export const schema = process.env.DB_USER_SCHEMA;
// const userSchema = "[user]";
export const dbConfig: sql.config = {
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

export let connected = false;

export async function dbconnect(config: sql.config): Promise<sql.ConnectionPool> {
  connected = true;
  return await sql.connect(config);
}

export async function dbdisconnect(sqlconnect: sql.ConnectionPool) {
  sqlconnect.close();
  connected = false;
}