import mongoose from "mongoose";
import { peopleConn } from "../config/db.js";
import { randomUUID } from "crypto";

const staffSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => `uuid_staff_${randomUUID()}`
  },
  societyId: {
    type: String,
    required: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  mobile: {
    type: String,
    required: true,
    trim: true
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    required: true,
    trim: true
  },
  status: {
    type: String,
    enum: ["active", "inactive", "terminated"],
    default: "active"
  },
  otp: {
    type: String
  },
  otpExpiry: {
    type: Date
  },
  preferences: {
    language: { type: String, default: "en" },
    theme: { type: String, enum: ["light", "dark", "system"], default: "system" }
  },
  notificationToken: {
    type: String,
    trim: true
  }
}, { 
  timestamps: true,
  versionKey: false 
});

const Staff = peopleConn.model("Staff", staffSchema, "staff");

export default Staff;
