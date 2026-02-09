import mongoose from "mongoose";
import { peopleConn } from "../config/db.js";
import { randomUUID } from "crypto";

const adminSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => `uuid_admin_${randomUUID()}`
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
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
  password: {
    type: String,
    required: true
  },
  roleId: {
    type: String,
    required: true
  },
  isSuperadmin: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ["active", "disabled", "suspended"],
    default: "active"
  },
  lastLoginAt: {
    type: Date
  },
  refreshToken: {
    type: String
  },
  notificationToken: {
    type: String,
    trim: true
  }
}, {
  timestamps: true,
  versionKey: false
});

const Admin = peopleConn.model("Admin", adminSchema, "admins");

export default Admin;
