import mongoose, { Schema } from "mongoose";
import { daysFromNow } from "../utils/date";

export interface SessionDocument extends mongoose.Document {
  userID: mongoose.Types.ObjectId;
  userAgent?: string;
  createdAt: Date;
  expiresAt: Date;
}

const sessionSchema = new Schema<SessionDocument>({
  userID: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  userAgent: {
    type: String,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    requireed: true,
    default: daysFromNow(1),
  },
});

export const Session = mongoose.model<SessionDocument>("Session", sessionSchema);
