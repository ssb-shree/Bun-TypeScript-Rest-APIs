import mongoose, { Schema } from "mongoose";
import type { VerificationCodeType } from "../utils/verificationCode";

export interface VerificationCodeDocument extends mongoose.Document {
  userID: mongoose.Types.ObjectId;
  type: VerificationCodeType;
  expiresAt: Date;
  createdAt: Date;
}

const verificationCodeSchema = new Schema<VerificationCodeDocument>({
  userID: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  type: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

export const VerificationCode = mongoose.model<VerificationCodeDocument>("VerificationCode", verificationCodeSchema);
