import mongoose, { Schema } from "mongoose";
import { comparePassword, hashPassword } from "../utils/bcrypt";

export interface UserDocument extends mongoose.Document {
  email: string;
  username: string;
  password: string;
  verified: boolean;
  userAgent: string;
  createdAt: Date;
  updatedAt: Date;
  comparedPassword(value: string): Promise<boolean>;
}

const userSchema = new Schema<UserDocument>(
  {
    email: {
      type: String,
      unique: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    userAgent: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      unique: true,
      required: true,
    },
    verified: {
      type: Boolean,
      default: false,
      required: true,
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await hashPassword(this.password);
  } else {
    next();
  }
});

userSchema.methods.comparedPassword = async function (pass: string) {
  return await comparePassword(pass, this.password);
};

export const User = mongoose.model<UserDocument>("User", userSchema);
