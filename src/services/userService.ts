import { User } from "@prisma/client";
import userRepository from "../repositories/userRepository.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

export type CreateUserData = Omit<User, "id">;
async function insert(createUserData: CreateUserData) {
  const existingUser = await userRepository.findByEmail(createUserData.email);
  if (existingUser)
    throw { type: "conflict", message: "Users must have unique emails" };

  const hashedPassword = bcrypt.hashSync(createUserData.password, 12);

  await userRepository.insert({ ...createUserData, password: hashedPassword });
}

async function signIn({ email, password }: CreateUserData) {
  const user = await userRepository.findByEmail(email);
  if (!user) throw { type: "unauthorized", message: "Invalid credentials" };

  const validatePassword = bcrypt.compareSync(password, user.password);
  if (!validatePassword)
    throw { type: "unauthorized", message: "Invalid credentials" };

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  return token;
}

async function findById(id: number) {
  const user = await userRepository.findById(id);
  if (!user) throw { type: "not_found" };

  delete user.password;
  return user;
}

export default {
  insert,
  signIn,
  findById,
};
