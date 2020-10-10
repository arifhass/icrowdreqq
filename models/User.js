const mongoose = require('mongoose');
var passportLocalMongoose=require("passport-local-mongoose");

const UserSchema = new mongoose.Schema({
  fname: { type: String, required: [true, "can't be blank"]},
  lname: { type: String, required: [true, "can't be blank"]},
  mnum: { type: String, default: ""},
  address: { type: String, required: [true, "can't be blank"]},
  email: { type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true },
  city: { type: String, required: [true, "can't be blank"]},
  password: { type: String, required: [true, "can't be blank"]},
  country: { type: String, required: [true, "can't be blank"]},
  pcode: { type: String, required: [true, "can't be blank"]},
  region: { type: String, default: ""},
  reset: {data: String, default: ''},
  resetPasswordToken: String,
  resetPasswordExpires: Date

}, { timestamps: true });

UserSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", UserSchema);

module.exports = User; 